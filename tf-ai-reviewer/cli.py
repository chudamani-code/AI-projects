#!/usr/bin/env python3
"""
cli.py — local testing CLI and GitHub Actions entry point.

Local usage (no GitHub, no API call — just print rendered comment from a canned response):
  python cli.py --diff sample_diffs/high_severity.diff --dry-run

Local usage (real API call, print to terminal):
  export ANTHROPIC_API_KEY=sk-ant-...
  python cli.py --diff sample_diffs/high_severity.diff

GitHub Actions usage (real API + post comment):
  python cli.py \\
    --diff terraform.diff \\
    --plan terraform_plan.txt \\
    --post-comment \\
    --pr-number 42 \\
    --repo org/repo

Exit codes:
  0 — APPROVED or ADVISORY (PR can proceed)
  1 — NEEDS_REVIEW (PR should be blocked until findings addressed)
  2 — Analyzer error
"""
import argparse
import json
import os
import sys

# Allow running as a top-level script or as a module
sys.path.insert(0, os.path.dirname(__file__))

from reviewer.analyzer import analyze
from reviewer.github_client import post_pr_comment
from reviewer.models import ReviewRequest, ReviewResult
from reviewer.prompt import render_github_comment


def load_file(path: str, label: str) -> str:
    if not path:
        return ""
    try:
        return open(path).read()
    except FileNotFoundError:
        print(f"[ERROR] {label} file not found: {path}", file=sys.stderr)
        sys.exit(2)


def canned_demo_result() -> ReviewResult:
    """Return a pre-built ReviewResult for --dry-run mode (no API key needed)."""
    from reviewer.models import Finding, ReviewSummary
    return ReviewResult(
        findings=[
            Finding(
                id="F001",
                severity="HIGH",
                category="IAM Misconfiguration",
                resource_type="google_project_iam_binding",
                resource_name="developer_sa_binding",
                title="Primitive owner role granted at project level",
                issue="roles/owner grants full control of all project resources including IAM policy modification. Any principal with this role can delete resources, exfiltrate data, and lock out legitimate owners.",
                blast_radius="Complete project compromise. An attacker gaining access to any bound service account can delete all GCP resources, read all secrets, and modify IAM to create persistent backdoor access.",
                recommendation='Replace with a resource-scoped role:\n\n# Instead of:\nrole = "roles/owner"\n\n# Use:\nrole = "roles/storage.objectAdmin"  # for GCS only\n# or\nrole = "roles/cloudsql.client"      # for Cloud SQL only',
                diff_context='+ role = "roles/owner"\n+ member = "serviceAccount:deploy-sa@project.iam.gserviceaccount.com"',
            ),
            Finding(
                id="F002",
                severity="MEDIUM",
                category="Data Exposure",
                resource_type="google_storage_bucket",
                resource_name="data_lake_bucket",
                title="Bucket-level access control disabled",
                issue="uniform_bucket_level_access = false allows object-level ACLs. Object ACLs can override bucket-level IAM, creating hard-to-audit access paths.",
                blast_radius="Individual objects can be made public or shared with arbitrary principals outside the bucket's IAM policy, bypassing centralized access control.",
                recommendation='Enable uniform access:\n\nresource "google_storage_bucket" "data_lake_bucket" {\n  uniform_bucket_level_access = true  # enforces IAM-only access\n}',
                diff_context="+ uniform_bucket_level_access = false",
            ),
        ],
        summary=__import__("reviewer.models", fromlist=["ReviewSummary"]).ReviewSummary(
            total_findings=2,
            high=1,
            medium=1,
            verdict="NEEDS_REVIEW",
            verdict_reason="One HIGH finding: primitive owner role grants project-wide blast radius.",
        ),
        model="claude-sonnet-4-20250514 (dry-run)",
        input_tokens=0,
        output_tokens=0,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Terraform Security Reviewer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--diff",         required=True,  help="Path to git diff file (.diff)")
    parser.add_argument("--plan",         default="",     help="Path to terraform plan output file")
    parser.add_argument("--post-comment", action="store_true", help="Post result as a GitHub PR comment")
    parser.add_argument("--pr-number",    type=int,       help="PR number (required for --post-comment)")
    parser.add_argument("--repo",         default="",     help="GitHub repo 'org/repo' (required for --post-comment)")
    parser.add_argument("--dry-run",      action="store_true", help="Use canned result, no API call")
    parser.add_argument("--json-output",  action="store_true", help="Print raw JSON instead of rendered comment")
    parser.add_argument("--fail-on-review", action="store_true",
                        help="Exit code 1 if verdict is NEEDS_REVIEW (for CI blocking)")
    args = parser.parse_args()

    git_diff = load_file(args.diff, "git diff")
    plan     = load_file(args.plan, "terraform plan") if args.plan else ""

    # ── Run analysis ──────────────────────────────────────────────────────────
    if args.dry_run:
        print("[DRY RUN] Using canned demo result — no API call made.\n")
        result = canned_demo_result()
    else:
        req    = ReviewRequest(git_diff=git_diff, terraform_plan=plan)
        result = analyze(req)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json_output:
        print(result.model_dump_json(indent=2))
    else:
        print(render_github_comment(result))

    # ── Post to GitHub ────────────────────────────────────────────────────────
    if args.post_comment:
        if not args.pr_number or not args.repo:
            print("[ERROR] --pr-number and --repo are required for --post-comment", file=sys.stderr)
            sys.exit(2)
        token = os.getenv("GITHUB_TOKEN", "")
        if not token:
            print("[ERROR] GITHUB_TOKEN environment variable is not set", file=sys.stderr)
            sys.exit(2)
        comment_body = render_github_comment(result)
        info = post_pr_comment(args.repo, args.pr_number, comment_body, token)
        print(f"\n[GitHub] Comment {info['action']}: {info['comment_url']}")

    # ── Exit code ─────────────────────────────────────────────────────────────
    print(f"\nVerdict: {result.summary.verdict}", file=sys.stderr)
    if args.fail_on_review and result.summary.verdict == "NEEDS_REVIEW":
        sys.exit(1)
    if result.summary.verdict == "APPROVED":
        sys.exit(0)
    sys.exit(0)   # ADVISORY is also exit 0 — human reviewer decides


if __name__ == "__main__":
    main()
