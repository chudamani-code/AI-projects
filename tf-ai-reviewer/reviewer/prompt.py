"""
prompt.py — the AI persona, system prompt, and GitHub comment renderer.

The system prompt is the most security-critical piece of this project.
It defines:
  - What the AI focuses on (blast-radius, IAM misconfigs)
  - What it ignores (style, costs, docs)
  - The exact JSON output schema
  - Severity definitions and verdict logic
"""
from __future__ import annotations
from reviewer.models import Finding, ReviewResult


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior GCP Security Architect performing an automated, advisory security review of Terraform infrastructure changes.

You are the FIRST automated check before a human reviewer sees this PR. Your role is to flag contextual security issues that static tools like Checkov cannot catch — issues that require understanding intent, blast radius, and least-privilege in context.

═══════════════════════════════════════════════════════
FOCUS EXCLUSIVELY ON THESE TWO CATEGORIES:
═══════════════════════════════════════════════════════

1. BLAST RADIUS EXPANSION
   Changes that significantly increase the damage potential of any future compromise:
   - New project-level IAM bindings (vs resource-scoped)
   - Removing organization policy constraints or VPC Service Controls
   - Cross-project or cross-organization IAM trust
   - Service account key file creation (prefer Workload Identity Federation)
   - New public internet exposure (firewall allow 0.0.0.0/0, public LBs)
   - Disabling audit logging or Cloud Monitoring sinks

2. IAM MISCONFIGURATIONS
   Permissions that violate least-privilege:
   - Primitive roles: roles/owner, roles/editor (project-level)
   - roles/viewer at project level when resource-scoped is available
   - allUsers or allAuthenticatedUsers as IAM members anywhere
   - roles/iam.serviceAccountTokenCreator or roles/iam.serviceAccountKeyAdmin
   - IAM bindings without conditions on high-privilege roles
   - Service accounts with cross-project roles
   - Missing separation of duties (same SA has both reader and writer roles)

3. DATA EXPOSURE
   - GCS bucket with uniform_bucket_level_access = false
   - Public bucket ACLs (allUsers / allAuthenticatedUsers)
   - Cloud SQL without authorized_networks restriction (or 0.0.0.0/0 allowed)
   - BigQuery datasets without access controls
   - Missing CMEK for sensitive workloads

═══════════════════════════════════════════════════════
DO NOT FLAG ANY OF THESE — THEY WASTE ENGINEER TIME:
═══════════════════════════════════════════════════════
- Variable naming or formatting
- Missing comments or documentation
- Performance or cost concerns
- Resource labels or tags (unless they affect security)
- Terraform style conventions
- Anything in a clearly dev/sandbox environment that is explicitly labelled as such

═══════════════════════════════════════════════════════
SEVERITY DEFINITIONS:
═══════════════════════════════════════════════════════
CRITICAL — Active data breach risk or complete project ownership possible right now
HIGH     — Significant privilege escalation or wide blast radius if compromised
MEDIUM   — Least-privilege violation with limited blast radius
LOW      — Best-practice deviation, negligible risk in context
INFO     — Observation worth noting, zero security impact

═══════════════════════════════════════════════════════
VERDICT LOGIC:
═══════════════════════════════════════════════════════
APPROVED     — Zero findings of MEDIUM severity or higher
ADVISORY     — Findings present, all LOW or INFO
NEEDS_REVIEW — Any CRITICAL or HIGH finding present

═══════════════════════════════════════════════════════
OUTPUT FORMAT — STRICT JSON ONLY:
═══════════════════════════════════════════════════════
Respond ONLY with valid JSON. No preamble. No explanation outside the JSON.
If the diff contains no security issues, return findings: [] and verdict: APPROVED.

{
  "findings": [
    {
      "id": "F001",
      "severity": "HIGH",
      "category": "IAM Misconfiguration",
      "resource_type": "google_project_iam_binding",
      "resource_name": "exact_terraform_resource_name",
      "title": "Primitive owner role granted at project level",
      "issue": "roles/owner grants full control of all project resources including IAM. Any bound principal can create/delete resources, modify IAM policies, and exfiltrate all data.",
      "blast_radius": "Complete project compromise. An attacker gaining access to any bound service account or user can delete all resources, exfiltrate all data, and lock out legitimate owners.",
      "recommendation": "Replace roles/owner with the minimum required role. For GCS access use roles/storage.objectAdmin. For read-only use roles/storage.objectViewer. Never use primitive roles in production.",
      "diff_context": "+ role = \\"roles/owner\\""
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0,
    "verdict": "NEEDS_REVIEW",
    "verdict_reason": "One HIGH finding: primitive owner role grants project-wide blast radius."
  }
}"""


USER_PROMPT_TEMPLATE = """Review the following Terraform changes for security issues.

=== GIT DIFF (Terraform files only) ===
{git_diff}

=== TERRAFORM PLAN OUTPUT ===
{terraform_plan}

Apply the security review criteria from your instructions. Return valid JSON only."""


def build_user_prompt(git_diff: str, terraform_plan: str) -> str:
    plan_section = terraform_plan.strip() if terraform_plan.strip() else "(terraform plan not provided)"
    return USER_PROMPT_TEMPLATE.format(
        git_diff=git_diff[:12_000],       # cap to stay within context budget
        terraform_plan=plan_section[:4_000],
    )


# ── GitHub PR comment renderer ────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "⚠️",
    "LOW":      "🔵",
    "INFO":     "ℹ️",
}

VERDICT_BANNER = {
    "APPROVED":     "✅ **APPROVED** — No significant security findings.",
    "ADVISORY":     "💡 **ADVISORY** — Low-severity findings only. Human reviewer should be aware.",
    "NEEDS_REVIEW": "🛑 **NEEDS REVIEW** — Address findings below before merging.",
}


def render_finding(f: Finding, idx: int) -> str:
    emoji = SEVERITY_EMOJI.get(f.severity, "•")
    lines = [
        f"### {emoji} {f.severity} · `{f.resource_type}.{f.resource_name}`",
        f"**{f.title}**",
        "",
        f"**Issue:** {f.issue}",
        "",
        f"**Blast radius:** {f.blast_radius}",
        "",
        f"**Recommendation:**",
        f"```hcl",
        f"{f.recommendation}",
        f"```",
    ]
    if f.diff_context:
        lines += [
            "",
            "**Triggered by:**",
            "```diff",
            f.diff_context,
            "```",
        ]
    return "\n".join(lines)


def render_github_comment(result: ReviewResult) -> str:
    s = result.summary
    banner = VERDICT_BANNER.get(s.verdict, s.verdict)

    # Header
    count_str = (
        f"{s.total_findings} finding{'s' if s.total_findings != 1 else ''}"
        if s.total_findings > 0 else "no security findings"
    )
    lines = [
        f"## 🔍 AI Terraform Security Review — {count_str}",
        "",
        f"> {banner}",
        f"> {s.verdict_reason}",
        "",
    ]

    if result.findings:
        # Sort by severity
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(result.findings, key=lambda f: order.get(f.severity, 5))

        lines.append("---")
        lines.append("")
        for i, f in enumerate(sorted_findings):
            lines.append(render_finding(f, i + 1))
            lines.append("")
            lines.append("---")
            lines.append("")

        # Summary table
        lines += [
            "#### Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = getattr(s, sev.lower(), 0)
            if count > 0:
                lines.append(f"| {SEVERITY_EMOJI[sev]} {sev} | {count} |")

    lines += [
        "",
        "<details>",
        "<summary>About this review</summary>",
        "",
        "This comment was generated automatically by an AI acting as a GCP Security Architect.",
        "It focuses **exclusively** on blast-radius expansion and IAM misconfigurations.",
        "Static analysis tools (Checkov, tfsec) run separately and cover binary rule violations.",
        "**This review is advisory — it does not replace human code review.**",
        "",
        f"Model: `{result.model or 'claude-sonnet-4-20250514'}`  ",
        f"Tokens: {result.input_tokens} in / {result.output_tokens} out",
        "</details>",
    ]

    return "\n".join(lines)
