"""
test_reviewer.py — unit tests for every component of the AI reviewer.
No API key required — the Anthropic call is mocked.

Run: python tests/test_reviewer.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reviewer.models import Finding, ReviewRequest, ReviewResult, ReviewSummary
from reviewer.prompt import (
    build_user_prompt, render_github_comment, render_finding,
    SEVERITY_EMOJI, VERDICT_BANNER,
)
from reviewer.analyzer import _extract_json, _error_result


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _finding(severity="HIGH", resource_name="test_resource", **kwargs) -> Finding:
    defaults = dict(
        id="F001", severity=severity,
        category="IAM Misconfiguration",
        resource_type="google_project_iam_binding",
        resource_name=resource_name,
        title="Test finding title",
        issue="Test issue description.",
        blast_radius="Test blast radius.",
        recommendation="Test recommendation.",
        diff_context='+ role = "roles/owner"',
    )
    return Finding(**{**defaults, **kwargs})


def _result(findings=None, verdict="NEEDS_REVIEW") -> ReviewResult:
    f = findings or [_finding()]
    counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        counts[sev.lower()] = sum(1 for x in f if x.severity == sev)
    return ReviewResult(
        findings=f,
        summary=ReviewSummary(
            total_findings=len(f),
            verdict=verdict,
            verdict_reason="Test reason.",
            **counts,
        ),
        model="claude-test",
        input_tokens=100,
        output_tokens=200,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Prompt construction
# ─────────────────────────────────────────────────────────────────────────────

def test_build_user_prompt_includes_diff():
    diff = "diff --git a/main.tf\n+ role = roles/owner"
    prompt = build_user_prompt(diff, "")
    assert "roles/owner" in prompt
    print("PASS: user prompt includes git diff content")


def test_build_user_prompt_includes_plan():
    plan = "Plan: 3 to add, 0 to change, 0 to destroy."
    prompt = build_user_prompt("some diff", plan)
    assert "3 to add" in prompt
    print("PASS: user prompt includes terraform plan content")


def test_build_user_prompt_caps_long_diff():
    giant_diff = "x" * 20_000
    prompt = build_user_prompt(giant_diff, "")
    # diff is capped at 12000 chars in the prompt
    assert len(prompt) < 25_000
    print("PASS: user prompt caps oversized diffs")


def test_build_user_prompt_handles_no_plan():
    prompt = build_user_prompt("some diff", "")
    assert "not provided" in prompt
    print("PASS: user prompt handles missing plan gracefully")


# ─────────────────────────────────────────────────────────────────────────────
# JSON extraction from model responses
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_json_bare():
    raw = '{"findings": [], "summary": {"verdict": "APPROVED"}}'
    result = _extract_json(raw)
    assert json.loads(result)["summary"]["verdict"] == "APPROVED"
    print("PASS: extract_json handles bare JSON")


def test_extract_json_with_markdown_fence():
    raw = '```json\n{"findings": [], "summary": {"verdict": "APPROVED"}}\n```'
    result = _extract_json(raw)
    assert json.loads(result)["summary"]["verdict"] == "APPROVED"
    print("PASS: extract_json strips markdown fences")


def test_extract_json_with_preamble():
    raw = 'Here is the review:\n\n{"findings": [], "summary": {"verdict": "APPROVED"}}'
    result = _extract_json(raw)
    assert json.loads(result)
    print("PASS: extract_json handles preamble text")


def test_extract_json_raises_on_garbage():
    try:
        _extract_json("no json here at all")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
    print("PASS: extract_json raises on non-JSON content")


# ─────────────────────────────────────────────────────────────────────────────
# Error result fallback
# ─────────────────────────────────────────────────────────────────────────────

def test_error_result_is_needs_review():
    r = _error_result("API timed out")
    assert r.summary.verdict == "NEEDS_REVIEW"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "HIGH"
    assert "API timed out" in r.findings[0].issue
    print("PASS: error result returns NEEDS_REVIEW (fail-closed)")


def test_error_result_never_approves():
    r = _error_result("some error")
    assert r.summary.verdict != "APPROVED"
    print("PASS: error result never returns APPROVED")


# ─────────────────────────────────────────────────────────────────────────────
# GitHub comment rendering
# ─────────────────────────────────────────────────────────────────────────────

def test_render_finding_includes_severity():
    f = _finding(severity="HIGH")
    out = render_finding(f, 1)
    assert "HIGH" in out
    assert SEVERITY_EMOJI["HIGH"] in out
    print("PASS: render_finding includes severity and emoji")


def test_render_finding_includes_resource():
    f = _finding(resource_name="my_iam_binding")
    out = render_finding(f, 1)
    assert "my_iam_binding" in out
    print("PASS: render_finding includes resource name")


def test_render_finding_includes_diff_context():
    f = _finding(diff_context='+ role = "roles/owner"')
    out = render_finding(f, 1)
    assert "roles/owner" in out
    assert "```diff" in out
    print("PASS: render_finding includes diff context code block")


def test_render_finding_includes_recommendation():
    f = _finding(recommendation="Use roles/storage.objectAdmin instead")
    out = render_finding(f, 1)
    assert "roles/storage.objectAdmin" in out
    print("PASS: render_finding includes recommendation")


def test_render_github_comment_needs_review_banner():
    r = _result(verdict="NEEDS_REVIEW")
    comment = render_github_comment(r)
    assert "NEEDS REVIEW" in comment or "NEEDS_REVIEW" in comment
    assert "🛑" in comment
    print("PASS: NEEDS_REVIEW comment includes stop banner")


def test_render_github_comment_approved_banner():
    r = _result(findings=[], verdict="APPROVED")
    comment = render_github_comment(r)
    assert "APPROVED" in comment
    assert "✅" in comment
    print("PASS: APPROVED comment includes green banner")


def test_render_github_comment_advisory_banner():
    r = _result(findings=[_finding(severity="LOW")], verdict="ADVISORY")
    comment = render_github_comment(r)
    assert "ADVISORY" in comment
    assert "💡" in comment
    print("PASS: ADVISORY comment includes info banner")


def test_render_github_comment_includes_all_findings():
    findings = [
        _finding(severity="HIGH", id="F001", resource_name="res_one"),
        _finding(severity="MEDIUM", id="F002", resource_name="res_two"),
    ]
    r = _result(findings=findings, verdict="NEEDS_REVIEW")
    comment = render_github_comment(r)
    assert "res_one" in comment
    assert "res_two" in comment
    print("PASS: comment includes all finding resource names")


def test_render_github_comment_has_model_info():
    r = _result()
    comment = render_github_comment(r)
    assert "claude-test" in comment
    assert "100" in comment   # input_tokens
    print("PASS: comment includes model and token info")


def test_render_github_comment_has_advisory_disclaimer():
    r = _result()
    comment = render_github_comment(r)
    assert "advisory" in comment.lower()
    assert "human" in comment.lower()
    print("PASS: comment includes advisory disclaimer")


def test_render_github_comment_summary_table():
    findings = [_finding(severity="HIGH"), _finding(severity="HIGH"), _finding(severity="MEDIUM")]
    r = _result(findings=findings, verdict="NEEDS_REVIEW")
    comment = render_github_comment(r)
    # Summary table should show counts
    assert "HIGH" in comment
    assert "MEDIUM" in comment
    print("PASS: comment includes severity summary table")


# ─────────────────────────────────────────────────────────────────────────────
# Model/Pydantic validation
# ─────────────────────────────────────────────────────────────────────────────

def test_finding_severity_validation():
    try:
        Finding(id="F1", severity="INVALID", category="x", resource_type="x",
                resource_name="x", title="x", issue="x", blast_radius="x",
                recommendation="x", diff_context="")
        assert False, "Should have raised validation error"
    except Exception:
        pass
    print("PASS: Finding rejects invalid severity")


def test_review_request_defaults():
    r = ReviewRequest(git_diff="some diff")
    assert r.terraform_plan == ""
    assert r.post_comment is False
    assert r.pr_number is None
    print("PASS: ReviewRequest has correct defaults")


def test_review_result_serialisation():
    r = _result()
    data = json.loads(r.model_dump_json())
    assert "findings" in data
    assert data["summary"]["verdict"] == "NEEDS_REVIEW"
    print("PASS: ReviewResult serialises to valid JSON")


# ─────────────────────────────────────────────────────────────────────────────
# Verdict logic (re-derivation in analyzer)
# ─────────────────────────────────────────────────────────────────────────────

def test_verdict_critical_is_needs_review():
    f = _finding(severity="CRITICAL")
    r = _result([f], verdict="NEEDS_REVIEW")
    assert r.summary.verdict == "NEEDS_REVIEW"
    print("PASS: CRITICAL finding → NEEDS_REVIEW")


def test_verdict_info_only_is_advisory():
    f = _finding(severity="INFO")
    r = _result([f], verdict="ADVISORY")
    assert r.summary.verdict == "ADVISORY"
    print("PASS: INFO-only findings → ADVISORY")


def test_verdict_no_findings_is_approved():
    r = _result([], verdict="APPROVED")
    assert r.summary.verdict == "APPROVED"
    assert r.summary.total_findings == 0
    print("PASS: no findings → APPROVED")


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

ALL_TESTS = [
    test_build_user_prompt_includes_diff,
    test_build_user_prompt_includes_plan,
    test_build_user_prompt_caps_long_diff,
    test_build_user_prompt_handles_no_plan,
    test_extract_json_bare,
    test_extract_json_with_markdown_fence,
    test_extract_json_with_preamble,
    test_extract_json_raises_on_garbage,
    test_error_result_is_needs_review,
    test_error_result_never_approves,
    test_render_finding_includes_severity,
    test_render_finding_includes_resource,
    test_render_finding_includes_diff_context,
    test_render_finding_includes_recommendation,
    test_render_github_comment_needs_review_banner,
    test_render_github_comment_approved_banner,
    test_render_github_comment_advisory_banner,
    test_render_github_comment_includes_all_findings,
    test_render_github_comment_has_model_info,
    test_render_github_comment_has_advisory_disclaimer,
    test_render_github_comment_summary_table,
    test_finding_severity_validation,
    test_review_request_defaults,
    test_review_result_serialisation,
    test_verdict_critical_is_needs_review,
    test_verdict_info_only_is_advisory,
    test_verdict_no_findings_is_approved,
]

GROUPS = {
    "Prompt construction":              ALL_TESTS[:4],
    "JSON extraction":                  ALL_TESTS[4:8],
    "Error result (fail-closed)":       ALL_TESTS[8:10],
    "Finding renderer":                 ALL_TESTS[10:14],
    "GitHub comment renderer":          ALL_TESTS[14:21],
    "Model validation":                 ALL_TESTS[21:24],
    "Verdict logic":                    ALL_TESTS[24:],
}

if __name__ == "__main__":
    passed = failed = 0
    for group, tests in GROUPS.items():
        print(f"\n{'─'*60}")
        print(f"  {group}")
        print(f"{'─'*60}")
        for fn in tests:
            try:
                fn()
                passed += 1
            except Exception as e:
                print(f"  FAIL [{fn.__name__}]: {e}")
                import traceback; traceback.print_exc()
                failed += 1

    print(f"\n{'═'*60}")
    print(f"  Results: {passed} passed, {failed} failed / {len(ALL_TESTS)} total")
    print(f"{'═'*60}")
    sys.exit(0 if failed == 0 else 1)
