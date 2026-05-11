"""
analyzer.py — sends the diff + plan to Claude and parses the JSON response.

Fail-safe design: if the LLM returns malformed JSON or the API fails,
we return a clearly-labelled error finding rather than silently passing the PR.
Never fail open on a security review.
"""
from __future__ import annotations

import json
import logging
import os
import re

import anthropic

from reviewer.models import Finding, ReviewRequest, ReviewResult, ReviewSummary
from reviewer.prompt import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger("analyzer")

MODEL   = os.getenv("ANTHROPIC_MODEL",       "claude-sonnet-4-20250514")
MAX_TOK = int(os.getenv("MAX_OUTPUT_TOKENS", "4096"))


def _extract_json(text: str) -> str:
    """
    Extract JSON from the model response.
    Handles cases where the model wraps output in markdown fences despite instructions.
    """
    # Try raw first
    text = text.strip()
    if text.startswith("{"):
        return text

    # Strip ```json ... ``` fences
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)

    # Last resort: find the outermost { }
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        return text[start:end]

    raise ValueError("No JSON object found in model response")


def _error_result(reason: str) -> ReviewResult:
    """Return a NEEDS_REVIEW result when the analyzer itself fails."""
    return ReviewResult(
        findings=[Finding(
            id="ERR001",
            severity="HIGH",
            category="Analyzer Error",
            resource_type="(system)",
            resource_name="(system)",
            title="AI review could not complete",
            issue=f"The automated review encountered an error: {reason}",
            blast_radius="Unknown — manual review of this PR is required.",
            recommendation="Address the underlying error and re-run the review.",
            diff_context="",
        )],
        summary=ReviewSummary(
            total_findings=1,
            high=1,
            verdict="NEEDS_REVIEW",
            verdict_reason=f"Analyzer error: {reason}",
        ),
    )


def analyze(req: ReviewRequest, api_key: str | None = None) -> ReviewResult:
    """
    Send the diff and plan to Claude, parse the structured JSON response.

    Parameters
    ----------
    req      : ReviewRequest
    api_key  : override ANTHROPIC_API_KEY env var (useful for tests)

    Returns
    -------
    ReviewResult  — never raises, returns error finding on failure
    """
    key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        return _error_result("ANTHROPIC_API_KEY is not set")

    if not req.git_diff.strip():
        return ReviewResult(
            findings=[],
            summary=ReviewSummary(
                total_findings=0,
                verdict="APPROVED",
                verdict_reason="No Terraform changes in this diff.",
            ),
        )

    client = anthropic.Anthropic(api_key=key)
    user_prompt = build_user_prompt(req.git_diff, req.terraform_plan)

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOK,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except anthropic.APIError as e:
        logger.error(f"Anthropic API error: {e}")
        return _error_result(f"API error: {e}")

    raw_text = "".join(
        b.text for b in response.content if hasattr(b, "text")
    )

    # ── Parse JSON ────────────────────────────────────────────────────────────
    try:
        json_str  = _extract_json(raw_text)
        data      = json.loads(json_str)
        findings  = [Finding(**f) for f in data.get("findings", [])]
        summary   = ReviewSummary(**data["summary"])
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logger.error(f"JSON parse error: {e}\nRaw response: {raw_text[:500]}")
        return _error_result(f"Could not parse model response: {e}")

    # ── Sanity-check severity counts ──────────────────────────────────────────
    # Recompute from findings in case the model miscounted
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1

    summary.critical      = counts["critical"]
    summary.high          = counts["high"]
    summary.medium        = counts["medium"]
    summary.low           = counts["low"]
    summary.info          = counts["info"]
    summary.total_findings = len(findings)

    # Re-derive verdict from actual findings (don't trust model's verdict)
    if counts["critical"] > 0 or counts["high"] > 0:
        summary.verdict = "NEEDS_REVIEW"
    elif counts["medium"] > 0:
        summary.verdict = "NEEDS_REVIEW"
    elif counts["low"] > 0 or counts["info"] > 0:
        summary.verdict = "ADVISORY"
    else:
        summary.verdict = "APPROVED"

    return ReviewResult(
        findings=findings,
        summary=summary,
        model=response.model,
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
    )
