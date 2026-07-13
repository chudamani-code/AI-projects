"""
github_client.py — posts the AI review comment to a GitHub pull request.

Uses the GitHub REST API v3 (no SDK dependency).
Requires a token with pull_requests:write permission.

In GitHub Actions this is:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""
from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("github")

GITHUB_API = "https://api.github.com"
HEADER_MARKER = "<!-- tf-ai-reviewer -->"   # used to find and update existing comments


def post_pr_comment(
    repo: str,           # "org/repo"
    pr_number: int,
    body: str,
    token: str | None = None,
) -> dict:
    """
    Post a comment on a PR. If a previous AI review comment exists on this PR,
    update it instead of creating a new one (keeps the PR timeline clean).
    """
    tok = token or os.getenv("GITHUB_TOKEN", "")
    if not tok:
        raise ValueError("GitHub token required (GITHUB_TOKEN env var or token param)")

    headers = {
        "Authorization": f"Bearer {tok}",
        "Accept":        "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    full_body = f"{HEADER_MARKER}\n{body}"

    with httpx.Client(timeout=30) as client:
        # Find existing AI review comment to update
        existing_id = _find_existing_comment(client, headers, repo, pr_number)

        if existing_id:
            url = f"{GITHUB_API}/repos/{repo}/issues/comments/{existing_id}"
            resp = client.patch(url, headers=headers, json={"body": full_body})
            action = "updated"
        else:
            url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
            resp = client.post(url, headers=headers, json={"body": full_body})
            action = "created"

        resp.raise_for_status()
        logger.info(f"PR comment {action}: {resp.json().get('html_url', '')}")
        return {"action": action, "comment_url": resp.json().get("html_url", "")}


def _find_existing_comment(
    client: httpx.Client,
    headers: dict,
    repo: str,
    pr_number: int,
) -> int | None:
    """Return the ID of an existing AI review comment, or None."""
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
    try:
        resp = client.get(url, headers=headers, params={"per_page": 100})
        resp.raise_for_status()
        for comment in resp.json():
            if HEADER_MARKER in comment.get("body", ""):
                return comment["id"]
    except httpx.HTTPError as e:
        logger.warning(f"Could not fetch existing comments: {e}")
    return None
