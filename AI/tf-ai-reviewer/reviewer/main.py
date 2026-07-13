"""
main.py — FastAPI service for the AI Terraform reviewer.

Endpoints:
  POST /review          Run a security review (returns JSON findings)
  GET  /health          Health check
  GET  /sample          Return a sample review (for testing without an API key)

Run locally:
  uvicorn reviewer.main:app --reload --port 8200
"""
import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from reviewer.analyzer import analyze
from reviewer.github_client import post_pr_comment
from reviewer.models import ReviewRequest, ReviewResult
from reviewer.prompt import render_github_comment

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="Terraform AI Security Reviewer",
    description="GCP Security Architect AI that reviews Terraform PRs for IAM misconfigurations and blast-radius expansion",
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.post("/review", response_model=ReviewResult)
async def review(req: ReviewRequest) -> ReviewResult:
    """
    Analyze a Terraform diff and optional plan output.
    Optionally post the result as a GitHub PR comment.
    """
    result = analyze(req)

    if req.post_comment and req.pr_number and req.repo:
        token = req.github_token or os.getenv("GITHUB_TOKEN", "")
        if not token:
            raise HTTPException(status_code=400, detail="GitHub token required to post comment")
        comment_body = render_github_comment(result)
        try:
            post_pr_comment(req.repo, req.pr_number, comment_body, token)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Could not post GitHub comment: {e}")

    return result


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
        "api_key_set": bool(os.getenv("ANTHROPIC_API_KEY")),
    }
