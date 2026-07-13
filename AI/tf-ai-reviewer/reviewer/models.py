"""
models.py — data shapes for the AI reviewer.
"""
from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str                          # F001, F002 …
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: str                    # "IAM Misconfiguration", "Blast Radius Expansion" …
    resource_type: str               # "google_project_iam_binding"
    resource_name: str               # Terraform resource name
    title: str                       # Short headline
    issue: str                       # What is wrong
    blast_radius: str                # What an attacker can do
    recommendation: str              # How to fix it
    diff_context: str                # Relevant diff lines


class ReviewSummary(BaseModel):
    total_findings: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    verdict: Literal["APPROVED", "ADVISORY", "NEEDS_REVIEW"]
    verdict_reason: str


class ReviewResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    summary: ReviewSummary
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class ReviewRequest(BaseModel):
    git_diff: str = Field(..., description="Output of git diff for .tf files")
    terraform_plan: str = Field(default="", description="Output of terraform plan -no-color")
    pr_number: Optional[int] = None
    repo: Optional[str] = None       # "org/repo"
    github_token: Optional[str] = None
    post_comment: bool = False
