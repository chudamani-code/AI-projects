# Enterprise Cloud Security & DevSecOps Portfolio

This repository demonstrates production-grade DevSecOps pipelines, Policy-as-Code (PaC) enforcement, and secure cloud architecture patterns designed to meet SOC 2 Type II and NIST CSF 2.0 compliance frameworks.

## 🛡️ Core Security Architecture Features
* **Automated Guardrails:** Integrated Open Policy Agent (OPA/Rego) and Checkov scanning within GitHub Actions to enforce static analysis and fail non-compliant infrastructure builds.
* **Hardened Cloud Infrastructure:** Declarative Terraform configurations built against CIS Foundations Benchmarks (Enforced TLS 1.2+, AES-256 at-rest encryption, zero-trust network boundaries).
* **Secure AI Integration:** Architecture patterns demonstrating how to securely deploy and isolate Retrieval-Augmented Generation (RAG) pipelines and LLM workloads without data leakage (PII protection).

## 🚀 The CI/CD Security Pipeline
Every commit triggers a multi-stage security validation pipeline:
1. **Lint & Format:** `terraform fmt` and `validate`.
2. **Static Application Security Testing (SAST):** Checkov scans for misconfigurations.
3. **Policy Enforcement:** OPA evaluates the deployment plan against custom organizational compliance rules.

## 🛠️ Tech Stack
* **Cloud & IaC:** AWS/Azure, Terraform, OpenTofu
* **Security & Compliance:** OPA (Rego), Checkov, Trivy, GitOps
* **Automation:** GitHub Actions CI/CD
