# AI-projects: Cloud & AI Security Portfolio

A portfolio of security-engineering projects spanning AI/LLM threat modeling, cloud IAM governance, infrastructure-as-code security automation, and DevSecOps pipeline design. Every root-level claim below is backed by artifacts in this repo: a live GitHub Actions security gate, real Terraform, and real OPA/Sentinel/Checkov policy files.

## Sub-projects

| Project | What it demonstrates |
|---|---|
| [AI/ai-threat-model](./AI/ai-threat-model) | Threat modeling methodology applied to an AI/LLM system, mapping attack surfaces to mitigations. |
| [security/audit-pipeline](./security/audit-pipeline) | An automated audit/logging pipeline pattern for continuous compliance evidence collection. |
| [AI/blast-radius-mapper](./AI/blast-radius-mapper) | A Neo4j-backed graph tool that maps AI agent attack-surface and blast radius across permissions and resources. |
| [security/iam-role-vending](./security/iam-role-vending) | A least-privilege IAM role vending pattern for automated, auditable cloud access provisioning. |
| [AI/kill-switch-project/agent-kill-switch-lab](./AI/kill-switch-project/agent-kill-switch-lab) | A kill-switch lab for safely halting misbehaving AI agents in a controlled environment. |
| [AI/tf-ai-reviewer](./AI/tf-ai-reviewer) | A standalone Terraform AI-reviewer tool with its own GitHub Actions workflow for automated IaC review. |

## Root-level security architecture

- **Automated guardrails**: [.github/workflows/devsecops-pipeline.yml](./.github/workflows/devsecops-pipeline.yml) runs Terraform fmt/validate, Checkov, OPA policy evaluation, and a Trivy IaC scan on every push and pull request against `main`.
- **Hardened reference infrastructure**: [security/terraform-infra/](./security/terraform-infra) contains a small secure-landing-zone example (encrypted S3, blocked public access, multi-region CloudTrail) that the pipeline lints, validates, and scans.
- **Policy-as-code, engine-agnostic**: [security/security-policies/opa](./security/security-policies/opa) holds OPA/Rego rules enforced in CI; [security/security-policies/sentinel](./security/security-policies/sentinel) holds an equivalent HashiCorp Sentinel policy (Sentinel only runs in Terraform Cloud/Enterprise, so it is included for reference rather than executed here); [security/security-policies/checkov.yaml](./security/security-policies/checkov.yaml) configures the Checkov SAST scan.

## CI/CD security pipeline

Every commit and pull request against `main` triggers:

1. **Lint & validate** — `terraform fmt -check` and `terraform validate` against `security/terraform-infra/`.
2. **SAST** — Checkov scans `security/terraform-infra/` using the shared `security/security-policies/checkov.yaml` config.
3. **Policy enforcement** — a Terraform plan is generated and evaluated against the OPA/Rego rules in `security/security-policies/opa`.
4. **IaC vulnerability scan** — Trivy scans `security/terraform-infra/` for critical/high severity misconfigurations.

`tf-ai-reviewer` runs its own separate workflow and is documented in its own subfolder.

## Tech stack

Cloud & IaC: AWS, Terraform. Policy-as-code: OPA/Rego, HashiCorp Sentinel, Checkov, Trivy. Automation: GitHub Actions. Graph analysis: Neo4j (blast-radius-mapper).

## Why this repo

This portfolio is built around the controls cloud security roles commonly evaluate for: least-privilege IAM design, encryption at rest and in transit, detective controls (audit logging, CloudTrail), and policy-as-code enforcement that maps to common compliance frameworks such as CIS, NIST, and SOC 2. Each sub-project targets one of these areas in depth, and the root-level pipeline ties them together into a working, verifiable example rather than a description of one.
