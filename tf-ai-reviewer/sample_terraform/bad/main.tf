# sample_terraform/bad/main.tf
# ⚠️  INTENTIONALLY MISCONFIGURED — for AI reviewer demo only
# This file contains the exact misconfigs the AI should catch.

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "my-gcp-project"
  region  = "us-central1"
}

# ── ISSUE 1: roles/owner at project level ─────────────────────────────────────
# A junior developer needed the deploy SA to access a GCS bucket.
# They used roles/owner "to make sure it has enough permissions."
resource "google_project_iam_binding" "developer_sa_binding" {
  project = "my-gcp-project"
  role    = "roles/owner"    # ← THIS IS WHAT THE AI SHOULD CATCH

  members = [
    "serviceAccount:deploy-sa@my-gcp-project.iam.gserviceaccount.com",
  ]
}

# ── ISSUE 2: public GCS bucket ────────────────────────────────────────────────
resource "google_storage_bucket" "data_lake" {
  name          = "my-company-data-lake"
  location      = "US"
  force_destroy = true

  uniform_bucket_level_access = false  # ← allows object ACLs to override bucket IAM
}

resource "google_storage_bucket_iam_binding" "public_read" {
  bucket = google_storage_bucket.data_lake.name
  role   = "roles/storage.objectViewer"

  members = [
    "allUsers",  # ← CRITICAL: makes bucket publicly readable on the internet
  ]
}

# ── ISSUE 3: Cloud SQL open to internet ──────────────────────────────────────
resource "google_sql_database_instance" "main" {
  name             = "prod-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      authorized_networks {
        value = "0.0.0.0/0"  # ← allows any internet IP to connect to the database
        name  = "open-to-world"
      }
    }
  }
}

# ── Clean resource (should NOT be flagged) ────────────────────────────────────
resource "google_storage_bucket" "build_artifacts" {
  name                        = "my-company-build-artifacts"
  location                    = "US"
  uniform_bucket_level_access = true
}
