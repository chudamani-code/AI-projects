# sample_terraform/good/main.tf
# ✅  Correct patterns — the AI should find nothing to flag here.

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "my-gcp-project"
  region  = "us-central1"
}

# ✅ Resource-scoped role instead of roles/owner
resource "google_storage_bucket_iam_member" "deploy_sa_bucket_access" {
  bucket = google_storage_bucket.app_data.name
  role   = "roles/storage.objectAdmin"   # scoped to this specific bucket only
  member = "serviceAccount:deploy-sa@my-gcp-project.iam.gserviceaccount.com"
}

# ✅ Private bucket with uniform access
resource "google_storage_bucket" "app_data" {
  name                        = "my-company-app-data"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_key.id
  }
}

# ✅ Cloud SQL with restricted network access
resource "google_sql_database_instance" "main" {
  name             = "prod-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled    = false   # private IP only
      private_network = google_compute_network.vpc.id
    }
  }
}

# ✅ KMS key for encryption
resource "google_kms_crypto_key" "bucket_key" {
  name     = "bucket-encryption-key"
  key_ring = google_kms_key_ring.main.id
  purpose  = "ENCRYPT_DECRYPT"
}

resource "google_kms_key_ring" "main" {
  name     = "main-key-ring"
  location = "us-central1"
}

resource "google_compute_network" "vpc" {
  name                    = "prod-vpc"
  auto_create_subnetworks = false
}
