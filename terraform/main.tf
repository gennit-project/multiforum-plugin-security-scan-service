terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Secrets are created out-of-band (or here) and referenced by the service.
resource "google_secret_manager_secret" "api_key" {
  secret_id = "scan-api-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "virustotal_api_key" {
  secret_id = "virustotal-api-key"
  replication {
    auto {}
  }
}

# Dedicated runtime identity for the service (least privilege).
resource "google_service_account" "runtime" {
  account_id   = "${var.service_name}-sa"
  display_name = "Security scan service runtime"
}

resource "google_cloud_run_v2_service" "service" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.runtime.email

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      env {
        name = "SCAN_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.api_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SCAN_VIRUSTOTAL_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.virustotal_api_key.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }
}

# Let the runtime SA read the secrets.
resource "google_secret_manager_secret_iam_member" "api_key_access" {
  secret_id = google_secret_manager_secret.api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "vt_key_access" {
  secret_id = google_secret_manager_secret.virustotal_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

# Only the Multiforum backend SA may invoke the service (no public access).
resource "google_cloud_run_v2_service_iam_member" "backend_invoker" {
  name     = google_cloud_run_v2_service.service.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.invoker_service_account}"
}
