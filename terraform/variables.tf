variable "project_id" {
  type        = string
  description = "GCP project ID."
}

variable "environment" {
  type        = string
  description = "Deployment environment name used for labels and state separation."
  default     = "production"
}

variable "region" {
  type        = string
  description = "Cloud Run region."
  default     = "us-central1"
}

variable "service_name" {
  type    = string
  default = "security-scan-service"
}

variable "image" {
  type        = string
  description = "Fully-qualified container image (Artifact Registry) to deploy."
}

variable "artifact_repository" {
  type        = string
  description = "Artifact Registry repository that stores scanner images."
  default     = "multiforum-services"
}

variable "allow_unauthenticated" {
  type        = bool
  description = "Allow requests to reach FastAPI. The /scan route still requires X-API-Key."
  default     = true
}

variable "min_instance_count" {
  type        = number
  description = "Minimum number of warm Cloud Run instances."
  default     = 0
}

variable "max_instance_count" {
  type        = number
  description = "Maximum number of Cloud Run instances."
  default     = 5

  validation {
    condition     = var.max_instance_count >= 1
    error_message = "max_instance_count must be at least 1."
  }
}

variable "scan_api_key_secret_id" {
  type        = string
  description = "Secret Manager ID containing the shared scanner API key."
  default     = "scan-api-key"
}

variable "virustotal_api_key_secret_id" {
  type        = string
  description = "Secret Manager ID containing the VirusTotal API key."
  default     = "virustotal-api-key"
}
