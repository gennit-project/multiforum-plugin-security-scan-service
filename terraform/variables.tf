variable "project_id" {
  type        = string
  description = "GCP project ID."
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

variable "invoker_service_account" {
  type        = string
  description = "Service account of the Multiforum backend, granted run.invoker."
}
