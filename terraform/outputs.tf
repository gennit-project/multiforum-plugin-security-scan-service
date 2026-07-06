output "service_url" {
  description = "HTTPS URL of the deployed Cloud Run service."
  value       = google_cloud_run_v2_service.service.uri
}

output "runtime_service_account" {
  value = google_service_account.runtime.email
}
