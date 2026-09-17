terraform {
  # The deployment workflow supplies bucket and prefix with -backend-config.
  # Keeping state in GCS makes plans repeatable across GitHub Actions runs.
  backend "gcs" {}
}
