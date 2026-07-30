provider "aws" {
  region = var.aws_region

  # These avoid credential and account API calls while the default-disabled
  # reference configuration is being validated locally.
  skip_credentials_validation = !var.deployment_enabled
  skip_metadata_api_check     = true
  skip_requesting_account_id  = !var.deployment_enabled

  default_tags {
    tags = {
      ManagedBy = "OpenTofu"
      Project   = var.name_prefix
      Purpose   = "synthetic-reference"
    }
  }
}

provider "awscc" {
  region = var.aws_region
}
