terraform {
  required_version = ">= 1.10.0"
  required_providers {
    awssigv4 = {
      source = "asana/awssigv4"
    }
  }
}

# Minimal — uses the AWS SDK default credential chain (env vars, ~/.aws/config
# and ~/.aws/credentials including `credential_process`, SSO, IMDS, etc.).
# Signing region is resolved per ephemeral resource: the resource's `region`
# argument wins, otherwise the SDK falls back to AWS_REGION/AWS_DEFAULT_REGION
# and then the active profile's `region` setting.
provider "awssigv4" {}

# Or with explicit profile + assume_role:
#
# provider "awssigv4" {
#   profile                  = "engineering"
#   shared_config_files      = ["~/.aws/config"]
#   shared_credentials_files = ["~/.aws/credentials"]
#
#   assume_role {
#     role_arn         = "arn:aws:iam::123456789012:role/terraform"
#     session_name     = "terraform-awssigv4"
#     duration_seconds = 3600
#   }
# }
