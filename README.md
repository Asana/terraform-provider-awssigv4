# terraform-provider-awssigv4

A Terraform provider that exposes a single [ephemeral resource](https://developer.hashicorp.com/terraform/language/block/ephemeral) — `awssigv4_request` — for sending [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html)-signed HTTP requests to any endpoint.

It sits at the intersection of the [`http` data source](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http) and the [`aws_lambda_invocation` ephemeral resource](https://registry.terraform.io/providers/-/aws/latest/docs/ephemeral-resources/lambda_invocation): a flexible HTTP client, plus the full AWS SDK default credential provider chain.

## Why ephemeral?

Responses from SigV4-signed endpoints often contain credentials or secrets that should not be written to Terraform state. Ephemeral resources are re-evaluated on every plan/apply and their results never persist.

## Provider configuration

All fields are optional. When omitted, the standard AWS SDK default credential provider chain applies — environment variables, the shared config/credentials files (including `credential_process` and SSO profiles), container/IMDS, assume-role and assume-role-with-web-identity.

There is no provider-level `region` attribute. The SigV4 signing region is resolved in this order: the ephemeral resource's `region` argument, then `AWS_REGION` / `AWS_DEFAULT_REGION`, then the active profile's `region` setting.

```hcl
terraform {
  required_providers {
    awssigv4 = {
      source = "asana/awssigv4"
    }
  }
}

provider "awssigv4" {
  profile                  = "engineering"     # named profile (region comes from the profile)
  shared_config_files      = ["~/.aws/config"]
  shared_credentials_files = ["~/.aws/credentials"]

  # Static credentials (rarely needed, strongly discouraged)
  # access_key = "..."
  # secret_key = "..."
  # token      = "..."

  assume_role {
    role_arn         = "arn:aws:iam::123456789012:role/terraform"
    session_name     = "terraform-awssigv4"
    duration_seconds = 3600
  }

  # assume_role_with_web_identity { role_arn = "...", web_identity_token_file = "..." }

  # max_retries                 = 3
  # retry_mode                  = "adaptive"
  # skip_credentials_validation = true
  # skip_metadata_api_check     = true
  # use_fips_endpoint           = false
  # use_dualstack_endpoint      = false
  # custom_ca_bundle            = "/etc/ssl/certs/ca-bundle.crt"
  # http_proxy / https_proxy / no_proxy
  # sts_endpoint / sts_region
  # ec2_metadata_service_endpoint / ec2_metadata_service_endpoint_mode
}
```

## Ephemeral resource: `awssigv4_request`

```hcl
ephemeral "awssigv4_request" "invoke" {
  url     = "https://abcdef1234.execute-api.us-east-1.amazonaws.com/prod/items"
  service = "execute-api"
  region  = "us-east-1"   # optional; falls back to configured region
  method  = "POST"

  request_headers = {
    "Content-Type" = "application/json"
  }
  request_body = jsonencode({ id = "42" })

  request_timeout_ms = 10000
}

output "status" {
  ephemeral = true
  value     = ephemeral.awssigv4_request.invoke.status_code
}
```

### Arguments

| Argument | Type | Required | Description |
| --- | --- | --- | --- |
| `url` | string | yes | Full URL to request. |
| `service` | string | yes | SigV4 service name (e.g. `execute-api`, `lambda`, `s3`, `appsync`, `bedrock`). |
| `method` | string | no | HTTP method. Defaults to `GET`, or `POST` when `request_body` is set. |
| `region` | string | no | SigV4 signing region. Falls back to the AWS SDK's resolution (env vars, active profile). |
| `request_headers` | map(string) | no | Headers attached before signing. |
| `request_body` | string | no | Request body. Hashed for SigV4 unless `sign_body = false`. |
| `request_timeout_ms` | number | no | Per-request timeout in milliseconds. |
| `ca_cert_pem` | string | no | Extra PEM-encoded CA bundle for the target endpoint. |
| `insecure` | bool | no | Skip TLS verification of the target endpoint. |
| `sign_body` | bool | no | If `false`, signs with `UNSIGNED-PAYLOAD` instead of hashing the body (useful for S3 streaming). Defaults to `true`. |
| `set_content_sha256_header` | bool | no | If `true`, set the `X-Amz-Content-Sha256` header to the value used when signing. S3 requires this; most other services do not. Defaults to `false`. |

### Computed attributes

| Attribute | Type | Description |
| --- | --- | --- |
| `status_code` | number | HTTP response status code. |
| `ok` | bool | `true` when `status_code` is in the 2xx range. |
| `response_headers` | map(string) | Response headers (first value per header name). |
| `response_body` | string (sensitive) | Response body as a UTF-8 string. Empty if the body is not valid UTF-8 — see `response_body_is_utf8` to disambiguate from an empty body. |
| `response_body_base64` | string (sensitive) | Response body, base64-encoded — always set, including binary responses. |
| `response_body_is_utf8` | bool | `true` when the response body is valid UTF-8 (and thus safely represented in `response_body`). |

## Building locally

```sh
go build ./...
```

To use a local build, follow the [Terraform plugin development overrides](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers) docs.

## Attribution

The project skeleton (`main.go`, the provider package shell) was scaffolded from [hashicorp/terraform-provider-scaffolding-framework](https://github.com/hashicorp/terraform-provider-scaffolding-framework) (MPL-2.0, © HashiCorp, Inc. / IBM Corp.). AWS credential resolution uses [hashicorp/aws-sdk-go-base](https://github.com/hashicorp/aws-sdk-go-base), the same library the official `terraform-provider-aws` provider uses, so the credential provider chain (env vars, profiles, `credential_process`, SSO, IMDS, assume-role, web identity) behaves identically.

## License

MPL-2.0. See [`LICENSE`](LICENSE).
