# terraform-provider-awssigv4

A Terraform provider that exposes a single [ephemeral resource](https://developer.hashicorp.com/terraform/language/block/ephemeral) — `awssigv4_request` — for sending [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html)-signed HTTP requests to any endpoint.

It sits at the intersection of the [`http` data source](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http) and the [`aws_lambda_invocation` ephemeral resource](https://registry.terraform.io/providers/-/aws/latest/docs/ephemeral-resources/lambda_invocation): a flexible HTTP client, plus the full AWS SDK default credential provider chain.

The complete schema reference lives in [`docs/index.md`](docs/index.md) (provider) and [`docs/ephemeral-resources/request.md`](docs/ephemeral-resources/request.md) (resource). Both are generated from the Go schema and verified by CI.

## Why ephemeral?

Responses from SigV4-signed endpoints often contain credentials or other secrets that should not be written to Terraform state. Ephemeral resources are re-evaluated on every plan/apply and their results never persist.

## Quick example

A realistic use case: exchange AWS-IAM-signed identity for a short-lived OIDC token, then hand it to another provider.

```hcl
terraform {
  required_providers {
    awssigv4 = { source = "asana/awssigv4" }
    github   = { source = "integrations/github" }
  }
}

provider "awssigv4" {
  profile = "engineering"
}

ephemeral "awssigv4_request" "github_token" {
  url     = "https://oidc.example.com/exchange"
  service = "execute-api"
  method  = "POST"

  request_headers = { "Content-Type" = "application/json" }
  request_body    = jsonencode({ audience = "github" })

  # Fail the plan if anything other than a 200 comes back. Without this,
  # a 401/500 with an empty body would surface as a confusing
  # `jsondecode(...) failed: EOF` downstream.
  expected_status_codes = [200]

  retry {
    attempts        = 5
    multiplier      = 2.0
    min_delay       = "500ms"
    max_delay       = "10s"
    on_status_codes = [429, 502, 503, 504]
  }

  request_timeout = "5s"   # per-attempt
  timeouts { open = "30s" } # end-to-end (all attempts + backoffs)
}

provider "github" {
  token = jsondecode(ephemeral.awssigv4_request.github_token.response_body).token
}
```

`response_body` is marked sensitive — Terraform won't print it in plan output, and the value propagates as sensitive into the consuming provider.

## Provider configuration

All provider fields are optional. When omitted, the standard AWS SDK default credential provider chain applies: environment variables, the shared config/credentials files (including `credential_process` and SSO profiles), container/IMDS, assume-role, and assume-role-with-web-identity.

There is no provider-level `region` attribute. The SigV4 signing region is resolved in this order: the ephemeral resource's `region` argument, then `AWS_REGION` / `AWS_DEFAULT_REGION`, then the active profile's `region` setting.

A more involved configuration that names a profile and assumes a role:

```hcl
provider "awssigv4" {
  profile = "engineering"

  assume_role {
    role_arn         = "arn:aws:iam::123456789012:role/terraform"
    session_name     = "terraform-awssigv4"
    duration_seconds = 3600
  }
}
```

For the full list of provider attributes (static credentials, custom CA bundles, proxy settings, STS overrides, IMDS controls, FIPS/dual-stack endpoints, web-identity assume-role, etc.), see [`docs/index.md`](docs/index.md).

## Ephemeral resource: `awssigv4_request`

The resource accepts the request inputs you'd expect (`url`, `method`, `service`, `region`, `request_headers`, `request_body`, plus TLS and timeout controls) and exposes the response as a set of computed attributes (`status_code`, `ok`, `response_headers`, `response_body`, `response_body_base64`, `response_body_is_utf8`, `attempts`).

Notable behaviors that aren't obvious from the field names:

- **Status enforcement** via `expected_status_codes = [200]` turns a non-matching status into a plan error. By default, the response body is *not* included in that diagnostic — set `include_response_body_in_errors = true` to include it, but only when you're confident the body cannot contain sensitive material (a misconfigured allowlist would otherwise leak the body into plaintext error output).
- **Retries** via the `retry { ... }` block re-sign every attempt, so SigV4's signature time window doesn't bound your retry budget. Configurable `multiplier`, `min_delay_ms`, `max_delay_ms`, `on_status_codes`, and `on_connection_errors`.
- **Redirects** are off by default (`follow_redirects = false`) because SigV4 signs the original host and path — following a redirect either drops the signature (cross-host, Go strips `Authorization`) or sends an invalid one (same-host, different path). When enabled, `allowed_redirect_hosts` gates destinations.
- **`X-Amz-Content-Sha256` is opt-in** (`set_content_sha256_header = true`). S3 requires it; most other services don't.
- **`sign_body = false`** signs with `UNSIGNED-PAYLOAD` instead of hashing the body — useful for streaming uploads.
- **`max_response_body_bytes`** caps how much body is read into memory. Unset means no cap.

See [`docs/ephemeral-resources/request.md`](docs/ephemeral-resources/request.md) for the full schema, and [`examples/ephemeral-resources/awssigv4_request/`](examples/ephemeral-resources/awssigv4_request/) for a few HCL snippets.

## Building locally

```sh
go build ./...
go test ./...
```

The generated `docs/` tree is verified by [`.github/workflows/test.yml`](.github/workflows/test.yml) on every PR — if you've changed the schema, run `cd tools && go generate ./...` and commit the result; CI will fail otherwise.

For local development against a real Terraform config, add a `dev_overrides` block to `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "asana/awssigv4" = "/absolute/path/to/this/repo"
  }
  direct {}
}
```

Then `go install .` and run `terraform plan` directly — skip `terraform init`. See the [Terraform plugin development overrides](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers) docs.

## Releasing

Releases are manually triggered from [`.github/workflows/release.yml`](.github/workflows/release.yml): open the Actions tab, pick **Release**, choose `main` as the ref, and enter the version (e.g. `0.1.0`). The workflow validates the version string, creates and pushes the `v<version>` tag itself, then runs [GoReleaser](https://goreleaser.com) using [`.goreleaser.yml`](.goreleaser.yml) to build binaries for the platform matrix the Terraform Registry requires and GPG-sign the `SHA256SUMS` checksum file.

The release-from-`main` flow lets the IAM role's trust policy be scoped to `refs/heads/main`. Branch protection on `main` is then the security boundary, instead of tag protection. Once tag protection is set up, switch the workflow's `on:` trigger back to `push.tags: ['v*']` and remove the tag-creation step.

One-time setup before the first release:

1. **Generate a dedicated, passphraseless GPG key** for release signing (do not reuse your personal key). RSA or DSA, not ECC.
   ```sh
   gpg --batch --gen-key <<EOF
   %no-protection
   Key-Type: RSA
   Key-Length: 4096
   Name-Real: terraform-provider-awssigv4 releases
   Name-Email: releases@example.invalid
   Expire-Date: 0
   %commit
   EOF
   ```
2. Export the **public** key (ASCII-armored) and upload it under **User Settings → Signing Keys** on the Terraform Registry:
   ```sh
   gpg --armor --export <fingerprint>
   ```
3. Store the **private** key in **AWS Secrets Manager** as `terraform_provider_gpg_key`. Use a JSON value with a single key, `private_key`:
   ```sh
   PRIVATE_KEY="$(gpg --armor --export-secret-keys <fingerprint>)" \
     jq -n --arg private_key "$PRIVATE_KEY" '{private_key: $private_key}' \
   | aws secretsmanager create-secret \
       --name terraform_provider_gpg_key \
       --secret-string file:///dev/stdin
   ```
   The release workflow reads the secret via `aws-actions/aws-secretsmanager-get-secrets`, which exposes it as the `GPG_PRIVATE_KEY` environment variable.
4. **Provision the IAM role** the workflow assumes via GitHub OIDC. The role ARN is already wired in `.github/workflows/release.yml`. Its trust policy should restrict `sts:AssumeRoleWithWebIdentity` to this repository's main branch (`repo:Asana/terraform-provider-awssigv4:ref:refs/heads/main`); its inline policy needs `secretsmanager:GetSecretValue` on the secret ARN above.
5. Publish the provider once via **Publish → Provider** on the Registry. Subsequent releases are picked up automatically from the GitHub release webhook.

## Attribution

The project skeleton (`main.go`, the provider package shell) was scaffolded from [hashicorp/terraform-provider-scaffolding-framework](https://github.com/hashicorp/terraform-provider-scaffolding-framework) (MPL-2.0, © HashiCorp, Inc. / IBM Corp.). AWS credential resolution uses [hashicorp/aws-sdk-go-base](https://github.com/hashicorp/aws-sdk-go-base), the same library the official `terraform-provider-aws` provider uses, so the credential provider chain (env vars, profiles, `credential_process`, SSO, IMDS, assume-role, web identity) behaves identically.

## License

MPL-2.0. See [`LICENSE`](LICENSE).
