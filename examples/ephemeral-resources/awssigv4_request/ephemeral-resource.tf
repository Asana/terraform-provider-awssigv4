# Invoke an API Gateway endpoint protected with IAM auth.
ephemeral "awssigv4_request" "ping" {
  url     = "https://abcdef1234.execute-api.us-east-1.amazonaws.com/prod/ping"
  service = "execute-api"
  # region inherits from AWS_REGION / AWS_DEFAULT_REGION / the active profile if omitted
}

# Use the response inside another ephemeral context (write-only attributes, etc).
# Reading an ephemeral resource outside an `ephemeral`-aware context errors.

# POST a JSON payload to a Lambda function URL configured with AWS_IAM auth.
ephemeral "awssigv4_request" "invoke_lambda" {
  url     = "https://xyz.lambda-url.us-east-1.on.aws/"
  service = "lambda"
  region  = "us-east-1"
  method  = "POST"

  request_headers = {
    "Content-Type" = "application/json"
  }
  request_body = jsonencode({
    action = "warmup"
  })

  request_timeout = "10s"

  retry {
    attempts        = 3
    min_delay       = "1s"
    max_delay       = "10s"
    on_status_codes = [429, 502, 503, 504]
  }

  timeouts {
    open = "1m"
  }
}

# GET an object from S3. S3 requires the X-Amz-Content-Sha256 header, so
# opt in via `set_content_sha256_header`. `sign_body = false` switches the
# canonical request (and the header) to UNSIGNED-PAYLOAD.
ephemeral "awssigv4_request" "fetch_object" {
  url                       = "https://my-bucket.s3.us-east-1.amazonaws.com/secrets/api.key"
  service                   = "s3"
  sign_body                 = false
  set_content_sha256_header = true
}
