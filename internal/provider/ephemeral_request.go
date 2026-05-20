// Copyright (c) Asana, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/ephemeral/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	// emptyPayloadSHA256 is the hex SHA-256 of the empty string — the value AWS
	// SigV4 requires for requests with no body.
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	unsignedPayload    = "UNSIGNED-PAYLOAD"

	defaultRetryAttempts          int           = 3
	defaultRetryMinDelay          time.Duration = 1 * time.Second
	defaultRetryMaxDelay          time.Duration = 30 * time.Second
	defaultRetryMultiplier        float64       = 2.0
	defaultMaxRedirects           int           = 10
)

// defaultRetryStatusCodes is the standard transient-failure set.
var defaultRetryStatusCodes = []int{408, 429, 500, 502, 503, 504}

var (
	_ ephemeral.EphemeralResource              = (*sigV4RequestEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithConfigure = (*sigV4RequestEphemeralResource)(nil)
)

type sigV4RequestEphemeralResource struct {
	cfg *ProviderConfig
}

// sigV4RequestModel is the typed config + result for `awssigv4_request`.
type sigV4RequestModel struct {
	URL                    types.String `tfsdk:"url"`
	Method                 types.String `tfsdk:"method"`
	Service                types.String `tfsdk:"service"`
	Region                 types.String `tfsdk:"region"`
	RequestHeaders         types.Map    `tfsdk:"request_headers"`
	RequestBody            types.String `tfsdk:"request_body"`
	RequestTimeout         types.String `tfsdk:"request_timeout"`
	CACertPEM              types.String `tfsdk:"ca_cert_pem"`
	Insecure               types.Bool   `tfsdk:"insecure"`
	SignBody               types.Bool   `tfsdk:"sign_body"`
	SetContentSha256Header types.Bool   `tfsdk:"set_content_sha256_header"`

	ExpectedStatusCodes         types.List     `tfsdk:"expected_status_codes"`
	IncludeResponseBodyInErrors types.Bool     `tfsdk:"include_response_body_in_errors"`
	FollowRedirects             types.Bool     `tfsdk:"follow_redirects"`
	MaxRedirects                types.Int64    `tfsdk:"max_redirects"`
	AllowedRedirectHosts        types.List     `tfsdk:"allowed_redirect_hosts"`
	MaxResponseBodyBytes        types.Int64    `tfsdk:"max_response_body_bytes"`
	Retry                       *retryModel    `tfsdk:"retry"`
	Timeouts                    timeouts.Value `tfsdk:"timeouts"`

	StatusCode         types.Int64  `tfsdk:"status_code"`
	Ok                 types.Bool   `tfsdk:"ok"`
	Attempts           types.Int64  `tfsdk:"attempts"`
	ResponseHeaders    types.Map    `tfsdk:"response_headers"`
	ResponseBody       types.String `tfsdk:"response_body"`
	ResponseBodyBase64 types.String `tfsdk:"response_body_base64"`
	ResponseBodyIsUTF8 types.Bool   `tfsdk:"response_body_is_utf8"`
}

// retryModel maps the optional `retry { ... }` block.
type retryModel struct {
	Attempts           types.Int64   `tfsdk:"attempts"`
	MinDelay           types.String  `tfsdk:"min_delay"`
	MaxDelay           types.String  `tfsdk:"max_delay"`
	Multiplier         types.Float64 `tfsdk:"multiplier"`
	OnStatusCodes      types.List    `tfsdk:"on_status_codes"`
	OnConnectionErrors types.Bool    `tfsdk:"on_connection_errors"`
}

// retryPolicy is the parsed, fully-defaulted retry configuration.
type retryPolicy struct {
	attempts           int
	minDelay           time.Duration
	maxDelay           time.Duration
	multiplier         float64
	onStatusCodes      []int
	onConnectionErrors bool
}

func NewSigV4RequestEphemeralResource() ephemeral.EphemeralResource {
	return &sigV4RequestEphemeralResource{}
}

func (r *sigV4RequestEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_request"
}

func (r *sigV4RequestEphemeralResource) Schema(ctx context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Sends an AWS SigV4-signed HTTP request to an arbitrary endpoint and exposes the response. " +
			"Credentials come from the provider's configured AWS credential chain (env vars, profiles, `credential_process`, SSO, " +
			"container/IMDS, assume-role, web identity).",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Required:    true,
				Description: "Full URL to request, e.g. `https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/foo/invocations`.",
			},
			"method": schema.StringAttribute{
				Optional:    true,
				Description: "HTTP method. Defaults to `GET`, or `POST` when `request_body` is set.",
			},
			"service": schema.StringAttribute{
				Required:    true,
				Description: "SigV4 service name (e.g. `execute-api`, `lambda`, `s3`, `apigateway`, `appsync`, `bedrock`).",
			},
			"region": schema.StringAttribute{
				Optional: true,
				Description: "SigV4 signing region. When omitted, falls back to the region resolved by the AWS SDK " +
					"(`AWS_REGION`/`AWS_DEFAULT_REGION` env var, or the active profile's `region` setting).",
			},
			"request_headers": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Headers to attach before signing. `Host`, `X-Amz-Date`, `Authorization`, and `X-Amz-Security-Token` are set by the signer; values for them are overwritten.",
			},
			"request_body": schema.StringAttribute{
				Optional:    true,
				Description: "Request body. Hashed for SigV4 unless `sign_body = false`.",
			},
			"request_timeout": schema.StringAttribute{
				Optional: true,
				Description: "Per-attempt HTTP timeout as a Go duration string (e.g. `\"5s\"`, `\"500ms\"`). " +
					"Unset or empty means no client-side timeout. With retries enabled, this applies to each attempt individually; " +
					"for an end-to-end budget covering all attempts and backoffs, use `timeouts { open = \"...\" }`.",
			},
			"ca_cert_pem": schema.StringAttribute{
				Optional:    true,
				Description: "Additional PEM-encoded CA bundle to trust when verifying the target endpoint's TLS certificate.",
			},
			"insecure": schema.BoolAttribute{
				Optional:    true,
				Description: "Skip TLS verification of the target endpoint.",
			},
			"sign_body": schema.BoolAttribute{
				Optional: true,
				Description: "If `false`, signs the request with `UNSIGNED-PAYLOAD` instead of hashing the body. " +
					"Useful for streaming uploads to services like S3. Defaults to `true`.",
			},
			"set_content_sha256_header": schema.BoolAttribute{
				Optional: true,
				Description: "If `true`, set the `X-Amz-Content-Sha256` request header to the value used when signing " +
					"(either the body's SHA-256 hex digest, or `UNSIGNED-PAYLOAD` when `sign_body = false`). " +
					"S3 requires this header; most other services do not. Defaults to `false`.",
			},

			"expected_status_codes": schema.ListAttribute{
				Optional:    true,
				ElementType: types.Int64Type,
				Description: "If set, fail the plan when the response status code is not in this list. " +
					"Unset means no enforcement — the caller can still gate downstream on `ok` or `status_code`.",
			},
			"include_response_body_in_errors": schema.BoolAttribute{
				Optional: true,
				Description: "If `true`, the response body is included in the diagnostic emitted when " +
					"`expected_status_codes` doesn't match. Defaults to `false` because a misconfigured allowlist " +
					"(e.g. expecting `201` but the endpoint returns `200`) would leak the response body — which " +
					"often contains tokens or other secrets — into Terraform's plaintext error output. " +
					"Diagnostics always include the status code, attempt count, body byte length, and `Content-Type` " +
					"header even when this is `false`.",
			},
			"follow_redirects": schema.BoolAttribute{
				Optional: true,
				Description: "If `true`, follow HTTP redirects. Defaults to `false` because SigV4 signs the original " +
					"host and path — following a redirect either drops the signature (cross-host) or sends an " +
					"invalid signature (same-host, different path). Combine with `allowed_redirect_hosts` to gate destinations.",
			},
			"max_redirects": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum redirects to follow when `follow_redirects = true`. Defaults to `10`.",
			},
			"allowed_redirect_hosts": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "When `follow_redirects = true`, restrict redirect destinations to these hostnames (exact match, case-insensitive). " +
					"Unset or empty means allow any host.",
			},
			"max_response_body_bytes": schema.Int64Attribute{
				Optional: true,
				Description: "Cap on response body size in bytes. If the server returns more, the request fails. " +
					"`0` (default) means no cap.",
			},

			"status_code": schema.Int64Attribute{
				Computed:    true,
				Description: "HTTP response status code of the final attempt.",
			},
			"ok": schema.BoolAttribute{
				Computed:    true,
				Description: "`true` when `status_code` is in the 2xx range.",
			},
			"attempts": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of attempts made, including the successful one. `1` when no retries occurred.",
			},
			"response_headers": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Response headers (first value per header).",
			},
			"response_body": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Response body as a UTF-8 string. Empty if the response body is not valid UTF-8 — use `response_body_is_utf8` to disambiguate from a genuinely empty body.",
			},
			"response_body_base64": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Response body, base64-encoded — set for any response, including binary ones.",
			},
			"response_body_is_utf8": schema.BoolAttribute{
				Computed:    true,
				Description: "`true` when the response body is valid UTF-8 (and therefore safely represented in `response_body`).",
			},
		},
		Blocks: map[string]schema.Block{
			"retry": schema.SingleNestedBlock{
				Description: "Retry transient failures. Each attempt is signed afresh, so SigV4's time-skew window does not bound the total retry budget.",
				Attributes: map[string]schema.Attribute{
					"attempts": schema.Int64Attribute{
						Optional:    true,
						Description: "Total attempts including the first one. Defaults to `3` when the block is present.",
					},
					"min_delay": schema.StringAttribute{
						Optional:    true,
						Description: "Initial delay before the first retry as a Go duration string (e.g. `\"1s\"`, `\"500ms\"`). Defaults to `\"1s\"`.",
					},
					"max_delay": schema.StringAttribute{
						Optional:    true,
						Description: "Upper bound on the backoff delay as a Go duration string. Defaults to `\"30s\"`.",
					},
					"multiplier": schema.Float64Attribute{
						Optional: true,
						Description: "Backoff multiplier applied between attempts. Each delay is `min_delay_ms * multiplier^(retry_index)`, " +
							"capped at `max_delay_ms`. Defaults to `2.0` (exponential doubling); set to `1.0` for constant delay.",
					},
					"on_status_codes": schema.ListAttribute{
						Optional:    true,
						ElementType: types.Int64Type,
						Description: "Response status codes that trigger a retry. Defaults to `[408, 429, 500, 502, 503, 504]`. " +
							"Set to `[]` to disable status-based retries entirely.",
					},
					"on_connection_errors": schema.BoolAttribute{
						Optional:    true,
						Description: "Retry on network/TLS/connection errors. Defaults to `true`.",
					},
				},
			},
			"timeouts": timeouts.Block(ctx),
		},
	}
}

func (r *sigV4RequestEphemeralResource) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	cfg, ok := req.ProviderData.(*ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("Expected *provider.ProviderConfig, got %T. This is a bug in terraform-provider-awssigv4.", req.ProviderData),
		)
		return
	}
	r.cfg = cfg
}

func (r *sigV4RequestEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data sigV4RequestModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.cfg == nil {
		resp.Diagnostics.AddError(
			"Provider not configured",
			"The awssigv4 provider was not configured. This is a bug in terraform-provider-awssigv4.",
		)
		return
	}

	region := data.Region.ValueString()
	if region == "" {
		region = r.cfg.DefaultRegion
	}
	if region == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"Missing region",
			"SigV4 requires a region. Set `region` on this ephemeral resource, set `AWS_REGION`/`AWS_DEFAULT_REGION`, "+
				"or set `region` on the active profile in your shared AWS config file.",
		)
		return
	}

	service := strings.TrimSpace(data.Service.ValueString())
	if service == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("service"),
			"Missing service",
			"`service` is required for SigV4 signing.",
		)
		return
	}

	method := strings.ToUpper(strings.TrimSpace(data.Method.ValueString()))
	body := []byte(data.RequestBody.ValueString())
	if method == "" {
		if len(body) > 0 {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}

	userHeaders := map[string]string{}
	if !data.RequestHeaders.IsNull() && !data.RequestHeaders.IsUnknown() {
		resp.Diagnostics.Append(data.RequestHeaders.ElementsAs(ctx, &userHeaders, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	signBody := true
	if !data.SignBody.IsNull() && !data.SignBody.IsUnknown() {
		signBody = data.SignBody.ValueBool()
	}
	var payloadHash string
	if !signBody {
		payloadHash = unsignedPayload
	} else if len(body) == 0 {
		payloadHash = emptyPayloadSHA256
	} else {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	expectedStatus, diags := int64ListAsInts(ctx, data.ExpectedStatusCodes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	retry, diags := parseRetryPolicy(ctx, data.Retry)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// End-to-end timeout from the `timeouts { open = "..." }` block, if set.
	openTimeout, diags := data.Timeouts.Open(ctx, 0)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if openTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, openTimeout)
		defer cancel()
	}

	maxBodyBytes := int64(0)
	if !data.MaxResponseBodyBytes.IsNull() && !data.MaxResponseBodyBytes.IsUnknown() {
		maxBodyBytes = data.MaxResponseBodyBytes.ValueInt64()
	}

	client, err := buildHTTPClient(ctx, data, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build HTTP client", err.Error())
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	creds, err := r.cfg.AWSConfig.Credentials.Retrieve(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to retrieve AWS credentials", err.Error())
		return
	}
	signer := v4.NewSigner()

	signRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, data.URL.ValueString(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}
		for k, v := range userHeaders {
			req.Header.Set(k, v)
		}
		if len(body) > 0 {
			req.ContentLength = int64(len(body))
		}
		if data.SetContentSha256Header.ValueBool() {
			req.Header.Set("X-Amz-Content-Sha256", payloadHash)
		}
		if err := signer.SignHTTP(ctx, creds, req, payloadHash, service, region, time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("signing request: %w", err)
		}
		return req, nil
	}

	httpResp, attempts, respBody, err := executeWithRetries(ctx, client, signRequest, retry, maxBodyBytes)
	if err != nil {
		resp.Diagnostics.AddError("HTTP request failed", err.Error())
		return
	}
	defer httpResp.Body.Close()

	if len(expectedStatus) > 0 && !slices.Contains(expectedStatus, httpResp.StatusCode) {
		resp.Diagnostics.AddError(
			"Unexpected response status",
			fmt.Sprintf(
				"Expected response status code in %v, got %d after %d attempt(s).%s",
				expectedStatus, httpResp.StatusCode, attempts,
				errorContext(httpResp, respBody, data.IncludeResponseBodyInErrors.ValueBool()),
			),
		)
		return
	}

	headerMap := make(map[string]string, len(httpResp.Header))
	for k, vs := range httpResp.Header {
		if len(vs) > 0 {
			headerMap[k] = vs[0]
		}
	}
	headersVal, diags := types.MapValueFrom(ctx, types.StringType, headerMap)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	bodyIsUTF8 := utf8.Valid(respBody)
	data.StatusCode = types.Int64Value(int64(httpResp.StatusCode))
	data.Ok = types.BoolValue(httpResp.StatusCode >= 200 && httpResp.StatusCode < 300)
	data.Attempts = types.Int64Value(int64(attempts))
	data.ResponseHeaders = headersVal
	data.ResponseBodyBase64 = types.StringValue(base64.StdEncoding.EncodeToString(respBody))
	data.ResponseBodyIsUTF8 = types.BoolValue(bodyIsUTF8)
	if bodyIsUTF8 {
		data.ResponseBody = types.StringValue(string(respBody))
	} else {
		data.ResponseBody = types.StringValue("")
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

// executeWithRetries runs signRequest() and client.Do() in a loop, applying
// the retry policy. The body of the *final* response is fully read into memory
// (subject to maxBodyBytes); intermediate retries have their bodies drained
// and discarded so connections can be reused.
func executeWithRetries(
	ctx context.Context,
	client *http.Client,
	signRequest func() (*http.Request, error),
	retry retryPolicy,
	maxBodyBytes int64,
) (*http.Response, int, []byte, error) {
	var (
		lastResp *http.Response
		lastErr  error
	)
	for attempt := 1; attempt <= retry.attempts; attempt++ {
		if attempt > 1 {
			delay := computeBackoff(attempt-1, retry.minDelay, retry.maxDelay, retry.multiplier)
			select {
			case <-ctx.Done():
				return nil, attempt - 1, nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := signRequest()
		if err != nil {
			return nil, attempt, nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if shouldRetryOnError(err, retry) && attempt < retry.attempts {
				continue
			}
			return nil, attempt, nil, err
		}

		// Retry on configured status codes (only if more attempts remain).
		if attempt < retry.attempts && slices.Contains(retry.onStatusCodes, resp.StatusCode) {
			// Drain & close so the connection can be reused.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			lastResp = resp
			lastErr = nil
			continue
		}

		respBody, readErr := readBody(resp.Body, maxBodyBytes)
		if readErr != nil {
			_ = resp.Body.Close()
			return nil, attempt, nil, readErr
		}
		return resp, attempt, respBody, nil
	}
	// Loop exited because we exhausted attempts. Prefer surfacing the last
	// status-based retry's response over the last connection error.
	if lastResp != nil {
		respBody, readErr := readBody(lastResp.Body, maxBodyBytes)
		if readErr != nil {
			_ = lastResp.Body.Close()
			return nil, retry.attempts, nil, readErr
		}
		return lastResp, retry.attempts, respBody, nil
	}
	return nil, retry.attempts, nil, lastErr
}

func readBody(body io.ReadCloser, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(body)
	}
	// Read up to maxBytes+1 so we can detect overflow.
	buf, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(buf)) > maxBytes {
		return nil, fmt.Errorf("response body exceeded max_response_body_bytes (%d)", maxBytes)
	}
	return buf, nil
}

func shouldRetryOnError(err error, retry retryPolicy) bool {
	if !retry.onConnectionErrors {
		return false
	}
	// Don't retry on intentional cancellation. Deadline-exceeded *can* indicate
	// transient slowness, so we do retry that.
	if errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

func computeBackoff(retryIndex int, minDelay, maxDelay time.Duration, multiplier float64) time.Duration {
	if retryIndex <= 0 {
		return minDelay
	}
	if multiplier <= 0 {
		multiplier = 1
	}
	d := float64(minDelay) * math.Pow(multiplier, float64(retryIndex))
	if d > float64(maxDelay) {
		d = float64(maxDelay)
	}
	if d < float64(minDelay) {
		d = float64(minDelay)
	}
	return time.Duration(d)
}

func parseRetryPolicy(ctx context.Context, m *retryModel) (retryPolicy, diag.Diagnostics) {
	policy := retryPolicy{
		attempts:           1,
		minDelay:           defaultRetryMinDelay,
		maxDelay:           defaultRetryMaxDelay,
		multiplier:         defaultRetryMultiplier,
		onStatusCodes:      append([]int(nil), defaultRetryStatusCodes...),
		onConnectionErrors: true,
	}
	if m == nil {
		return policy, nil
	}

	// Block present — default attempts up from 1.
	policy.attempts = defaultRetryAttempts

	var diags diag.Diagnostics
	if !m.Attempts.IsNull() && !m.Attempts.IsUnknown() {
		policy.attempts = int(m.Attempts.ValueInt64())
		if policy.attempts < 1 {
			policy.attempts = 1
		}
	}
	if d, ok := parseDurationField(m.MinDelay, path.Root("retry").AtName("min_delay"), &diags); ok {
		policy.minDelay = d
	}
	if diags.HasError() {
		return policy, diags
	}
	if d, ok := parseDurationField(m.MaxDelay, path.Root("retry").AtName("max_delay"), &diags); ok {
		policy.maxDelay = d
	}
	if diags.HasError() {
		return policy, diags
	}
	if !m.Multiplier.IsNull() && !m.Multiplier.IsUnknown() {
		policy.multiplier = m.Multiplier.ValueFloat64()
	}
	if !m.OnStatusCodes.IsNull() && !m.OnStatusCodes.IsUnknown() {
		codes, d := int64ListAsInts(ctx, m.OnStatusCodes)
		if d.HasError() {
			diags.Append(d...)
			return policy, diags
		}
		// Distinguish empty list (disable) from null (use defaults).
		policy.onStatusCodes = codes
	}
	if !m.OnConnectionErrors.IsNull() && !m.OnConnectionErrors.IsUnknown() {
		policy.onConnectionErrors = m.OnConnectionErrors.ValueBool()
	}
	return policy, diags
}

// parseDurationField parses a types.String as a Go duration. Returns (0, false)
// when the field is null/unknown/empty. Adds a framework diagnostic on parse
// failure and returns (0, false).
func parseDurationField(v types.String, attrPath path.Path, diags *diag.Diagnostics) (time.Duration, bool) {
	if v.IsNull() || v.IsUnknown() {
		return 0, false
	}
	s := strings.TrimSpace(v.ValueString())
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		diags.AddAttributeError(
			attrPath,
			"Invalid duration",
			fmt.Sprintf("Could not parse %q as a Go duration (e.g. %q, %q, %q): %s", s, "500ms", "5s", "1m30s", err),
		)
		return 0, false
	}
	return d, true
}

// int64ListAsInts decodes a types.List of int64 into []int. Null/unknown lists
// return (nil, nil); decoding errors flow back as framework diagnostics.
func int64ListAsInts(ctx context.Context, l types.List) ([]int, diag.Diagnostics) {
	if l.IsNull() || l.IsUnknown() {
		return nil, nil
	}
	raw := make([]int64, 0, len(l.Elements()))
	if diags := l.ElementsAs(ctx, &raw, false); diags.HasError() {
		return nil, diags
	}
	out := make([]int, 0, len(raw))
	for _, v := range raw {
		out = append(out, int(v))
	}
	return out, nil
}

func buildHTTPClient(ctx context.Context, m sigV4RequestModel, diags *diag.Diagnostics) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if m.Insecure.ValueBool() {
		tlsCfg.InsecureSkipVerify = true
	}
	if pem := m.CACertPEM.ValueString(); pem != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, fmt.Errorf("ca_cert_pem did not contain any valid PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}

	timeout, _ := parseDurationField(m.RequestTimeout, path.Root("request_timeout"), diags)
	if diags.HasError() {
		return nil, nil
	}

	followRedirects := m.FollowRedirects.ValueBool()
	maxRedirects := defaultMaxRedirects
	if !m.MaxRedirects.IsNull() && !m.MaxRedirects.IsUnknown() {
		maxRedirects = int(m.MaxRedirects.ValueInt64())
	}

	var allowedHosts []string
	if !m.AllowedRedirectHosts.IsNull() && !m.AllowedRedirectHosts.IsUnknown() {
		raw := make([]string, 0, len(m.AllowedRedirectHosts.Elements()))
		if diags := m.AllowedRedirectHosts.ElementsAs(ctx, &raw, false); diags.HasError() {
			return nil, fmt.Errorf("allowed_redirect_hosts: %s", diags.Errors()[0].Detail())
		}
		allowedHosts = make([]string, 0, len(raw))
		for _, h := range raw {
			allowedHosts = append(allowedHosts, strings.ToLower(h))
		}
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			Proxy:             http.ProxyFromEnvironment,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: redirectPolicy(followRedirects, maxRedirects, allowedHosts),
	}, nil
}

func redirectPolicy(follow bool, maxRedirects int, allowedHosts []string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !follow {
			return http.ErrUseLastResponse
		}
		if maxRedirects > 0 && len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if len(allowedHosts) > 0 {
			host := strings.ToLower(req.URL.Hostname())
			if !slices.Contains(allowedHosts, host) {
				return &redirectHostError{Target: req.URL, Allowed: allowedHosts}
			}
		}
		return nil
	}
}

// redirectHostError lets callers (and tests) recognize the host-rejection case
// without string matching.
type redirectHostError struct {
	Target  *url.URL
	Allowed []string
}

func (e *redirectHostError) Error() string {
	return fmt.Sprintf("redirect target %q not in allowed_redirect_hosts %v", e.Target.Host, e.Allowed)
}

// errorContext renders the trailing diagnostic lines for a status-mismatch
// error. Metadata (length, content-type) is always included. The body itself
// is *only* included when includeBody is true, because a misconfigured
// `expected_status_codes` allowlist would otherwise leak the response body —
// which is frequently a token or other secret — into plaintext error output.
func errorContext(httpResp *http.Response, body []byte, includeBody bool) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Response body length: %d byte(s).", len(body)))
	if ct := httpResp.Header.Get("Content-Type"); ct != "" {
		lines = append(lines, fmt.Sprintf("Content-Type: %s", ct))
	}
	if !includeBody {
		lines = append(lines, "Response body redacted. Set `include_response_body_in_errors = true` to include it; do so only when you are confident the body cannot contain sensitive material.")
		return "\n\n" + strings.Join(lines, "\n")
	}

	const limit = 4096
	switch {
	case len(body) == 0:
		lines = append(lines, "Response body was empty.")
	case !utf8.Valid(body):
		lines = append(lines, fmt.Sprintf("Response body is %d bytes of non-UTF-8 data; read `response_body_base64` if you need it.", len(body)))
	case len(body) > limit:
		lines = append(lines, fmt.Sprintf("Response body (first %d of %d bytes):\n%s", limit, len(body), string(body[:limit])))
	default:
		lines = append(lines, "Response body:\n"+string(body))
	}
	return "\n\n" + strings.Join(lines, "\n")
}

