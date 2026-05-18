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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
)

var (
	_ ephemeral.EphemeralResource              = (*sigV4RequestEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithConfigure = (*sigV4RequestEphemeralResource)(nil)
)

type sigV4RequestEphemeralResource struct {
	cfg *ProviderConfig
}

// sigV4RequestModel is the typed config + result for `awssigv4_request`.
type sigV4RequestModel struct {
	URL                     types.String `tfsdk:"url"`
	Method                  types.String `tfsdk:"method"`
	Service                 types.String `tfsdk:"service"`
	Region                  types.String `tfsdk:"region"`
	RequestHeaders          types.Map    `tfsdk:"request_headers"`
	RequestBody             types.String `tfsdk:"request_body"`
	RequestTimeoutMs        types.Int64  `tfsdk:"request_timeout_ms"`
	CACertPEM               types.String `tfsdk:"ca_cert_pem"`
	Insecure                types.Bool   `tfsdk:"insecure"`
	SignBody                types.Bool   `tfsdk:"sign_body"`
	SetContentSha256Header  types.Bool   `tfsdk:"set_content_sha256_header"`

	StatusCode         types.Int64  `tfsdk:"status_code"`
	Ok                 types.Bool   `tfsdk:"ok"`
	ResponseHeaders    types.Map    `tfsdk:"response_headers"`
	ResponseBody       types.String `tfsdk:"response_body"`
	ResponseBodyBase64 types.String `tfsdk:"response_body_base64"`
	ResponseBodyIsUTF8 types.Bool   `tfsdk:"response_body_is_utf8"`
}

func NewSigV4RequestEphemeralResource() ephemeral.EphemeralResource {
	return &sigV4RequestEphemeralResource{}
}

func (r *sigV4RequestEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_request"
}

func (r *sigV4RequestEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
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
			"request_timeout_ms": schema.Int64Attribute{
				Optional:    true,
				Description: "Per-request timeout in milliseconds. `0` (default) means no client-side timeout.",
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

			"status_code": schema.Int64Attribute{
				Computed:    true,
				Description: "HTTP response status code.",
			},
			"ok": schema.BoolAttribute{
				Computed:    true,
				Description: "`true` when `status_code` is in the 2xx range.",
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

	httpReq, err := http.NewRequestWithContext(ctx, method, data.URL.ValueString(), bytes.NewReader(body))
	if err != nil {
		resp.Diagnostics.AddError("Invalid request URL", err.Error())
		return
	}

	if !data.RequestHeaders.IsNull() && !data.RequestHeaders.IsUnknown() {
		headers := map[string]string{}
		resp.Diagnostics.Append(data.RequestHeaders.ElementsAs(ctx, &headers, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for k, v := range headers {
			httpReq.Header.Set(k, v)
		}
	}
	// http.NewRequestWithContext sets ContentLength only when given a
	// *bytes.Reader/*bytes.Buffer/*strings.Reader, which we do — so it's
	// already correct. Ensure Content-Length header agrees for the signer.
	if len(body) > 0 {
		httpReq.ContentLength = int64(len(body))
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
	// S3 (and a few others) require the X-Amz-Content-Sha256 header to be set
	// to the same value used in the canonical request. For most services it's
	// unnecessary, so it's opt-in. Setting it before SignHTTP means the signer
	// includes it in the signed headers list, keeping body and header in sync.
	if data.SetContentSha256Header.ValueBool() {
		httpReq.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	creds, err := r.cfg.AWSConfig.Credentials.Retrieve(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to retrieve AWS credentials", err.Error())
		return
	}

	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, creds, httpReq, payloadHash, service, region, time.Now().UTC()); err != nil {
		resp.Diagnostics.AddError("Failed to sign request", err.Error())
		return
	}

	client, err := buildHTTPClient(data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build HTTP client", err.Error())
		return
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("HTTP request failed", err.Error())
		return
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read response body", err.Error())
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

func buildHTTPClient(m sigV4RequestModel) (*http.Client, error) {
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

	timeout := time.Duration(0)
	if !m.RequestTimeoutMs.IsNull() && !m.RequestTimeoutMs.IsUnknown() && m.RequestTimeoutMs.ValueInt64() > 0 {
		timeout = time.Duration(m.RequestTimeoutMs.ValueInt64()) * time.Millisecond
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			// Match Go's default but ensure we have control of the transport
			// for TLS config; everything else is left at default.
			Proxy:           http.ProxyFromEnvironment,
			ForceAttemptHTTP2: true,
		},
	}, nil
}

