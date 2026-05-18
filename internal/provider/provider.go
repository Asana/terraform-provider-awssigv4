// Copyright (c) HashiCorp, Inc. / IBM Corp. 2021, 2025
// Copyright (c) Asana, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Structure adapted from hashicorp/terraform-provider-scaffolding-framework;
// schema content and AWS credential plumbing are original.

package provider

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	awsbasediag "github.com/hashicorp/aws-sdk-go-base/v2/diag"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.Provider                       = (*AwsSigV4Provider)(nil)
	_ provider.ProviderWithEphemeralResources = (*AwsSigV4Provider)(nil)
)

// AwsSigV4Provider is the Terraform provider that exposes the SigV4 ephemeral
// resource.
type AwsSigV4Provider struct {
	version string
}

// ProviderConfig is what gets passed to ephemeral resources via
// ConfigureResponse.EphemeralResourceData. It carries everything the SigV4
// request needs: an AWS SDK config (whose credential provider already honors
// the full default chain — env vars, shared config/credentials files including
// credential_process, SSO, container/IMDS, assume-role, web identity), plus
// the provider-level default region that ephemeral resources fall back to.
type ProviderConfig struct {
	AWSConfig     aws.Config
	DefaultRegion string
}

// ProviderModel mirrors the HCL `provider "awssigv4" { ... }` block.
type ProviderModel struct {
	AccessKey                      types.String                    `tfsdk:"access_key"`
	SecretKey                      types.String                    `tfsdk:"secret_key"`
	Token                          types.String                    `tfsdk:"token"`
	Profile                        types.String                    `tfsdk:"profile"`
	SharedConfigFiles              types.List                      `tfsdk:"shared_config_files"`
	SharedCredentialsFiles         types.List                      `tfsdk:"shared_credentials_files"`
	CustomCABundle                 types.String                    `tfsdk:"custom_ca_bundle"`
	MaxRetries                     types.Int64                     `tfsdk:"max_retries"`
	RetryMode                      types.String                    `tfsdk:"retry_mode"`
	SkipCredentialsValidation      types.Bool                      `tfsdk:"skip_credentials_validation"`
	SkipMetadataAPICheck           types.Bool                      `tfsdk:"skip_metadata_api_check"`
	UseFIPSEndpoint                types.Bool                      `tfsdk:"use_fips_endpoint"`
	UseDualStackEndpoint           types.Bool                      `tfsdk:"use_dualstack_endpoint"`
	Insecure                       types.Bool                      `tfsdk:"insecure"`
	HTTPProxy                      types.String                    `tfsdk:"http_proxy"`
	HTTPSProxy                     types.String                    `tfsdk:"https_proxy"`
	NoProxy                        types.String                    `tfsdk:"no_proxy"`
	EC2MetadataServiceEndpoint     types.String                    `tfsdk:"ec2_metadata_service_endpoint"`
	EC2MetadataServiceEndpointMode types.String                    `tfsdk:"ec2_metadata_service_endpoint_mode"`
	STSEndpoint                    types.String                    `tfsdk:"sts_endpoint"`
	STSRegion                      types.String                    `tfsdk:"sts_region"`
	AssumeRole                     *AssumeRoleModel                `tfsdk:"assume_role"`
	AssumeRoleWithWebIdentity      *AssumeRoleWithWebIdentityModel `tfsdk:"assume_role_with_web_identity"`
}

// AssumeRoleModel models the `assume_role { ... }` nested block.
type AssumeRoleModel struct {
	RoleARN           types.String `tfsdk:"role_arn"`
	SessionName       types.String `tfsdk:"session_name"`
	ExternalID        types.String `tfsdk:"external_id"`
	Policy            types.String `tfsdk:"policy"`
	PolicyARNs        types.List   `tfsdk:"policy_arns"`
	DurationSeconds   types.Int64  `tfsdk:"duration_seconds"`
	SourceIdentity    types.String `tfsdk:"source_identity"`
	Tags              types.Map    `tfsdk:"tags"`
	TransitiveTagKeys types.List   `tfsdk:"transitive_tag_keys"`
}

// AssumeRoleWithWebIdentityModel models the `assume_role_with_web_identity { ... }` nested block.
type AssumeRoleWithWebIdentityModel struct {
	RoleARN              types.String `tfsdk:"role_arn"`
	SessionName          types.String `tfsdk:"session_name"`
	Policy               types.String `tfsdk:"policy"`
	PolicyARNs           types.List   `tfsdk:"policy_arns"`
	DurationSeconds      types.Int64  `tfsdk:"duration_seconds"`
	WebIdentityToken     types.String `tfsdk:"web_identity_token"`
	WebIdentityTokenFile types.String `tfsdk:"web_identity_token_file"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &AwsSigV4Provider{version: version}
	}
}

func (p *AwsSigV4Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "awssigv4"
	resp.Version = p.version
}

func (p *AwsSigV4Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Configures AWS credentials for the `awssigv4_request` ephemeral resource. " +
			"All fields are optional — when omitted, the standard AWS SDK default credential provider chain applies " +
			"(env vars, shared config/credentials files including `credential_process`, SSO, container/IMDS, etc.). " +
			"There is no provider-level region attribute: the SigV4 signing region is resolved in this order — " +
			"the ephemeral resource's `region` argument, then `AWS_REGION`/`AWS_DEFAULT_REGION`, then the active profile's `region` setting.",
		Attributes: map[string]schema.Attribute{
			"access_key": schema.StringAttribute{
				Optional:    true,
				Description: "Static AWS access key ID. Prefer profiles or the default credential chain.",
			},
			"secret_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Static AWS secret access key. Prefer profiles or the default credential chain.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Static AWS session token to pair with `access_key`/`secret_key`.",
			},
			"profile": schema.StringAttribute{
				Optional:    true,
				Description: "Named profile from the shared config/credentials files.",
			},
			"shared_config_files": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Paths to shared AWS config files. Defaults to `~/.aws/config`.",
			},
			"shared_credentials_files": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Paths to shared AWS credentials files. Defaults to `~/.aws/credentials`.",
			},
			"custom_ca_bundle": schema.StringAttribute{
				Optional:    true,
				Description: "Path to a PEM-encoded CA bundle for AWS API calls (STS, IMDS, SSO).",
			},
			"max_retries": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of times the AWS SDK retries failed API calls during credential resolution.",
			},
			"retry_mode": schema.StringAttribute{
				Optional:    true,
				Description: "Retry mode for the AWS SDK: `standard` or `adaptive`.",
			},
			"skip_credentials_validation": schema.BoolAttribute{
				Optional:    true,
				Description: "Skip the STS `GetCallerIdentity` call used to validate credentials at provider startup.",
			},
			"skip_metadata_api_check": schema.BoolAttribute{
				Optional:    true,
				Description: "Disable the EC2 IMDS as a credential source.",
			},
			"use_fips_endpoint": schema.BoolAttribute{
				Optional:    true,
				Description: "Use FIPS-compliant AWS endpoints when resolving credentials.",
			},
			"use_dualstack_endpoint": schema.BoolAttribute{
				Optional:    true,
				Description: "Use dual-stack (IPv4/IPv6) AWS endpoints when resolving credentials.",
			},
			"insecure": schema.BoolAttribute{
				Optional:    true,
				Description: "Skip TLS verification on AWS API endpoints (does not affect the SigV4 target URL).",
			},
			"http_proxy": schema.StringAttribute{
				Optional:    true,
				Description: "HTTP proxy URL used for AWS API calls.",
			},
			"https_proxy": schema.StringAttribute{
				Optional:    true,
				Description: "HTTPS proxy URL used for AWS API calls.",
			},
			"no_proxy": schema.StringAttribute{
				Optional:    true,
				Description: "Comma-separated list of hosts that bypass the proxy.",
			},
			"ec2_metadata_service_endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Override the IMDS endpoint.",
			},
			"ec2_metadata_service_endpoint_mode": schema.StringAttribute{
				Optional:    true,
				Description: "IMDS endpoint mode: `IPv4` or `IPv6`.",
			},
			"sts_endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Override the STS endpoint URL (used when assuming roles).",
			},
			"sts_region": schema.StringAttribute{
				Optional:    true,
				Description: "Region for STS calls; defaults to `region` when unset.",
			},
		},
		Blocks: map[string]schema.Block{
			"assume_role": schema.SingleNestedBlock{
				Description: "Assume an IAM role before signing requests.",
				Attributes: map[string]schema.Attribute{
					"role_arn": schema.StringAttribute{
						Optional:    true,
						Description: "ARN of the role to assume.",
					},
					"session_name": schema.StringAttribute{
						Optional:    true,
						Description: "Session name for the assumed role.",
					},
					"external_id": schema.StringAttribute{
						Optional:    true,
						Description: "External ID used when assuming the role.",
					},
					"policy": schema.StringAttribute{
						Optional:    true,
						Description: "Inline session policy.",
					},
					"policy_arns": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "ARNs of managed policies to attach to the session.",
					},
					"duration_seconds": schema.Int64Attribute{
						Optional:    true,
						Description: "Session duration in seconds.",
					},
					"source_identity": schema.StringAttribute{
						Optional:    true,
						Description: "Source identity to set on the session.",
					},
					"tags": schema.MapAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Session tags.",
					},
					"transitive_tag_keys": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Session tag keys passed to subsequent role chaining.",
					},
				},
			},
			"assume_role_with_web_identity": schema.SingleNestedBlock{
				Description: "Assume an IAM role using a web identity (OIDC) token.",
				Attributes: map[string]schema.Attribute{
					"role_arn": schema.StringAttribute{
						Optional:    true,
						Description: "ARN of the role to assume.",
					},
					"session_name": schema.StringAttribute{
						Optional:    true,
						Description: "Session name for the assumed role.",
					},
					"policy": schema.StringAttribute{
						Optional:    true,
						Description: "Inline session policy.",
					},
					"policy_arns": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "ARNs of managed policies to attach to the session.",
					},
					"duration_seconds": schema.Int64Attribute{
						Optional:    true,
						Description: "Session duration in seconds.",
					},
					"web_identity_token": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Web identity (OIDC) token value.",
					},
					"web_identity_token_file": schema.StringAttribute{
						Optional:    true,
						Description: "Path to a file containing the web identity (OIDC) token.",
					},
				},
			},
		},
	}
}

func (p *AwsSigV4Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var model ProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	baseCfg := awsbase.Config{
		CallerName:                     "terraform-provider-awssigv4",
		CallerDocumentationURL:         "https://github.com/asana/terraform-provider-awssigv4",
		AccessKey:                      model.AccessKey.ValueString(),
		SecretKey:                      model.SecretKey.ValueString(),
		Token:                          model.Token.ValueString(),
		Profile:                        model.Profile.ValueString(),
		CustomCABundle:                 model.CustomCABundle.ValueString(),
		Insecure:                       model.Insecure.ValueBool(),
		SkipCredsValidation:            model.SkipCredentialsValidation.ValueBool(),
		UseFIPSEndpoint:                model.UseFIPSEndpoint.ValueBool(),
		UseDualStackEndpoint:           model.UseDualStackEndpoint.ValueBool(),
		EC2MetadataServiceEndpoint:     model.EC2MetadataServiceEndpoint.ValueString(),
		EC2MetadataServiceEndpointMode: model.EC2MetadataServiceEndpointMode.ValueString(),
		StsEndpoint:                    model.STSEndpoint.ValueString(),
		StsRegion:                      model.STSRegion.ValueString(),
		NoProxy:                        model.NoProxy.ValueString(),
	}

	if !model.HTTPProxy.IsNull() && !model.HTTPProxy.IsUnknown() {
		v := model.HTTPProxy.ValueString()
		baseCfg.HTTPProxy = &v
	}
	if !model.HTTPSProxy.IsNull() && !model.HTTPSProxy.IsUnknown() {
		v := model.HTTPSProxy.ValueString()
		baseCfg.HTTPSProxy = &v
	}
	if !model.MaxRetries.IsNull() && !model.MaxRetries.IsUnknown() {
		baseCfg.MaxRetries = int(model.MaxRetries.ValueInt64())
	}
	if v := model.RetryMode.ValueString(); v != "" {
		baseCfg.RetryMode = aws.RetryMode(v)
	}
	if model.SkipMetadataAPICheck.ValueBool() {
		baseCfg.EC2MetadataServiceEnableState = imds.ClientDisabled
	}

	if list, diags := stringSliceFromList(ctx, model.SharedConfigFiles); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	} else {
		baseCfg.SharedConfigFiles = list
	}
	if list, diags := stringSliceFromList(ctx, model.SharedCredentialsFiles); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	} else {
		baseCfg.SharedCredentialsFiles = list
	}

	if model.AssumeRole != nil {
		ar := *model.AssumeRole
		entry := awsbase.AssumeRole{
			RoleARN:        ar.RoleARN.ValueString(),
			SessionName:    ar.SessionName.ValueString(),
			ExternalID:     ar.ExternalID.ValueString(),
			Policy:         ar.Policy.ValueString(),
			SourceIdentity: ar.SourceIdentity.ValueString(),
		}
		if !ar.DurationSeconds.IsNull() && !ar.DurationSeconds.IsUnknown() {
			entry.Duration = time.Duration(ar.DurationSeconds.ValueInt64()) * time.Second
		}
		if arns, diags := stringSliceFromList(ctx, ar.PolicyARNs); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		} else {
			entry.PolicyARNs = arns
		}
		if keys, diags := stringSliceFromList(ctx, ar.TransitiveTagKeys); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		} else {
			entry.TransitiveTagKeys = keys
		}
		if !ar.Tags.IsNull() && !ar.Tags.IsUnknown() {
			tags := map[string]string{}
			resp.Diagnostics.Append(ar.Tags.ElementsAs(ctx, &tags, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			entry.Tags = tags
		}
		if entry.RoleARN != "" {
			baseCfg.AssumeRole = []awsbase.AssumeRole{entry}
		}
	}

	if model.AssumeRoleWithWebIdentity != nil {
		ar := *model.AssumeRoleWithWebIdentity
		wi := &awsbase.AssumeRoleWithWebIdentity{
			RoleARN:              ar.RoleARN.ValueString(),
			SessionName:          ar.SessionName.ValueString(),
			Policy:               ar.Policy.ValueString(),
			WebIdentityToken:     ar.WebIdentityToken.ValueString(),
			WebIdentityTokenFile: ar.WebIdentityTokenFile.ValueString(),
		}
		if !ar.DurationSeconds.IsNull() && !ar.DurationSeconds.IsUnknown() {
			wi.Duration = time.Duration(ar.DurationSeconds.ValueInt64()) * time.Second
		}
		if arns, diags := stringSliceFromList(ctx, ar.PolicyARNs); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		} else {
			wi.PolicyARNs = arns
		}
		if wi.RoleARN != "" {
			baseCfg.AssumeRoleWithWebIdentity = wi
		}
	}

	_, awsCfg, awsDiags := awsbase.GetAwsConfig(ctx, &baseCfg)
	for _, d := range awsDiags {
		if d.Severity() == awsbasediag.SeverityError {
			resp.Diagnostics.AddError(d.Summary(), d.Detail())
		} else {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	pc := &ProviderConfig{AWSConfig: awsCfg, DefaultRegion: awsCfg.Region}
	resp.EphemeralResourceData = pc
	resp.ResourceData = pc
	resp.DataSourceData = pc
}

func (p *AwsSigV4Provider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *AwsSigV4Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *AwsSigV4Provider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewSigV4RequestEphemeralResource,
	}
}

// stringSliceFromList decodes a types.List of strings to []string. Null and
// unknown lists become nil so they are treated as "unset" by aws-sdk-go-base.
func stringSliceFromList(ctx context.Context, l types.List) ([]string, diag.Diagnostics) {
	if l.IsNull() || l.IsUnknown() {
		return nil, nil
	}
	out := make([]string, 0, len(l.Elements()))
	diags := l.ElementsAs(ctx, &out, false)
	return out, diags
}
