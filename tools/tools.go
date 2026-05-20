// Copyright (c) HashiCorp, Inc. / IBM Corp. 2021, 2025
// Copyright (c) Asana, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build generate

package tools

import (
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)

// Format Terraform code used inside docs/examples.
//go:generate terraform fmt -recursive ../examples/

// Generate the docs/ tree for the Terraform Registry.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-dir .. -provider-name awssigv4
