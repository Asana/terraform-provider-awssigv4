// Copyright (c) HashiCorp, Inc. / IBM Corp. 2021, 2025
// Copyright (c) Asana, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Adapted from hashicorp/terraform-provider-scaffolding-framework.

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/asana/terraform-provider-awssigv4/internal/provider"
)

// version is set by goreleaser on release builds; "dev" otherwise.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/asana/awssigv4",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
