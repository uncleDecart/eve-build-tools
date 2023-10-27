// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package main runs the scanner
package main

import (
	"github.com/lf-edge/eve/tools/github-sbom-generator/cli"
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
