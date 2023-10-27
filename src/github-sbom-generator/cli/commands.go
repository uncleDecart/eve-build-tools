// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

// New get a new root cli command
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github-sbom-generator",
		Short: "Generate SBOMs for github repos as a single unit",
		Long: `Generate SBOMs for one or more github repos as a single unit.
		Can generate for multiple at once. Output can be in spdx or spdx-json formats.
`,
	}
	cmd.AddCommand(generateCmd())
	return cmd
}
