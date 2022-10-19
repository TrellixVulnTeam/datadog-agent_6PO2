// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows && kubeapiserver
// +build !windows,kubeapiserver

// Package version implements 'cluster-agent version'.
package version

import (
	"fmt"
	"runtime"

	"github.com/DataDog/datadog-agent/cmd/cluster-agent/command"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/version"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// TODO(juliogreff): this command is almost exactly equivalent to
// `cmd/agent/subcommands/version`, the only difference is that it prints
// `Cluster Agent` instead of `Agent`.

// Commands returns a slice of subcommands for the 'cluster-agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version info",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(run)
		},
	}

	return []*cobra.Command{versionCmd}
}

func run() error {
	av, _ := version.Agent()
	meta := ""

	if av.Meta != "" {
		meta = fmt.Sprintf("- Meta: %s ", color.YellowString(av.Meta))
	}

	fmt.Fprintln(
		color.Output,
		fmt.Sprintf("Cluster agent %s %s- Commit: %s - Serialization version: %s - Go version: %s",
			color.CyanString(av.GetNumberAndPre()),
			meta,
			color.GreenString(version.Commit),
			color.YellowString(serializer.AgentPayloadVersion),
			color.RedString(runtime.Version()),
		),
	)

	return nil
}
