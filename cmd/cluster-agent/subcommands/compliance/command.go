// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows && kubeapiserver
// +build !windows,kubeapiserver

// Package compliance implements 'cluster-agent compliance'.
package compliance

import (
	"github.com/DataDog/datadog-agent/cmd/cluster-agent/command"
	"github.com/DataDog/datadog-agent/pkg/cli/subcommands/compliance"
	"github.com/spf13/cobra"
)

// Commands returns a slice of subcommands for the 'cluster-agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	complianceCmd := &cobra.Command{
		Use:   "compliance",
		Short: "Compliance utility commands",
		Long:  ``,
	}

	// `compliance` has a `check` subcommand that's shared with other binaries
	complianceCmd.AddCommand(compliance.MakeCommand(func() compliance.GlobalParams {
		return compliance.GlobalParams{
			ConfFilePath: globalParams.ConfFilePath,
			ConfigName:   "datadog-cluster",
			LoggerName:   "CLUSTER",
		}
	}))

	return []*cobra.Command{complianceCmd}
}
