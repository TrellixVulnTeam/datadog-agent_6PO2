// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows && kubeapiserver
// +build !windows,kubeapiserver

package app

import (
	"github.com/DataDog/datadog-agent/cmd/security-agent/app/common"
	"github.com/DataDog/datadog-agent/pkg/cli/subcommands/compliance"
	"github.com/spf13/cobra"
)

// CheckCommands returns a cobra command to run security agent checks
func CheckCommands(globalParams *common.GlobalParams) []*cobra.Command {
	cmd := compliance.MakeCommand(func() compliance.GlobalParams {
		return compliance.GlobalParams{
			ConfFilePath: globalParams.ConfFilePath,
			ConfigName:   "datadog",
			LoggerName:   "CORE",
		}
	})

	return []*cobra.Command{cmd}
}
