// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows && kubeapiserver
// +build !windows,kubeapiserver

package subcommands

import (
	"github.com/DataDog/datadog-agent/cmd/cluster-agent/command"
	cmdcheck "github.com/DataDog/datadog-agent/cmd/cluster-agent/subcommands/check"
	cmdcompliance "github.com/DataDog/datadog-agent/cmd/cluster-agent/subcommands/compliance"
	cmdstart "github.com/DataDog/datadog-agent/cmd/cluster-agent/subcommands/start"
	cmdversion "github.com/DataDog/datadog-agent/cmd/cluster-agent/subcommands/version"
)

// ClusterAgentSubcommands returns SubcommandFactories for the subcommands
// supported with the current build flags.
func ClusterAgentSubcommands() []command.SubcommandFactory {
	return []command.SubcommandFactory{
		cmdstart.Commands,
		cmdversion.Commands,
		cmdcheck.Commands,
		cmdcompliance.Commands,
		// clusterchecks.go
		// config.go
		// config_check.go
		// diagnose.go
		// dummy.go
		// flare.go
		// health.go
		// metadata_mapper_digest.go
		// secret_helper.go
		// status.go
		// telemetry.go
	}
}
