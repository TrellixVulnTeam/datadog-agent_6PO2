// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package module

import (
	"runtime"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"
)

type RuleFilterEvent struct {
	windowsVersion string
}

type RuleFilterModel struct {
	windowsVersion string
}

func NewRuleFilterModel() (*RuleFilterModel, error) {
	windowsVersion, err := winutil.GetWindowsBuildString()
	if err != nil {
		return nil, err
	}

	return &RuleFilterModel{
		windowsVersion: windowsVersion,
	}, nil
}

func (m *RuleFilterModel) NewEvent() eval.Event {
	return &RuleFilterEvent{
		windowsVersion: m.windowsVersion,
	}
}

func (m *RuleFilterModel) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {
	case "kernel.version.major", "kernel.version.minor", "kernel.version.patch",
		"kernel.version.abi", "kernel.version.flavor":
		return &eval.IntEvaluator{
			Value: 0,
			Field: field,
		}, nil

	case "os":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string { return runtime.GOOS },
			Field:   field,
		}, nil
	case "os.id", "os.platform_id", "os.version_id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string { return (*RuleFilterEvent)(ctx.Object).windowsVersion },
			Field:   field,
		}, nil

	case "os.is_amazon_linux", "os.is_cos", "os.is_debian", "os.is_oracle", "os.is_rhel", "os.is_rhel7",
		"os.is_rhel8", "os.is_sles", "os.is_sles12", "os.is_sles15":
		return &eval.BoolEvaluator{
			Value: false,
			Field: field,
		}, nil
	}

	return nil, &eval.ErrFieldNotFound{Field: field}
}

func (e *RuleFilterEvent) Init() {}

func (e *RuleFilterEvent) GetFieldValue(field eval.Field) (interface{}, error) {
	switch field {
	case "kernel.version.major", "kernel.version.minor", "kernel.version.patch",
		"kernel.version.abi", "kernel.version.flavor":
		return 0, nil

	case "os":
		return runtime.GOOS, nil
	case "os.id", "os.platform_id", "os.version_id":
		return e.windowsVersion, nil

	case "os.is_amazon_linux", "os.is_cos", "os.is_debian", "os.is_oracle", "os.is_rhel", "os.is_rhel7",
		"os.is_rhel8", "os.is_sles", "os.is_sles12", "os.is_sles15":
		return false, nil
	}

	return nil, &eval.ErrFieldNotFound{Field: field}
}
