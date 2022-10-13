// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && npm
// +build windows,npm

package tracer

import (
	"testing"
)

func dnsSupported(t *testing.T) bool {
	return true
}

func httpSupported(t *testing.T) bool {
	return false
}

func httpsSupported(t *testing.T) bool {
	return false
}

func protocolClassificationSupported(t *testing.T) bool {
	return false
}
