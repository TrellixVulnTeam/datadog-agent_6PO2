// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package model

import (
	"fmt"

	"github.com/pkg/errors"
)

var (
	// ErrNotEnoughData is returned when the buffer is too small to unmarshal the event
	ErrNotEnoughData = errors.New("not enough data")

	// ErrNotEnoughSpace is returned when the provided buffer is too small to marshal the event
	ErrNotEnoughSpace = errors.New("not enough space")

	// ErrStringArrayOverflow returned when there is a string array overflow
	ErrStringArrayOverflow = errors.New("string array overflow")

	// ErrNonPrintable returned when a string contains non printable char
	ErrNonPrintable = errors.New("non printable")
)

// ErrInvalidPathKey is returned when inode or mountid are not valid
type ErrInvalidPathKey struct {
	Inode   uint64
	MountID uint32
}

func (e *ErrInvalidPathKey) Error() string {
	return fmt.Sprintf("invalid inode/mountID couple: %d/%d", e.Inode, e.MountID)
}
