package cmd

import (
	"fmt"
	"math"
	"strings"
)

const defaultFalcoDockerImage = "falcosecurity/falco-no-driver:master"

const defaultFalcoDockerEntrypoint = "/usr/bin/falco"

var falcoPriorities = []string{
	"emergency",
	"alert",
	"critical",
	"error",
	"warning",
	"notice",
	"informational", // or "info"
	"debug",
}

// compareInt returns -1 if "left" is greater than right,
// 1 if "right" is greater than left, and 0 otherwise.
func compareInt(a, b int) int {
	if a == b {
		return 0
	}
	if a > b {
		return -1
	}
	return 1
}

// compareFalcoPriorities returns -1 if "left" is more urgent than right,
// 1 if "right" is more urgent than left, and 0 otherwise.
func compareFalcoPriorities(left, right string) int {
	lIndex := math.MaxInt
	rIndex := math.MaxInt
	for i, p := range falcoPriorities {
		if strings.HasPrefix(p, strings.ToLower(left)) {
			lIndex = i
		}
		if strings.HasPrefix(p, strings.ToLower(right)) {
			rIndex = i
		}
	}
	return compareInt(lIndex, rIndex)
}

// errAppend returns an error resulting froma appending two errors.
func errAppend(left, right error) error {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return fmt.Errorf("%s, %s", left.Error(), right.Error())
}
