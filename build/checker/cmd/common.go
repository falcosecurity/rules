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

// compareInt returns 1 if "left" is greater than right,
// -1 if "right" is greater than left, and 0 otherwise.
func compareInt(a, b int) int {
	if a == b {
		return 0
	}
	if a < b {
		return -1
	}
	return 1
}

// compareFalcoPriorities returns 1 if "left" is more urgent than right,
// -1 if "right" is more urgent than left, and 0 otherwise.
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
	return compareInt(rIndex, lIndex)
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

// strSliceToMap returns a map[string]bool (a set, basically) from a strings slice.
func strSliceToMap(s []string) map[string]bool {
	items := make(map[string]bool)
	for _, item := range s {
		items[item] = true
	}
	return items
}

// diffStrSet returns a map[string]bool containing all the strings present
// in left but without the strings present in right.
func diffStrSet(left, right []string) map[string]bool {
	l := strSliceToMap(left)
	r := strSliceToMap(right)
	for k := range r {
		delete(l, k)
	}
	return l
}
