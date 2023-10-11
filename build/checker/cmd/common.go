// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
