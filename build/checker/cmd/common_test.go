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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareInt(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -1, compareInt(1, 2))
	assert.Equal(t, -1, compareInt(1, 5))
	assert.Equal(t, 0, compareInt(5, 5))
	assert.Equal(t, 1, compareInt(6, 5))
	assert.Equal(t, 1, compareInt(10, 5))
}

func TestCompareFalcoPriorities(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -1, compareFalcoPriorities("debug", "info"))
	assert.Equal(t, 1, compareFalcoPriorities("info", "debug"))
	assert.Equal(t, 0, compareFalcoPriorities("info", "informational"))
}

func TestDiffStrSet(t *testing.T) {
	t.Parallel()
	a := []string{"a", "b", "c"}
	b := []string{"b", "d"}

	d1 := diffStrSet(a, b)
	assert.Len(t, d1, 2)
	assert.Contains(t, d1, "a")
	assert.Contains(t, d1, "c")

	d2 := diffStrSet(b, a)
	assert.Len(t, d2, 1)
	assert.Contains(t, d2, "d")
}
