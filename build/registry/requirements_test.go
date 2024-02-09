// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRulesFilesRequirement(t *testing.T) {
	req, err := rulesfileRequirement("testdata/rules-failed-req.yaml")
	assert.Error(t, err)

	req, err = rulesfileRequirement("testdata/rules-numeric-req.yaml")
	assert.NoError(t, err)
	assert.Equal(t, "0.15.0", req.Version)
	assert.Equal(t, "engine_version_semver", req.Name)

	req, err = rulesfileRequirement("testdata/rules-semver-req.yaml")
	assert.NoError(t, err)
	assert.Equal(t, "0.31.0", req.Version)
	assert.Equal(t, "engine_version_semver", req.Name)
}
