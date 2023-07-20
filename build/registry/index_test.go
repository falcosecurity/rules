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

package main

import (
	"reflect"
	"testing"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/stretchr/testify/assert"
)

func Test_upsertIndex(t *testing.T) {
	tests := []struct {
		name              string
		registryPath      string
		ociArtifacts      map[string]string
		indexPath         string
		expectedIndexPath string
	}{
		{
			"missing",
			"testdata/registry.yaml",
			map[string]string{"falco": "ghcr.io/falcosecurity/rules/falco"},
			"testdata/index1.yaml",
			"testdata/index_expected1.yaml",
		},
		{
			"already_present",
			"testdata/registry.yaml",
			map[string]string{"falco": "ghcr.io/falcosecurity/rules/falco"},
			"testdata/index2.yaml",
			"testdata/index2.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			i := index.New(GHOrg)
			assert.NoError(t, i.Read(tt.indexPath))
			expectedIndex := index.New(GHOrg)
			assert.NoError(t, expectedIndex.Read(tt.expectedIndexPath))

			r, err := loadRegistryFromFile(tt.registryPath)
			assert.NoError(t, err)

			upsertIndex(r, tt.ociArtifacts, i)

			if !reflect.DeepEqual(i, expectedIndex) {
				t.Errorf("index() = %v, want %v", i, expectedIndex)
			}
		})
	}
}

func TestPluginRulesToIndexEntrySignature(t *testing.T) {
	t.Parallel()

	signature := &index.Signature{
		Cosign: &index.CosignSignature{},
	}

	expected := signature

	p := Rulesfile{Signature: signature}

	entry := pluginRulesToIndexEntry(p, "", "")
	if !reflect.DeepEqual(entry.Signature, expected) {
		t.Fatalf("Index entry signature: expected %#v, got %v", expected, entry.Signature)
	}
}
