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
	"path/filepath"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
)

const (
	GHOrg = "falcosecurity"
)

func pluginRulesToIndexEntry(rf Rulesfile, registry, repo string) *index.Entry {
	return &index.Entry{
		Name:        rf.Name,
		Type:        string(oci.Rulesfile),
		Registry:    registry,
		Repository:  repo,
		Description: rf.Description,
		Home:        rf.URL,
		Keywords:    append(rf.Keywords, rf.Name),
		License:     rf.License,
		Maintainers: rf.Maintainers,
		Sources:     []string{rf.URL},
	}
}

func upsertIndex(r *Registry, ociArtifacts map[string]string, i *index.Index) {
	for _, rf := range r.Rulesfiles {
		// We only publish falcosecurity artifacts that have been uploaded to the repo.
		ref, ociRulesFound := ociArtifacts[rf.Name]

		// Build registry and repo starting from the reference.
		tokens := strings.Split(ref, "/")
		ociRegistry := tokens[0]
		ociRepo := filepath.Join(tokens[1:]...)
		if ociRulesFound {
			i.Upsert(pluginRulesToIndexEntry(rf, ociRegistry, ociRepo))
		}
	}
}

func upsertIndexFile(r *Registry, ociArtifacts map[string]string, indexPath string) error {
	i := index.New(GHOrg)

	if err := i.Read(indexPath); err != nil {
		return err
	}

	upsertIndex(r, ociArtifacts, i)

	return i.Write(indexPath)
}
