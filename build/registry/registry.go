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
	"fmt"
	"os"
	"regexp"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"gopkg.in/yaml.v2"
)

var (
	rgxName = regexp.MustCompile(`^[a-z]+[a-z0-9-_]*$`)
)

type Rulesfile struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Authors     string `yaml:"authors"`
	Contact     string `yaml:"contact"`
	Maintainers []struct {
		Email string `yaml:"email"`
		Name  string `yaml:"name"`
	} `yaml:"maintainers"`
	Keywords  []string         `yaml:"keywords"`
	Path      string           `yaml:"path"`
	URL       string           `yaml:"url"`
	License   string           `yaml:"license"`
	Reserved  bool             `yaml:"reserved"`
	Archived  bool             `yaml:"archived"`
	Signature *index.Signature `yaml:"signature,omitempty"`
}

type Registry struct {
	Rulesfiles []Rulesfile `yaml:"rulesfiles"`
}

// Validate returns nil if the Registry is valid, and an error otherwise.
func (r *Registry) Validate() error {
	names := make(map[string]bool)
	for _, p := range r.Rulesfiles {
		if !rgxName.MatchString(p.Name) {
			return fmt.Errorf("rulesfile name does follow the naming convention: '%s'", p.Name)
		}
		if _, ok := names[p.Name]; ok {
			return fmt.Errorf("rulesfile name is not unique: '%s'", p.Name)
		}
		names[p.Name] = true
	}

	return nil
}

// RulesfileByName returns the rulesfile in the index with the specified name, or nil if not found
func (r *Registry) RulesfileByName(name string) *Rulesfile {
	for _, rf := range r.Rulesfiles {
		if rf.Reserved || rf.Archived {
			continue
		}
		if rf.Name == name {
			return &rf
		}
	}
	return nil
}

func loadRegistryFromFile(fname string) (*Registry, error) {
	yamlFile, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	var registry Registry

	err = yaml.Unmarshal(yamlFile, &registry)
	if err != nil {
		return nil, err
	}

	return &registry, nil
}
