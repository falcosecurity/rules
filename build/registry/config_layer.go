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

package main

import (
	"errors"
	"fmt"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// rulesFileConfig generates the artifact configuration for a rulesfile given its path.
func rulesfileConfig(name, version, filePath string) (*oci.ArtifactConfig, error) {
	cfg := &oci.ArtifactConfig{
		Name:         name,
		Version:      version,
		Dependencies: nil,
		Requirements: nil,
	}

	// Get the requirements for the given file.
	req, err := rulesfileRequirement(filePath)
	if err != nil && !errors.Is(err, ErrReqNotFound) {
		return nil, err
	}
	// If found add it to the requirements list.
	if err == nil {
		_ = cfg.SetRequirement(req.Name, req.Version)
	}

	if cfg.Requirements == nil {
		return nil, fmt.Errorf("no dependencies or requirements found for rulesfile %q", filePath)
	}

	return cfg, nil
}
