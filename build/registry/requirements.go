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
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blang/semver"
	"github.com/falcosecurity/falcoctl/pkg/oci"
)

const (
	rulesEngineAnchor = "- required_engine_version"
	engineVersionKey  = "engine_version"
)

// ErrReqNotFound error when the requirements are not found in the rulesfile.
var ErrReqNotFound = errors.New("requirements not found")

// rulesfileRequirement given a rulesfile in yaml format it scans it and extracts its requirements.
func rulesfileRequirement(filePath string) (*oci.ArtifactRequirement, error) {
	var requirement string
	// Open the file.
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %q: %v", filePath, file)
	}

	defer file.Close()

	// Prepare the file to be read line by line.
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		if strings.HasPrefix(fileScanner.Text(), rulesEngineAnchor) {
			requirement = fileScanner.Text()
			break
		}
	}

	if requirement == "" {
		return nil, fmt.Errorf("requirements for rulesfile %q: %w", filePath, ErrReqNotFound)
	}

	// Split the requirement and parse the version as semVer.
	tokens := strings.Split(fileScanner.Text(), ":")
	reqVer, err := semver.Parse(tokens[1])
	if err != nil {
		// Check if the version is a expressed as an integer.
		ver, err := strconv.ParseUint(tokens[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unable to parse version %q as neither semver nor integer: %w", tokens[1], err)
		}
		reqVer = implicitEngineVersion(ver)
	}

	return &oci.ArtifactRequirement{
		Name:    engineVersionKey,
		Version: reqVer.String(),
	}, nil
}

func implicitEngineVersion(minor uint64) semver.Version {
	return semver.Version{
		Major: 0,
		Minor: minor,
		Patch: 0,
	}
}
