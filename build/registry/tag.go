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
	"fmt"
	"regexp"

	"github.com/blang/semver"
)

var (
	// see: https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
	// note: we have a capturing group for the plugin name prefix, so that we can use
	// it to specify the right make release target
	versionRegexp = regexp.MustCompile(`^([a-z]+[a-z0-9_\-]*)-((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?)$`)
)

type rulesfileNameSemver struct {
	Name   string
	Semver semver.Version
}

func (rn *rulesfileNameSemver) Version() string {
	return rn.Semver.String()
}

func parseGitTag(tag string) (*rulesfileNameSemver, error) {
	sm := versionRegexp.FindStringSubmatch(tag)
	if len(sm) == 0 {
		return nil, fmt.Errorf("tag %s could not be matched to a rulesfile name-version", tag)
	}

	rv := &rulesfileNameSemver{
		Name: sm[1],
	}

	sv, err := semver.Parse(sm[2])
	if err != nil {
		return nil, err
	}

	rv.Semver = sv

	return rv, nil
}

func isLatestSemver(newSemver semver.Version, existingSemvers []semver.Version) bool {
	for _, esv := range existingSemvers {
		if esv.GT(newSemver) {
			return false
		}
	}

	return true
}

func isLatestSemverForMinor(newSemver semver.Version, existingSemvers []semver.Version) bool {
	for _, esv := range existingSemvers {
		if esv.Minor == newSemver.Minor && esv.Major == newSemver.Major && esv.GT(newSemver) {
			return false
		}
	}

	return true
}

func isLatestSemverForMajor(newSemver semver.Version, existingSemvers []semver.Version) bool {
	for _, esv := range existingSemvers {
		if esv.Major == newSemver.Major && esv.GT(newSemver) {
			return false
		}
	}

	return true
}

// ociTagsToUpdate returns the MAJOR.MINOR tag to update if any, the latest tag if any and the new tag to update
// in OCI registry given a new (already semver) tag and a list of existing tags in the OCI repo
func ociTagsToUpdate(newTag string, existingTags []string) []string {
	newSemver := semver.MustParse(newTag)
	tagsToUpdate := []string{newSemver.String()}

	if len(newSemver.Pre) > 0 {
		// pre-release version, do not update anything else
		return tagsToUpdate
	}

	var existingFinalSemvers []semver.Version
	for _, tag := range existingTags {
		if sv, err := semver.Parse(tag); err == nil {
			// ignore prereleases
			if len(sv.Pre) == 0 {
				existingFinalSemvers = append(existingFinalSemvers, sv)
			}
		}
	}

	if isLatestSemverForMinor(newSemver, existingFinalSemvers) {
		tagsToUpdate = append(tagsToUpdate, fmt.Sprintf("%d.%d", newSemver.Major, newSemver.Minor))
	}

	if isLatestSemverForMajor(newSemver, existingFinalSemvers) {
		tagsToUpdate = append(tagsToUpdate, fmt.Sprintf("%d", newSemver.Major))
	}

	if isLatestSemver(newSemver, existingFinalSemvers) {
		tagsToUpdate = append(tagsToUpdate, "latest")
	}

	return tagsToUpdate
}
