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
	"context"
	"fmt"

	"k8s.io/klog/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
)

// pushCompressedRulesfile publishes rulesfile as OCI artifact and returns its digest.
// It possibly returns an error.
func pushCompressedRulesfile(
	ociClient remote.Client,
	filePath, repoRef, repoGit string,
	tags []string,
	config *oci.ArtifactConfig) (*string, error) {
	klog.Infof("Processing compressed rulesfile %q for repo %q and tags %s...", filePath, repoRef, tags)

	pusher := ocipusher.NewPusher(ociClient, false, nil)
	artifact, err := pusher.Push(context.Background(), oci.Rulesfile, repoRef,
		ocipusher.WithTags(tags...),
		ocipusher.WithFilepaths([]string{filePath}),
		ocipusher.WithAnnotationSource(repoGit),
		ocipusher.WithArtifactConfig(*config))

	if err != nil {
		return nil, fmt.Errorf("an error occurred while pushing: %w", err)
	}

	return &artifact.Digest, nil
}
