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
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	RegistryTokenEnv = "REGISTRY_TOKEN"
	RegistryUserEnv  = "REGISTRY_USER"
	OCIRepoPrefixEnv = "OCI_REPO_PREFIX"
	RepoGithubEnv    = "GITHUB_REPO_URL"
	S3BucketEnv      = "AWS_S3_BUCKET"
	S3PrefixEnv      = "AWS_S3_PREFIX"
	S3RegionEnv      = "AWS_S3_REGION"
)

func doCheck(fileName string) error {
	registry, err := loadRegistryFromFile(fileName)
	if err != nil {
		return err
	}
	return registry.Validate()
}

func doUploadToS3(registryFilename, gitTag string) error {
	var s3prefix, s3bucket, s3region string
	var found bool

	if s3prefix, found = os.LookupEnv(S3PrefixEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", S3PrefixEnv)
	}

	if s3bucket, found = os.LookupEnv(S3BucketEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", S3BucketEnv)
	}

	if s3region, found = os.LookupEnv(S3RegionEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", S3RegionEnv)
	}

	s3s, err := session.NewSession(&aws.Config{Region: aws.String(s3region)})
	if err != nil {
		log.Fatal(err)
	}

	pt, err := parseGitTag(gitTag)
	if err != nil {
		return err
	}

	reg, err := loadRegistryFromFile(registryFilename)
	if err != nil {
		return fmt.Errorf("could not read registry from %s: %w", registryFilename, err)
	}

	rulesfileInfo := reg.RulesfileByName(pt.Name)
	if rulesfileInfo == nil {
		return fmt.Errorf("could not find rulesfile %s in registry", pt.Name)
	}

	tmpDir, err := os.MkdirTemp("", "falco-artifacts-to-upload")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tgzFile := filepath.Join(tmpDir, filepath.Base(rulesfileInfo.Path)+".tar.gz")
	if err = tarGzSingleFile(tgzFile, rulesfileInfo.Path); err != nil {
		return fmt.Errorf("could not compress %s: %w", rulesfileInfo.Path, err)
	}
	defer os.RemoveAll(tgzFile)

	key := path.Join(s3prefix, gitTag+".tar.gz")
	if err = s3UploadFile(s3s, s3bucket, tgzFile, key); err != nil {
		return fmt.Errorf("could not upload %s to bucket %s, key %s: %w", tgzFile, s3bucket, key, err)
	}

	return nil
}

func doPushToOCI(registryFilename, gitTag string) (*string, error) {
	var ociRepoPrefix, repoGit, user, token string
	var found bool

	if token, found = os.LookupEnv(RegistryTokenEnv); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RegistryTokenEnv)
	}

	if user, found = os.LookupEnv(RegistryUserEnv); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RegistryUserEnv)
	}

	if ociRepoPrefix, found = os.LookupEnv(OCIRepoPrefixEnv); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", OCIRepoPrefixEnv)
	}

	if repoGit, found = os.LookupEnv(RepoGithubEnv); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RepoGithubEnv)
	}

	pt, err := parseGitTag(gitTag)
	if err != nil {
		return nil, err
	}

	cred := &auth.Credential{
		Username: user,
		Password: token,
	}

	client := authn.NewClient(authn.WithCredentials(cred))
	ociRepoRef := fmt.Sprintf("%s/%s", ociRepoPrefix, pt.Name)

	reg, err := loadRegistryFromFile(registryFilename)
	if err != nil {
		return nil, fmt.Errorf("could not read registry from %s: %w", registryFilename, err)
	}

	rulesfileInfo := reg.RulesfileByName(pt.Name)
	if rulesfileInfo == nil {
		return nil, fmt.Errorf("could not find rulesfile %s in registry", pt.Name)
	}

	// Create the repository object for the ref.
	var repo *repository.Repository
	if repo, err = repository.NewRepository(ociRepoRef, repository.WithClient(client)); err != nil {
		return nil, fmt.Errorf("unable to create repository for ref %q: %w", ociRepoRef, err)
	}

	existingTags, _ := repo.Tags(context.Background())
	// note that the call above can generate an error if the repository does not exist yet, so we can proceed

	tagsToUpdate := ociTagsToUpdate(pt.Version(), existingTags)

	tmpDir, err := os.MkdirTemp("", "falco-artifacts-to-upload")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tgzFile := filepath.Join(tmpDir, filepath.Base(rulesfileInfo.Path)+".tar.gz")
	if err = tarGzSingleFile(tgzFile, rulesfileInfo.Path); err != nil {
		return nil, fmt.Errorf("could not compress %s: %w", rulesfileInfo.Path, err)
	}
	defer os.RemoveAll(tgzFile)

	config, err := rulesfileConfig(rulesfileInfo.Name, pt.Version(), rulesfileInfo.Path)
	if err != nil {
		return nil, fmt.Errorf("could not generate configuration layer for rulesfiles %q: %w", rulesfileInfo.Path, err)
	}

	digest, err := pushCompressedRulesfile(client, tgzFile, ociRepoRef, repoGit, tagsToUpdate, config)
	if err != nil {
		return nil, fmt.Errorf("could not push %s to %s with source %s and tags %v: %w", tgzFile, ociRepoRef, repoGit, tagsToUpdate, err)
	}

	// ociRepoDigest is a string that looks like ghcr.io/falcosecurity/rules/falco-rules@sha256:123456...
	ociRepoDigest := fmt.Sprintf("%s@%s", ociRepoRef, *digest)

	return &ociRepoDigest, nil
}

func rulesOciRepos(registryEntries *Registry, ociRepoPrefix string) (map[string]string, error) {
	var repo *repository.Repository
	var err error
	ociClient := authn.NewClient(authn.WithCredentials(&auth.EmptyCredential))
	ociEntries := make(map[string]string)

	for _, entry := range registryEntries.Rulesfiles {
		ref := ociRepoPrefix + "/" + entry.Name
		if repo, err = repository.NewRepository(ref, repository.WithClient(ociClient)); err != nil {
			return nil, fmt.Errorf("unable to create repository for ref %q: %w", ref, err)
		}

		_, _, err = repo.FetchReference(context.Background(), ref+":latest")
		if err != nil && (errors.Is(err, errdef.ErrNotFound) || strings.Contains(err.Error(), "requested access to the resource is denied")) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("unable to fetch reference for %q: %w", ref+":latest", err)
		}

		ociEntries[entry.Name] = ref
	}

	return ociEntries, nil
}

func doUpdateIndex(registryFile, indexFile string) error {
	var ociPrefix string
	var found bool

	if ociPrefix, found = os.LookupEnv(OCIRepoPrefixEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", OCIRepoPrefixEnv)
	}

	registryEntries, err := loadRegistryFromFile(registryFile)
	if err != nil {
		return err
	}
	ociEntries, err := rulesOciRepos(registryEntries, ociPrefix)
	if err != nil {
		return err
	}
	if err := registryEntries.Validate(); err != nil {
		return err
	}

	return upsertIndexFile(registryEntries, ociEntries, indexFile)
}

func main() {
	checkCmd := &cobra.Command{
		Use:                   "check <filename>",
		Short:                 "Verify the correctness of a registry YAML file",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doCheck(args[0])
		},
	}

	updateIndexCmd := &cobra.Command{
		Use:                   "update-index <registryFilename> <indexFilename>",
		Short:                 "Update an index file for artifacts distribution using registry data",
		Args:                  cobra.ExactArgs(2),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doUpdateIndex(args[0], args[1])
		},
	}

	pushToOCI := &cobra.Command{
		Use:                   "push-to-oci <registryFilename> <gitTag>",
		Short:                 "Push the rulesfile identified by the tag to the OCI repo identified by the env variable OCI_REPO_PREFIX, authenticating via REGISTRY_USER/REGISTRY_TOKEN and linking to the sources via GITHUB_REPO_URL",
		Args:                  cobra.ExactArgs(2),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			ociRepoDigest, err := doPushToOCI(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Println(*ociRepoDigest)

			return nil
		},
	}

	uploadToS3 := &cobra.Command{
		Use:                   "upload-to-s3 <registryFilename> <gitTag>",
		Short:                 "Upload the rulesfile identified by the tag to the S3 bucket S3_BUCKET with prefix S3_PREFIX",
		Args:                  cobra.ExactArgs(2),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doUploadToS3(args[0], args[1])
		},
	}

	rootCmd := &cobra.Command{
		Use:     "rules-registry",
		Version: "0.1.0",
	}
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(updateIndexCmd)
	rootCmd.AddCommand(pushToOCI)
	rootCmd.AddCommand(uploadToS3)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
