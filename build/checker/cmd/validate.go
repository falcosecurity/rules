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
	"fmt"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/pkg/run"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate one or more rules file with a given Falco version",
	RunE: func(cmd *cobra.Command, args []string) error {
		falcoImage, err := cmd.Flags().GetString("falco-image")
		if err != nil {
			return err
		}

		rulesFilesPaths, err := cmd.Flags().GetStringArray("rule")
		if err != nil {
			return err
		}

		if len(rulesFilesPaths) == 0 {
			return fmt.Errorf("you must specify at least one rules file")
		}

		var ruleFiles []run.FileAccessor
		for _, rf := range rulesFilesPaths {
			f := run.NewLocalFileAccessor(rf, rf)
			ruleFiles = append(ruleFiles, f)
		}

		falcoTestOptions := []falco.TestOption{
			falco.WithOutputJSON(),
			falco.WithRulesValidation(ruleFiles...),
		}

		falcoConfigPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}
		if len(falcoConfigPath) > 0 {
			config := run.NewLocalFileAccessor(falcoConfigPath, falcoConfigPath)
			falcoTestOptions = append(falcoTestOptions, falco.WithConfig(config))
		}

		falcoFilesPaths, err := cmd.Flags().GetStringArray("file")
		if err != nil {
			return err
		}
		if len(falcoFilesPaths) > 0 {
			for _, path := range falcoFilesPaths {
				file := run.NewLocalFileAccessor(path, path)
				falcoTestOptions = append(falcoTestOptions, falco.WithExtraFiles(file))
			}
		}

		// run falco and collect/print validation issues
		runner, err := run.NewDockerRunner(falcoImage, defaultFalcoDockerEntrypoint, nil)
		if err != nil {
			return err
		}

		res := falco.Test(runner, falcoTestOptions...)
		if res.RuleValidation() == nil {
			err = errAppend(err, fmt.Errorf("rules validation command failed"))
		} else {
			for _, r := range res.RuleValidation().Results {
				if !r.Successful || len(r.Errors) > 0 || len(r.Warnings) > 0 {
					err = errAppend(err, fmt.Errorf("rules validation had warning or errors"))
					fmt.Fprintln(cmd.OutOrStdout(), res.Stdout())
					break
				}
			}
		}

		// collect errors
		err = errAppend(err, res.Err())
		if res.ExitCode() != 0 {
			err = errAppend(err, fmt.Errorf("unexpected exit code (%d)", res.ExitCode()))
		}
		if err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), res.Stderr())
		}
		return err
	},
}

func init() {
	validateCmd.Flags().StringP("falco-image", "i", defaultFalcoDockerImage, "Docker image of Falco to be used for validation")
	validateCmd.Flags().StringP("config", "c", "", "Config file to be used for running Falco")
	validateCmd.Flags().StringArrayP("file", "f", []string{}, "Extra files required by Falco for running")
	validateCmd.Flags().StringArrayP("rule", "r", []string{}, "Rules files to be validated by Falco")
	rootCmd.AddCommand(validateCmd)
}
