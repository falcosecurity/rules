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
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/blang/semver"
	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/pkg/run"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// todo(jasondellaluce,loresuso): move this definitions and their deserialization
// logic in falcosecurity/testing, and check for duplicates in falcoctl

type falcoListOutput struct {
	Details struct {
		Lists []string `json:"lists"`
	} `json:"details"`
	Info struct {
		Items []string `json:"items"`
		Name  string   `json:"name"`
	} `json:"info"`
}

type falcoMacroOutput struct {
	Details struct {
		ConditionFields []string `json:"condition_fields"`
		Events          []string `json:"events"`
		Lists           []string `json:"lists"`
		Macros          []string `json:"macros"`
		Operators       []string `json:"operators"`
	} `json:"details"`
	Info struct {
		Condition string `json:"condition"`
		Name      string `json:"name"`
	} `json:"info"`
}

type falcoRuleOutput struct {
	Details struct {
		ConditionFields    []string `json:"condition_fields"`
		Events             []string `json:"events"`
		ExceptionFields    []string `json:"exception_fields"`
		ExceptionOperators []string `json:"exception_operators"`
		Exceptions         []string `json:"exceptions"`
		Lists              []string `json:"lists"`
		Macros             []string `json:"macros"`
		Operators          []string `json:"operators"`
		OutputFields       []string `json:"output_fields"`
	} `json:"details"`
	Info struct {
		Condition   string   `json:"condition"`
		Description string   `json:"description"`
		Enabled     bool     `json:"enabled"`
		Name        string   `json:"name"`
		Output      string   `json:"output"`
		Priority    string   `json:"priority"`
		Source      string   `json:"source"`
		Tags        []string `json:"tags"`
	} `json:"info"`
}

type falcoPluginVerReq struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type falcoPluginVerReqOutput struct {
	falcoPluginVerReq
	Alternatives []falcoPluginVerReq `json:"alternatives"`
}

func (f *falcoPluginVerReqOutput) GetVerRequirement(pluginName string) *falcoPluginVerReq {
	if f.Name == pluginName {
		return &f.falcoPluginVerReq
	}
	for _, a := range f.Alternatives {
		if a.Name == pluginName {
			return &a
		}
	}
	return nil
}

func (f *falcoPluginVerReqOutput) GetRequirements() []*falcoPluginVerReq {
	var res []*falcoPluginVerReq
	res = append(res, &f.falcoPluginVerReq)
	for _, a := range f.Alternatives {
		res = append(res, &a)
	}
	return res
}

type falcoCompareOutput struct {
	RequiredEngineVersion  string                    `json:"required_engine_version"`
	RequiredPluginVersions []falcoPluginVerReqOutput `json:"required_plugin_versions"`
	Lists                  []falcoListOutput         `json:"lists"`
	Macros                 []falcoMacroOutput        `json:"macros"`
	Rules                  []falcoRuleOutput         `json:"rules"`
}

func (f *falcoCompareOutput) FindPluginVerRequirement(pluginName string) *falcoPluginVerReqOutput {
	for _, r := range f.RequiredPluginVersions {
		req := r.GetVerRequirement(pluginName)
		if req != nil {
			return &r
		}
	}
	return nil
}

func (f *falcoCompareOutput) ListNames() []string {
	var names []string
	for _, l := range f.Lists {
		names = append(names, l.Info.Name)
	}
	return names
}

func (f *falcoCompareOutput) MacroNames() []string {
	var names []string
	for _, l := range f.Macros {
		names = append(names, l.Info.Name)
	}
	return names
}

func (f *falcoCompareOutput) RuleNames() []string {
	var names []string
	for _, l := range f.Rules {
		names = append(names, l.Info.Name)
	}
	return names
}

func getCompareOutput(falcoImage, configFile string, ruleFiles, extraFiles []string) (*falcoCompareOutput, error) {
	testOptions := []falco.TestOption{
		falco.WithOutputJSON(),
		falco.WithOutputJSON(),
		falco.WithArgs("-L"),
	}

	for _, rf := range ruleFiles {
		f := run.NewLocalFileAccessor(rf, rf)
		testOptions = append(testOptions, falco.WithRules(f))
	}

	if len(configFile) > 0 {
		f := run.NewLocalFileAccessor(configFile, configFile)
		testOptions = append(testOptions, falco.WithConfig(f))
	}

	for _, ef := range extraFiles {
		f := run.NewLocalFileAccessor(ef, ef)
		testOptions = append(testOptions, falco.WithExtraFiles(f))
	}

	// run falco and collect/print validation issues
	runner, err := run.NewDockerRunner(falcoImage, defaultFalcoDockerEntrypoint, nil)
	if err != nil {
		return nil, err
	}

	res := falco.Test(runner, testOptions...)

	// collect errors
	err = errAppend(err, res.Err())
	if res.ExitCode() != 0 {
		err = errAppend(err, fmt.Errorf("unexpected exit code (%d)", res.ExitCode()))
	}

	// unmarshal json output
	var out falcoCompareOutput
	err = json.Unmarshal(([]byte)(res.Stdout()), &out)
	if err != nil {
		logrus.Info(res.Stderr())
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	return &out, nil
}

func compareRulesPatch(left, right *falcoCompareOutput) (res []string) {
	// Decrementing required_engine_version
	lRequiredEngineVersion, _ := strconv.Atoi(left.RequiredEngineVersion)
	rRequiredEngineVersion, _ := strconv.Atoi(right.RequiredEngineVersion)
	if compareInt(lRequiredEngineVersion, rRequiredEngineVersion) > 0 {
		res = append(res, fmt.Sprintf("Required engine version was decremented from %s to %s",
			left.RequiredEngineVersion, right.RequiredEngineVersion))
	}

	// Remove or decrement plugin version requirement
	for _, lpr := range left.RequiredPluginVersions {
		var tmpRemoveRes []string
		lpReqs := lpr.GetRequirements()
		for _, lr := range lpReqs {
			rr := right.FindPluginVerRequirement(lr.Name)
			if rr == nil {
				// removed dep (not an alternative)
				tmpRemoveRes = append(tmpRemoveRes, fmt.Sprintf("Version dependency to plugin `%s` has removed", lr.Name))
			} else {
				// decremented
				lv := semver.MustParse(lr.Version)
				rv := semver.MustParse(rr.GetVerRequirement(lr.Name).Version)
				if lv.Compare(rv) > 0 {
					res = append(res, fmt.Sprintf("Version dependency to plugin `%s` has been decremented", lr.Name))
				}
			}
		}
		if len(tmpRemoveRes) == len(lpReqs) {
			res = append(res, tmpRemoveRes...)
		}
	}

	// Adding plugin version requirement alternative
	for _, rpr := range right.RequiredPluginVersions {
		var lrl *falcoPluginVerReqOutput
		rReqs := rpr.GetRequirements()
		for _, rreq := range rReqs {
			lrl = left.FindPluginVerRequirement(rreq.Name)
			if lrl != nil {
				break
			}
		}
		if lrl != nil {
			for _, rreq := range rReqs {
				if lrl.GetVerRequirement(rreq.Name) == nil {
					res = append(res, fmt.Sprintf("Version dependency alternative to plugin `%s` has added", rreq.Name))
				}
			}
		}
	}

	for _, l := range left.Rules {
		for _, r := range right.Rules {
			if l.Info.Name == r.Info.Name {
				// Enabling at default one or more rules that used to be disabled
				if !l.Info.Enabled && r.Info.Enabled {
					res = append(res, fmt.Sprintf("Rule `%s` has been enabled at default", l.Info.Name))
				}

				// Matching more events in a rule condition
				if len(diffStrSet(r.Details.Events, l.Details.Events)) > 0 {
					res = append(res, fmt.Sprintf("Rule `%s` matches more events than before", l.Info.Name))
				}

				// A rule has different output fields
				if compareInt(len(l.Details.OutputFields), len(r.Details.OutputFields)) != 0 {
					res = append(res, fmt.Sprintf("Rule `%s` changed its output fields", l.Info.Name))
				}

				// A rule has more tags than before
				if len(diffStrSet(r.Info.Tags, l.Info.Tags)) > 0 {
					res = append(res, fmt.Sprintf("Rule `%s` has more tags than before", l.Info.Name))
				}

				// A rule's priority becomes more urgent than before
				if compareFalcoPriorities(r.Info.Priority, l.Info.Priority) > 0 {
					res = append(res, fmt.Sprintf("Rule `%s` has a more urgent priority than before", l.Info.Name))
				}

				// Adding or removing exceptions for one or more Falco rules
				if len(diffStrSet(l.Details.Exceptions, r.Details.Exceptions)) != 0 ||
					len(diffStrSet(r.Details.Exceptions, l.Details.Exceptions)) != 0 {
					res = append(res, fmt.Sprintf("Rule '%s' has some exceptions added or removed", l.Info.Name))
				}

			}
		}
	}

	for _, l := range left.Lists {
		for _, r := range right.Lists {
			if l.Info.Name == r.Info.Name {
				// Adding or removing items for one or more lists
				if len(diffStrSet(l.Info.Items, r.Info.Items)) != 0 ||
					len(diffStrSet(r.Info.Items, l.Info.Items)) != 0 {
					res = append(res, fmt.Sprintf("List `%s` has some item added or removed", l.Info.Name))
				}
			}
		}
	}

	return
}

func compareRulesMinor(left, right *falcoCompareOutput) (res []string) {
	// Incrementing the required_engine_version number
	l_required_engine_version, _ := strconv.Atoi(left.RequiredEngineVersion)
	r_required_engine_version, _ := strconv.Atoi(right.RequiredEngineVersion)
	if compareInt(l_required_engine_version, r_required_engine_version) < 0 {
		res = append(res, fmt.Sprintf("Required engine version was incremented from %s to %s",
			left.RequiredEngineVersion, right.RequiredEngineVersion))
	}

	// Adding a new plugin version requirement in required_plugin_versions
	for _, rpr := range right.RequiredPluginVersions {
		var lrl *falcoPluginVerReqOutput
		rReqs := rpr.GetRequirements()
		for _, rreq := range rReqs {
			lrl = left.FindPluginVerRequirement(rreq.Name)
			if lrl != nil {
				break
			}
		}
		if lrl == nil {
			res = append(res, fmt.Sprintf("Version dependency to plugin `%s` has added", rpr.Name))
		}
	}

	// Incrementing the version requirement for one or more plugin
	for _, lpr := range left.RequiredPluginVersions {
		lpReqs := lpr.GetRequirements()
		for _, lr := range lpReqs {
			rr := right.FindPluginVerRequirement(lr.Name)
			if rr != nil {
				lv := semver.MustParse(lr.Version)
				rv := semver.MustParse(rr.GetVerRequirement(lr.Name).Version)
				if lv.Compare(rv) < 0 {
					res = append(res, fmt.Sprintf("Version dependency to plugin `%s` has been incremented", lr.Name))
				}
			}
		}
	}

	// Adding one or more lists, macros, or rules
	diff := diffStrSet(right.RuleNames(), left.RuleNames())
	if len(diff) > 0 {
		for v := range diff {
			res = append(res, fmt.Sprintf("Rule `%s` has been added", v))
		}
	}
	diff = diffStrSet(right.MacroNames(), left.MacroNames())
	if len(diff) > 0 {
		for v := range diff {
			res = append(res, fmt.Sprintf("Macro `%s` has been added", v))
		}
	}
	diff = diffStrSet(right.ListNames(), left.ListNames())
	if len(diff) > 0 {
		for v := range diff {
			res = append(res, fmt.Sprintf("List `%s` has been added", v))
		}
	}

	return
}

func compareRulesMajor(left, right *falcoCompareOutput) (res []string) {
	// Remove plugin version requirement alternative
	for _, lpr := range left.RequiredPluginVersions {
		var tmpRes []string
		lpReqs := lpr.GetRequirements()
		for _, lr := range lpReqs {
			rr := right.FindPluginVerRequirement(lr.Name)
			if rr == nil && len(lpr.Alternatives) > 0 {
				// removed dep (an alternative)
				tmpRes = append(tmpRes, fmt.Sprintf("Version dependency alternative to plugin `%s` has removed", lr.Name))
			}
		}
		// it's not a breaking change to remove a whole plugin dependency block
		if len(tmpRes) < len(lpReqs) {
			res = append(res, tmpRes...)
		}
	}

	// Renaming or removing a list, macro, or rule
	diff := diffStrSet(left.RuleNames(), right.RuleNames())
	if len(diff) > 0 {
		for v := range diff {
			res = append(res, fmt.Sprintf("Rule `%s` has been removed", v))
		}
	}
	diff = diffStrSet(left.MacroNames(), right.MacroNames())
	if len(diff) > 0 {
		for v := range diff {
			res = append(res, fmt.Sprintf("Macro `%s` has been removed", v))
		}
	}
	diff = diffStrSet(left.ListNames(), right.ListNames())
	if len(diff) > 0 {
		for v := range diff {
			res = append(res, fmt.Sprintf("List `%s` has been removed", v))
		}
	}

	for _, l := range left.Rules {
		for _, r := range right.Rules {
			if l.Info.Name == r.Info.Name {
				// Rule has a different source
				if l.Info.Source != r.Info.Source {
					res = append(res, fmt.Sprintf("Rule `%s` has different source (before='%s', after='%s')", l.Info.Name, l.Info.Source, r.Info.Source))
				}

				// Disabling at default one or more rules that used to be enabled
				if l.Info.Enabled && !r.Info.Enabled {
					res = append(res, fmt.Sprintf("Rule `%s` has been disabled at default", l.Info.Name))
				}

				// Matching less events in a rule condition
				if len(diffStrSet(l.Details.Events, r.Details.Events)) > 0 {
					res = append(res, fmt.Sprintf("Rule `%s` matches less events than before", l.Info.Name))
				}

				// A rule has less tags than before
				if len(diffStrSet(l.Info.Tags, r.Info.Tags)) > 0 {
					res = append(res, fmt.Sprintf("Rule `%s` has less tags than before", l.Info.Name))
				}

				// a priority becomes less urgent than before
				if compareFalcoPriorities(l.Info.Priority, r.Info.Priority) > 0 {
					res = append(res, fmt.Sprintf("Rule `%s` has a less urgent priority than before", l.Info.Name))
				}
			}
		}
	}

	for _, l := range left.Macros {
		for _, r := range right.Macros {
			if l.Info.Name == r.Info.Name {
				// Matching different events in a macro condition
				if len(diffStrSet(l.Details.Events, r.Details.Events)) > 0 ||
					len(diffStrSet(r.Details.Events, l.Details.Events)) > 0 {
					res = append(res, fmt.Sprintf("Macro `%s` matches different events than before", l.Info.Name))
				}
			}
		}
	}
	return
}

var compareCmd = &cobra.Command{
	Use: "compare",
	// todo: load more than one rules files both on left and right
	Short: "Compare two rules files and suggest version changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		leftRules, err := cmd.Flags().GetStringArray("left")
		if err != nil {
			return err
		}

		rightRules, err := cmd.Flags().GetStringArray("right")
		if err != nil {
			return err
		}

		if len(leftRules) == 0 || len(rightRules) == 0 {
			return fmt.Errorf("you must specify at least one rules file for both the left-hand and right-hand sides of comparison")
		}

		falcoImage, err := cmd.Flags().GetString("falco-image")
		if err != nil {
			return err
		}

		falcoConfigPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}

		falcoFilesPaths, err := cmd.Flags().GetStringArray("file")
		if err != nil {
			return err
		}

		leftOutput, err := getCompareOutput(falcoImage, falcoConfigPath, leftRules, falcoFilesPaths)
		if err != nil {
			return err
		}

		rightOutput, err := getCompareOutput(falcoImage, falcoConfigPath, rightRules, falcoFilesPaths)
		if err != nil {
			return err
		}

		diff := compareRulesMajor(leftOutput, rightOutput)
		if len(diff) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "**Major** changes:")
			for _, s := range diff {
				fmt.Fprintln(cmd.OutOrStdout(), "* "+s)
			}
			fmt.Fprintln(cmd.OutOrStdout())
		}

		diff = compareRulesMinor(leftOutput, rightOutput)
		if len(diff) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "**Minor** changes:")
			for _, s := range diff {
				fmt.Fprintln(cmd.OutOrStdout(), "* "+s)
			}
			fmt.Fprintln(cmd.OutOrStdout())
		}

		diff = compareRulesPatch(leftOutput, rightOutput)
		if len(diff) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "**Patch** changes:")
			for _, s := range diff {
				fmt.Fprintln(cmd.OutOrStdout(), "* "+s)
			}
			fmt.Fprintln(cmd.OutOrStdout())
		}

		return nil
	},
}

func init() {
	compareCmd.Flags().StringP("falco-image", "i", defaultFalcoDockerImage, "Docker image of Falco to be used for validation")
	compareCmd.Flags().StringP("config", "c", "", "Config file to be used for running Falco")
	compareCmd.Flags().StringArrayP("file", "f", []string{}, "Extra files required by Falco for running")
	compareCmd.Flags().StringArrayP("left", "l", []string{}, "Rules files to be loaded for the left-hand side of the comparison")
	compareCmd.Flags().StringArrayP("right", "r", []string{}, "Rules files to be loaded for the right-hand side of the comparison")
	rootCmd.AddCommand(compareCmd)
}
