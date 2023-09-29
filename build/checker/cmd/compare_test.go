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
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/stretchr/testify/assert"
)

const sampleFalcoCompareOutput = `{
	"lists": [
		{
			"details": {
				"lists": []
			},
			"info": {
				"items": ["ash", "bash"],
				"name": "list1"
			}
		}
	],
	"macros": [
		{
			"details": {
				"condition_fields": ["fd.num","evt.type"],
				"events": ["openat2","openat","open"],
				"lists": [],
				"macros": [],
				"operators": [">=","=","in"]
			},
			"info": {
				"name": "macro1"
			}
		}
	],
	"required_engine_version": "13",
	"required_plugin_versions": [
		{
			"alternatives": [
				{
					"name": "k8saudit-eks",
					"version": "0.2.0"
				}
			],
			"name": "k8saudit",
			"version": "0.6.0"
		},
		{
			"name": "json",
			"version": "0.7.0"
		}
	],
	"rules": [
		{
			"details": {
				"condition_fields": [],
				"events": ["execve", "openat"],
				"exceptions" : [],
				"exception_fields": [],
				"exception_operators": [],
			"lists": [],
				"macros": [],
				"operators": [],
				"output_fields": ["user.name","container.id"]
			},
			"info": {
				"enabled": false,
				"name": "rule1",
				"priority": "Notice",
				"source": "syscall",
				"tags": ["container","network"]
			}
		}
	]
  }`

func testGetSampleFalcoCompareOutput(t *testing.T) *falco.RulesetDescription {
	var out falco.RulesetDescription
	err := json.Unmarshal(([]byte)(sampleFalcoCompareOutput), &out)
	if err != nil {
		t.Fatal(err.Error())
	}
	return &out
}

func TestCompareRulesPatch(t *testing.T) {
	t.Parallel()

	t.Run("decrement-required-engine-version", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.RequiredEngineVersion = "0"
		res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-plugin-version-requirement", func(t *testing.T) {
		t.Parallel()
		t.Run("with-alternatives", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.RequiredPluginVersions = o2.RequiredPluginVersions[1:]
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 2)
		})
		t.Run("with-no-alternatives", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.RequiredPluginVersions = o2.RequiredPluginVersions[:1]
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
	})

	t.Run("add-plugin-version-requirement-alternative", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		a := falco.PluginVersionRequirement{Name: "json2", Version: "0.1.0"}
		o2.RequiredPluginVersions[1].Alternatives = append(o2.RequiredPluginVersions[1].Alternatives, a)
		res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("change-list", func(t *testing.T) {
		t.Parallel()
		t.Run("add-item", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Lists[0].Info.Items = append(o2.Lists[0].Info.Items, "some_value")
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("remove-item", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Lists[0].Info.Items = []string{}
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
	})

	t.Run("change-rule", func(t *testing.T) {
		t.Parallel()
		t.Run("enable", func(t *testing.T) {
			t.Parallel()
			o1 := testGetSampleFalcoCompareOutput(t)
			o2 := testGetSampleFalcoCompareOutput(t)
			o1.Rules[0].Info.Enabled = false
			o2.Rules[0].Info.Enabled = true
			res := compareRulesPatch(o1, o2)
			assert.Len(t, res, 1)
		})
		t.Run("add-events", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Details.Events = append(o2.Rules[0].Details.Events, "pluginevent")
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("add-tags", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Info.Tags = append(o2.Rules[0].Info.Tags, "some_other_tag")
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("remove-output-field", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Details.OutputFields = []string{}
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("add-output-field", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Details.OutputFields = append(o2.Rules[0].Details.OutputFields, "some.otherfield")
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("greater-priority", func(t *testing.T) {
			t.Parallel()
			o1 := testGetSampleFalcoCompareOutput(t)
			o2 := testGetSampleFalcoCompareOutput(t)
			o1.Rules[0].Info.Priority = "DEBUG"
			o2.Rules[0].Info.Priority = "INFO"
			res := compareRulesPatch(o1, o2)
			assert.Len(t, res, 1)
		})
		t.Run("add-exceptions", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Details.ExceptionNames = append(o2.Rules[0].Details.ExceptionNames, "some-exception-name")
			res := compareRulesPatch(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("remove-exceptions", func(t *testing.T) {
			t.Parallel()
			o1 := testGetSampleFalcoCompareOutput(t)
			o2 := testGetSampleFalcoCompareOutput(t)
			o1.Rules[0].Details.ExceptionNames = append(o1.Rules[0].Details.ExceptionNames, "exception1, exception2")
			o2.Rules[0].Details.ExceptionNames = append(o2.Rules[0].Details.ExceptionNames, "exception1")
			res := compareRulesPatch(o1, o2)
			assert.Len(t, res, 1)
		})
	})
}

func TestCompareRulesMinor(t *testing.T) {
	t.Parallel()

	t.Run("increment-required-engine-version", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.RequiredEngineVersion = "100"
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-plugin-version-requirement", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		dep := falco.PluginVersionRequirementDescription{
			PluginVersionRequirement: falco.PluginVersionRequirement{Name: "some_other_plugin", Version: "0.1.0"},
		}
		o2.RequiredPluginVersions = append(o2.RequiredPluginVersions, dep)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("increment-plugin-version-requirement", func(t *testing.T) {
		t.Parallel()
		t.Run("of alternative", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.RequiredPluginVersions[0].Alternatives[0].Version = "10.0.0"
			res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("of main requirement", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.RequiredPluginVersions[1].Version = "10.0.0"
			res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
	})

	t.Run("add-list", func(t *testing.T) {
		t.Parallel()
		l := falco.ListDescription{}
		l.Info.Name = "l2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = append(o2.Lists, l)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-macro", func(t *testing.T) {
		t.Parallel()
		l := falco.MacroDescription{}
		l.Info.Name = "m2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Macros = append(o2.Macros, l)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-rule", func(t *testing.T) {
		t.Parallel()
		l := falco.RuleDescription{}
		l.Info.Name = "r2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Rules = append(o2.Rules, l)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-all", func(t *testing.T) {
		t.Parallel()
		l := falco.ListDescription{}
		l.Info.Name = "l2"
		m := falco.MacroDescription{}
		m.Info.Name = "m2"
		r := falco.RuleDescription{}
		r.Info.Name = "r2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = append(o2.Lists, l)
		o2.Macros = append(o2.Macros, m)
		o2.Rules = append(o2.Rules, r)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 3)
	})
}

func TestCompareRulesMajor(t *testing.T) {
	t.Parallel()

	t.Run("remove-plugin-version-requirement", func(t *testing.T) {
		t.Parallel()
		t.Run("with-alternatives", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.RequiredPluginVersions[0].Alternatives = []falco.PluginVersionRequirement{}
			res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
	})

	t.Run("remove-list", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = []falco.ListDescription{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-macro", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Macros = []falco.MacroDescription{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-rule", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Rules = []falco.RuleDescription{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-all", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = []falco.ListDescription{}
		o2.Macros = []falco.MacroDescription{}
		o2.Rules = []falco.RuleDescription{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 3)
	})

	t.Run("change-macro", func(t *testing.T) {
		t.Parallel()
		t.Run("add-events", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Macros[0].Details.Events = append(o2.Macros[0].Details.Events, "pluginevent")
			res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("remove-events", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Macros[0].Details.Events = []string{}
			res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
	})

	t.Run("change-rule", func(t *testing.T) {
		t.Parallel()
		t.Run("change-source", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Info.Source = "some_other_source"
			res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("disable", func(t *testing.T) {
			t.Parallel()
			o1 := testGetSampleFalcoCompareOutput(t)
			o2 := testGetSampleFalcoCompareOutput(t)
			o1.Rules[0].Info.Enabled = true
			o2.Rules[0].Info.Enabled = false
			res := compareRulesMajor(o1, o2)
			assert.Len(t, res, 1)
		})
		t.Run("remove-events", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Details.Events = []string{}
			res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("remove-tags", func(t *testing.T) {
			t.Parallel()
			o2 := testGetSampleFalcoCompareOutput(t)
			o2.Rules[0].Info.Tags = []string{}
			res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
			assert.Len(t, res, 1)
		})
		t.Run("lower-priority", func(t *testing.T) {
			t.Parallel()
			o1 := testGetSampleFalcoCompareOutput(t)
			o2 := testGetSampleFalcoCompareOutput(t)
			o1.Rules[0].Info.Priority = "INFO"
			o2.Rules[0].Info.Priority = "DEBUG"
			res := compareRulesMajor(o1, o2)
			assert.Len(t, res, 1)
		})
	})
}
