package cmd

import (
	"encoding/json"
	"testing"

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
	"rules": [
		{
			"details": {
				"condition_fields": [],
				"events": ["execve", "openat"],
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

func testGetSampleFalcoCompareOutput(t *testing.T) *falcoCompareOutput {
	var out falcoCompareOutput
	err := json.Unmarshal(([]byte)(sampleFalcoCompareOutput), &out)
	if err != nil {
		t.Fatal(err.Error())
	}
	return &out
}

func TestCompareRulesPatch(t *testing.T) {
	t.Parallel()
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
	})
}

func TestCompareRulesMinor(t *testing.T) {
	t.Parallel()
	t.Run("add-list", func(t *testing.T) {
		t.Parallel()
		l := falcoListOutput{}
		l.Info.Name = "l2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = append(o2.Lists, l)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-macro", func(t *testing.T) {
		t.Parallel()
		l := falcoMacroOutput{}
		l.Info.Name = "m2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Macros = append(o2.Macros, l)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-rule", func(t *testing.T) {
		t.Parallel()
		l := falcoRuleOutput{}
		l.Info.Name = "r2"
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Rules = append(o2.Rules, l)
		res := compareRulesMinor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("add-all", func(t *testing.T) {
		t.Parallel()
		l := falcoListOutput{}
		l.Info.Name = "l2"
		m := falcoMacroOutput{}
		m.Info.Name = "m2"
		r := falcoRuleOutput{}
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
	t.Run("remove-list", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = []falcoListOutput{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-macro", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Macros = []falcoMacroOutput{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-rule", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Rules = []falcoRuleOutput{}
		res := compareRulesMajor(testGetSampleFalcoCompareOutput(t), o2)
		assert.Len(t, res, 1)
	})

	t.Run("remove-all", func(t *testing.T) {
		t.Parallel()
		o2 := testGetSampleFalcoCompareOutput(t)
		o2.Lists = []falcoListOutput{}
		o2.Macros = []falcoMacroOutput{}
		o2.Rules = []falcoRuleOutput{}
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
