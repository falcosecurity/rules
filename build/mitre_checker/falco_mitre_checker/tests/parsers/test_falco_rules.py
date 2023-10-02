import pytest

from falco_mitre_checker.exceptions.rules_exceptions import FalcoRulesFileContentError
from falco_mitre_checker.parsers.falco_rules import FalcoRulesParser
from falco_mitre_checker.tests.test_common import NOT_FALCO_RULES_FILE, FALCO_RULES_FILE

# test falco rules file validation
with pytest.raises(FalcoRulesFileContentError):
    FalcoRulesParser(NOT_FALCO_RULES_FILE)

falco_rules_parser = FalcoRulesParser(FALCO_RULES_FILE)
assert falco_rules_parser.rules


def test_get_mitre_relations():
    relations = falco_rules_parser.get_mitre_relations()
    assert relations
    assert len(relations) == 6

    correct_mitre_rule = relations.rules['correct mitre rule']
    assert correct_mitre_rule.tactics == ['mitre_persistence']
    assert correct_mitre_rule.techniques == ['T1098']

    wrong_mitre_rule = relations.rules['wrong mitre rule']
    assert wrong_mitre_rule.tactics == ['mitre_lateral_movement']
    assert wrong_mitre_rule.techniques == ['T1610']
