import re
from pathlib import Path
from typing import Dict

from falco_mitre_attack_checker.exceptions.rules_exceptions import FalcoRulesFileContentError
from falco_mitre_attack_checker.models.falco_mitre_relations import MitreRelations
from falco_mitre_attack_checker.utils.file import read_yaml


class FalcoRulesParser(object):
    """
    A Deserialization class for Falco rules file in order to define parsing methods
    """
    VALIDATION_KEY = "required_engine_version"
    rules: Dict

    def __init__(self, rules_file: Path):
        self.path = rules_file
        self.rules = read_yaml(rules_file)
        self.validate()

    def validate(self):
        """
        Simple function to check if the submitted file contains some requirements that Falco rules files
        should have.
        """
        error = FalcoRulesFileContentError(self.path,
                                           message=f"Missing 'required_engine_version' conf in "
                                                   f"{self.path}, so wrong falco rules file format or "
                                                   f"not a rules file.")
        try:
            if not [items for items in self.rules if self.VALIDATION_KEY in items.keys()]:
                raise error
        except AttributeError:
            raise error

    def get_mitre_relations(self) -> "MitreRelations":
        """
        Build a relation model between techniques and mitre phases described in the falco rules
        :return: the list of the relations
        """
        # filter for rules with extra tags
        filtered_rules = [rule for rule in self.rules if "tags" in rule.keys()]
        relations = MitreRelations()
        for rule in filtered_rules:
            rule_desc: str = rule['rule']
            formatted_tags = [str(tag).upper() for tag in rule['tags']]
            tactics = [tag.lower() for tag in formatted_tags if "MITRE_" in tag]
            techniques = [tag for tag in formatted_tags if re.search("^TA?(\\d+).(\\d+)", tag)]
            relations.add_techniques_and_tactics(rule_desc, techniques, tactics)

        return relations
