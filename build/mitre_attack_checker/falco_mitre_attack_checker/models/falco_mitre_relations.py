from typing import List, Dict

from pydantic import BaseModel


class MitreRelation(BaseModel):
    """
    Simple relation between Mitre techniques or sub-techniques and the attached mitre phases
    """
    techniques: List[str]
    tactics: List[str]


class MitreRelations(BaseModel):
    """
    This class builds a relation between a Falco rule and the extra tags it uses for Mitre ATT&CK
    """
    rules: Dict[str, MitreRelation] = {}

    def __len__(self):
        return len(self.rules)

    def add_techniques_and_tactics(self, rule_name: str, techniques_ids: List[str],
                                   tactics_names: List[str]):
        if rule_name in self.rules.keys():
            self.rules[rule_name].techniques += techniques_ids
            self.rules[rule_name].tactics += tactics_names
        else:
            self.rules[rule_name] = MitreRelation(techniques=techniques_ids, tactics=tactics_names)
