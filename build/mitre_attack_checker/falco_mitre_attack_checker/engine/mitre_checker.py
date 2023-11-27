import logging
from pathlib import Path
from typing import List

from falco_mitre_attack_checker.models.falco_mitre_errors import \
    ErrorReason, FalcoMitreError, FalcoRulesErrors
from falco_mitre_attack_checker.models.falco_mitre_relations import MitreRelations
from falco_mitre_attack_checker.parsers.falco_rules import FalcoRulesParser
from falco_mitre_attack_checker.parsers.mitre_stix import MitreParser
from falco_mitre_attack_checker.utils.file import write_file
from falco_mitre_attack_checker.utils.logger import MitreCheckerLogger

logger = logging.getLogger(MitreCheckerLogger.name)


class FalcoMitreChecker(object):

    def __init__(self, mitre_domain: str, mitre_domain_version: str):
        logger.info(f"Load Mitre ATT&CK STIX Data for domain '{mitre_domain}' and version "
                    f"'{mitre_domain_version}'")
        self.mitre_parser = MitreParser(mitre_domain, mitre_domain_version)

    def validate(self, falco_rules_file: Path) -> "List[FalcoMitreError]":
        """
        This function validates the falco rules' extra tags against Mitre ATT&CK STIX Data when they
        contain mitre information.
        This method gets the mitre techniques or sub-techniques IDs and the mitre tactics (mitre phases)
        names in the extra tags of each falco rules.
        If the mitre techniques or sub-techniques IDs in the tags are not related to proper the mitre
        tactics names by comparing them with the mitre data (STIX data from Mitre CTI), this method
        considers that the rule contains an error.
        For example, if the extra tags contain :
        {"tags": ["T1611", "mitre_initial_access"] }
        And the actual mitre domain is 'enterprise-attack' in version '13.1', the tags' rule will be
        considered erroneous since the proper mitre phase for 'T1611' is 'privilege-escalation' in this
        version.
        :param falco_rules_file: A falco rule file to analyse against the Mitre ATT&CK STIX Data
        :return: A list of models containing a description of each error in the falco rules for Mitre
                    ATT&CK
        """
        logger.info(f"Audit Falco rules file '{falco_rules_file}' for Mitre ATT&CK")
        falco_rules_parser = FalcoRulesParser(falco_rules_file)
        falco_mitre_errors: List[FalcoMitreError] = []
        # build the model relation between technique (or sub-technique) ID and the mitre phase configured
        # in each rule
        rules_mitre_relations: MitreRelations = falco_rules_parser.get_mitre_relations()
        for rule_name, rule_mitre_relation in rules_mitre_relations.rules.items():
            rule_tactics = rule_mitre_relation.tactics
            all_mitre_tactics = []
            all_mitre_techniques_names = []
            all_mitre_techniques_urls = []

            # verify each technique tag against mitre data
            for rule_technique_or_tactic in rule_mitre_relation.techniques:
                mitre_technique_or_tactic = self.mitre_parser.get_tactic_or_technique_by_id(
                    rule_technique_or_tactic)
                mitre_tactics_names = self.mitre_parser.get_tactics_names(mitre_technique_or_tactic)
                formatted_mitre_tactics_names = [f"mitre_{tactic.replace('-', '_')}" for tactic in
                                                 mitre_tactics_names]
                # gather all correct mitre tactics & techniques of this rule
                all_mitre_tactics += mitre_tactics_names
                mitre_technique_name = self.mitre_parser.get_mitre_name(mitre_technique_or_tactic)
                mitre_technique_url = self.mitre_parser.get_technique_external_reference(
                    mitre_technique_or_tactic)['url']
                all_mitre_techniques_names.append(mitre_technique_name)
                all_mitre_techniques_urls.append(mitre_technique_url)
                if not set(formatted_mitre_tactics_names).issubset(set(rule_tactics)):
                    # detect errors
                    # missing tactic tag in rule for this technique
                    falco_error = FalcoMitreError(rule=rule_name,
                                                  techniques_tags=[rule_technique_or_tactic],
                                                  tactics_tags=rule_tactics,
                                                  mitre_techniques_names=[mitre_technique_name],
                                                  mitre_tactics_names=mitre_tactics_names,
                                                  mitre_techniques_urls=[mitre_technique_url],
                                                  reasons=[ErrorReason.MISSING])

                    falco_mitre_errors.append(falco_error)

            # verify tactics
            all_mitre_tactics_set = set(all_mitre_tactics)
            if len(rule_tactics) > len(all_mitre_tactics_set):
                # detect errors when too many tactic tags are included into the rule extra tags
                falco_error = FalcoMitreError(rule=rule_name,
                                              techniques_tags=rule_mitre_relation.techniques,
                                              tactics_tags=rule_tactics,
                                              mitre_techniques_names=list(
                                                  set(all_mitre_techniques_names)),
                                              mitre_tactics_names=list(set(all_mitre_tactics_set)),
                                              mitre_techniques_urls=list(set(all_mitre_techniques_urls)),
                                              reasons=[ErrorReason.OVERDO])
                falco_mitre_errors.append(falco_error)

        return falco_mitre_errors

    def autofix(self, falco_rules_file: Path, falco_mitre_errors: List[FalcoMitreError]):
        """
        Automatically fix Mitre tags in a falco rules file from a provided falco mitre errors report
        :param falco_rules_file: the rules file to fix
        :param falco_mitre_errors: the falco mitre error report for this file
        """
        pass

    @staticmethod
    def dump_errors(falco_mitre_errors: List[FalcoMitreError], output: Path) -> None:
        """
        Write a list of falco mitre errors model to a file
        :param output: output file to dump the errors
        :param falco_mitre_errors: List of falco mitre errors models
        """
        write_file(FalcoRulesErrors(errors=falco_mitre_errors).json(), output)
