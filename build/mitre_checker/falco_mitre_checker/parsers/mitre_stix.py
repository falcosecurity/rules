import logging
from typing import Dict, List

import requests
from stix2 import MemoryStore, Filter, AttackPattern

from falco_mitre_checker.utils.logger import MitreCheckerLogger

logger = logging.getLogger(MitreCheckerLogger.name)


class MitreParser(object):
    """
    A Deserialization class for Mitre ATT&CK STIX2 data from Mitre CTI in order to define parsing methods
    """
    # src is the source data directly fetched from STIX2 CTI bundle
    src: MemoryStore

    def __init__(self, mitre_domain: str, mitre_domain_version: str):
        """
        Init the Mitre parser by loading Mitre's STIX data from source.
        https://github.com/mitre/cti/blob/master/USAGE.md
        :param mitre_domain: either 'enterprise-attack', 'mobile-attack', or 'ics-attack'
        :param mitre_domain_version: version of the mitre domain in format 'XX.XX'
        """
        self.mitre_domain = mitre_domain
        self.mitre_domain_version = mitre_domain_version
        stix_json = requests.get(
            f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{mitre_domain_version}/{mitre_domain}/{mitre_domain}.json").json()
        self.src = MemoryStore(stix_data=stix_json["objects"])

    def get_tactic_or_technique_by_id(self, external_id: str) -> "AttackPattern | None":
        """
        Query Mitre CTI's STIX data to search a STIX technique definition by its ID
        :param external_id: ID of the MITRE ATT&CK technique
        :return: the technique definition in STIX2 data format
        """
        # by default, a List is returned for STIX2 refs, but we expect only one technique per ID
        try:
            technique = self.src.query([
                Filter('external_references.external_id', '=', external_id),
                Filter('type', 'in', ['x-mitre-tactic', 'attack-pattern']),
            ])[0]
            # Some techniques do not contain the 'x_mitre_deprecated' field
            # So it is not exploitable with a filter, but we can do it by ourselves
            if 'x_mitre_technique' in technique:
                # return None if deprecated
                return technique if not technique.x_mitre_deprecated else None
            # considering technique is valid if no 'deprecation' field is defined
            return technique
        except IndexError:
            logger.warning(f"Technique {external_id} doesn't exist for '{self.mitre_domain}' "
                           f"v{self.mitre_domain_version}")
            return None

    @classmethod
    def get_tactics_names(cls, ttp: AttackPattern) -> "List[str]":
        """
        Get the mitre phase name (tactic) of a given technique or tactic.
        If it is a tactic, only return the tactic name.
        :param ttp: The MITRE ATT&CK data of a technique of a tactic
        :return: The mitre phase names of the given technique or tactic
        """
        return [tactic["phase_name"] for tactic in
                ttp["kill_chain_phases"]] if "kill_chain_phases" in ttp else [ttp["x_mitre_shortname"]]

    @classmethod
    def get_mitre_name(cls, ttp: AttackPattern) -> str:
        return ttp['name']

    @classmethod
    def get_technique_external_reference(cls, ttp: AttackPattern) -> "Dict[str, str]":
        return [reference for reference in ttp['external_references']
                if reference['source_name'] == "mitre-attack"][0]
