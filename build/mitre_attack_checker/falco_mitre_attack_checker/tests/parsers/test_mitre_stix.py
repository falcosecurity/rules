from falco_mitre_attack_checker.parsers.mitre_stix import MitreParser
from falco_mitre_attack_checker.tests.test_common import RESOURCES_DIR, MITRE_VERSION, MITRE_DOMAIN

MITRE_STIX_DATAFILE = f"{RESOURCES_DIR}/mitre_cti_stix_13_1.json"

mitre_parser = MitreParser(MITRE_DOMAIN, MITRE_VERSION)
assert mitre_parser.src


def test_get_tactic_or_technique_by_id():
    # technique
    technique = mitre_parser.get_tactic_or_technique_by_id("T1548.001")
    assert technique
    assert not bool(technique.x_mitre_deprecated)
    assert technique.type == 'attack-pattern'
    assert technique.kill_chain_phases
    kill_chain_names = [chain.kill_chain_name for chain in technique.kill_chain_phases]
    assert 'mitre-attack' in kill_chain_names

    # tactic
    tactic = mitre_parser.get_tactic_or_technique_by_id("TA0001")
    assert tactic
    assert tactic['type'] == "x-mitre-tactic"


def test_get_mitre_name():
    technique = mitre_parser.get_tactic_or_technique_by_id("T1548.001")
    assert mitre_parser.get_mitre_name(technique) == "Setuid and Setgid"


def test_get_technique_external_reference():
    technique = mitre_parser.get_tactic_or_technique_by_id("T1548.001")
    reference = mitre_parser.get_technique_external_reference(technique)
    assert reference
    assert reference['source_name'] == 'mitre-attack'
    assert reference['url'] == "https://attack.mitre.org/techniques/T1548/001"


def test_get_tactics_names():
    # technique with multiple tactics
    technique = mitre_parser.get_tactic_or_technique_by_id("T1610")
    tactics_names = mitre_parser.get_tactics_names(technique)
    assert tactics_names
    assert tactics_names == ['defense-evasion', 'execution']

    # tactic
    tactic = mitre_parser.get_tactic_or_technique_by_id("TA0001")
    tactics_names = mitre_parser.get_tactics_names(tactic)
    assert tactics_names
    assert tactics_names == ['initial-access']
