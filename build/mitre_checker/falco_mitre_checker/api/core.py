import logging
from pathlib import Path
from typing import List, Dict

from falco_mitre_checker.engine.mitre_checker import FalcoMitreChecker
from falco_mitre_checker.models.falco_mitre_errors import FalcoMitreError
from falco_mitre_checker.utils.logger import MitreCheckerLogger

logger = logging.getLogger(MitreCheckerLogger.name)


def mitre_checker_engine(rules_files: List[Path], mitre_domain: str, mitre_version: str,
                         output_dir: Path = None) -> "Dict[str, List[FalcoMitreError]]":
    """
    CLI core function to validate the rules against the Mitre ATT&CK's data.
    :param rules_files: One or more falco rules files to check
    :param mitre_domain: The name of the Mitre ATT&CK matrix domain to validate the rules. This name is
                         used to pull the data from the Mitre CTI's database.
    :param mitre_version: The version of the Mitre ATT&CK to validate the rules. This version is used to
                          pull the data from the Mitre CTI's database.
    :param output_dir: A folder path to dump the errors information in json format.
    :param fix: If True, automatically generate the corrected falco rules file next to the original one
    """
    mitre_checker = FalcoMitreChecker(mitre_domain, mitre_version)
    errors_reports: Dict[str, List[FalcoMitreError]] = {}
    for file in rules_files:
        # validate the falco rules against the data of the mitre ATT&CK framework
        errors = mitre_checker.validate(file)
        errors_reports[file.stem] = errors
        output_name = f"{file.stem}_mitre_errors.json"
        output_path = output_dir / output_name if output_dir else file.parent / output_name

        FalcoMitreChecker.dump_errors(errors, output_path)
        logger.info(f"Dumped errors report in '{output_path}'")

        logger.info(f"Found {len(errors)} Mitre errors")

    return errors_reports
