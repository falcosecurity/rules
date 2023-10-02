import logging
from pathlib import Path
from typing import List

import typer

from falco_mitre_checker.api.core import mitre_checker_engine
from falco_mitre_checker.exceptions.rules_exceptions import FalcoRulesFileContentError
from falco_mitre_checker.utils.logger import MitreCheckerLogger

app = typer.Typer(help=f"Mitre Checker",
                  no_args_is_help=True,
                  context_settings={"help_option_names": ["-h", "--help"]})

logger = logging.getLogger(MitreCheckerLogger.name)


@app.command()
def core(rules_files: List[Path] = typer.Option(..., "-f", "--file",
                                                help="Path to a Falco rules file. "
                                                     "Repeat for multiple files validation."),
         mitre_domain: str = typer.Option("enterprise-attack", "-d", "--domain",
                                          help="Mitre ATT&CK domain name."),
         mitre_version: str = typer.Option("13.1", "-V", "--Version",
                                           help="Mitre ATT&CK domain version."),
         output_dir: Path = typer.Option(None, "-o", "--output-dir",
                                         help="Path to a directory to dump the error report for Mitre "
                                              "ATT&CK.")
         ):
    try:
        mitre_checker_engine(rules_files, mitre_domain, mitre_version, output_dir)
    except FalcoRulesFileContentError as e:
        logger.error(e.message)
        typer.Exit(1)


def cli():
    app()
