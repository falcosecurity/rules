import os
from pathlib import Path
from typing import Dict

import yaml


def read_yaml(path: Path) -> Dict:
    """
    Validate format and read yaml file content
    :param path: Path to a yaml file
    :return: file content as dictionnary
    """
    with open(path, "r") as p:
        return yaml.safe_load(p.read())


def write_file(content: str, output: Path):
    with open(os.path.expandvars(output), 'w') as f:
        f.write(content)
