# Mitre Checker Module

The Mitre Checker module aims to check the compliance of the Falco rules against the Mitre ATT&CK
Framework. This module provides to Falco experts and Falco users a way to check default and custom
rules for Mitre ATT&CK extra tags.
This module uses STIX from the OASIS standards. Structured Threat Information Expression (STIX™) is a
language and serialization format used to exchange cyber threat intelligence (CTI) :

- [STIX CTI documentation](https://oasis-open.github.io/cti-documentation/stix/intro)

Leveraging STIX, Mitre Checker fetches the ATT&CK® STIX Data from MITRE ATT&CK repositories using the
`python-stix2` library implemented by OASIS:

- [ATT&CK STIX Data repository](https://github.com/mitre-attack/attack-stix-data)
- [Python STIX2 repository](https://github.com/oasis-open/cti-python-stix2)

The choice of a module is motivated by the packaging of a python code to integrate it into wider Falco
implementations. More precisely, the module can be used :

- by the rules_overview_generator.py script
- by Falco users and experts to check their Falco rules files
- by other Falco components that need to check the validity of rules files

## Build

Requirements :

- Python >= `3.10`
- Poetry >= `1.5.1`

```sh
./build.sh
```

## Install

Requirements :

- Python >= `3.10`

```sh
./install.sh
```

Or manualy using `pip` :

```sh
pip install dist/mitre_checker-0.1.0-py3-none-any.whl
```

## Usage

```sh
python -m falco_mitre_checker --help
```

Using the stable falco rules :

```sh
python -m falco_mitre_checker -f ../../rules/falco_rules.yaml -o /tmp/
```

## Development

Requirements :

- Python >= `3.10`
- Poetry >= `1.5.1`

```sh
poetry check
poetry update
poetry install --sync
```

### Testing

With coverage :

```sh
poetry update
poetry run python -m pytest falco_mitre_checker/tests --cov=falco_mitre_checker
```

```
---------- coverage: platform linux, python 3.10.12-final-0 ----------                                   
Name                                                     Stmts   Miss  Cover                             
----------------------------------------------------------------------------                             
falco_mitre_checker/__init__.py                              0      0   100%                             
falco_mitre_checker/__main__.py                              7      7     0%                             
falco_mitre_checker/api/__init__.py                          0      0   100%                             
falco_mitre_checker/api/core.py                             19     19     0%                             
falco_mitre_checker/cli/__init__.py                          0      0   100%                             
falco_mitre_checker/cli/core.py                             18     18     0%                             
falco_mitre_checker/engine/__init__.py                       0      0   100%                             
falco_mitre_checker/engine/mitre_checker.py                 46      1    98%                             
falco_mitre_checker/exceptions/__init__.py                   0      0   100%          
falco_mitre_checker/exceptions/rules_exceptions.py           8      0   100%                             
falco_mitre_checker/models/__init__.py                       0      0   100%                             
falco_mitre_checker/models/falco_mitre_errors.py            16      0   100%                             
falco_mitre_checker/models/falco_mitre_relations.py         14      2    86%
falco_mitre_checker/parsers/__init__.py                      0      0   100%
falco_mitre_checker/parsers/falco_rules.py                  30      1    97%                             
falco_mitre_checker/parsers/mitre_stix.py                   31      4    87%                            
falco_mitre_checker/tests/__init__.py                        0      0   100%                             
falco_mitre_checker/tests/engine/__init__.py                 0      0   100%                            
falco_mitre_checker/tests/engine/test_mitre_checker.py      41      0   100%                            
falco_mitre_checker/tests/parsers/__init__.py                0      0   100%                            
falco_mitre_checker/tests/parsers/test_falco_rules.py       18      0   100%                             
falco_mitre_checker/tests/parsers/test_mitre_stix.py        34      0   100%
falco_mitre_checker/tests/test_common.py                    13      2    85%
falco_mitre_checker/utils/__init__.py                        0      0   100%
falco_mitre_checker/utils/file.py                           10      0   100%
falco_mitre_checker/utils/logger.py                         36      7    81%
----------------------------------------------------------------------------
TOTAL                                                      341     61    82%
```

### Security

You should run a vulnerability scanner every time you add a new dependency in projects :

```sh
poetry update
poetry run python -m safety check
```

```
  Using non-commercial database
  Found and scanned 33 packages
  Timestamp 2023-10-02 13:43:51
  0 vulnerabilities found
  0 vulnerabilities ignored
+=======================================================================================================+

 No known security vulnerabilities found. 

+=======================================================================================================+
```


