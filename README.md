# Falco Rules

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) [![License](https://img.shields.io/github/license/falcosecurity/rules?style=for-the-badge)](./LICENSE)

Note: *This repository has been created upon this [proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20221129-artifacts-distribution.md#move-falco-rules-to-their-own-repo).*

This repository maintains the default *rules files* officially owned by the Falcosecurity organization as well as the Falco Rules Files Registry. 

## Falco Rules

Rules tell [Falco](https://github.com/falcosecurity/falco) what to do. These rules are pre-defined detections for various security threats, abnormal behaviors, and compliance-related monitoring. Adopters can customize these rules to their specific needs or use them as examples. Please refer to the [official documentation](https://falco.org/docs/rules) to better understand the rules' concepts.

The `main` branch contains the most up-to-date state of development. All rules files are located under the [rules folder](rules/). Please refer to our [Release Process](./RELEASE.md) to understand how rules are released. Stable rules are released and published only when a new release gets tagged. This means that rules in the `main` branch can become incompatible with the latest stable Falco release if, for example, new output fields are introduced.

Links:
- [Getting Started with Falco Rules - Official Documentation](https://falco.org/docs/rules)
- [Rules Overview Document](https://falcosecurity.github.io/rules/)
- [Rules Maturity Framework and Adoption](CONTRIBUTING.md#rules-maturity-framework)

### Default Rules

The [falco_rules.yaml](rules/falco_rules.yaml) file contains Falco's default rules, categorized by the maturity level `maturity_stable` based on the [Rules Maturity Framework](CONTRIBUTING.md#rules-maturity-framework). Stable rules are enabled by default. Additionally, the file includes incubating and sandbox rules that are not enabled by default and may require engineering effort for [effective adoption](CONTRIBUTING.md#justification-of-rules-maturity-framework-for-falco-adoption). All rules in [falco_rules.yaml](rules/falco_rules.yaml) are solely based on syscalls and container events. For an up-to-date overview table linking to the respective Mitre Attack resources and more, please refer to the [rules overview](https://falcosecurity.github.io/rules/) document. Lastly, you can find Falco plugins rules in the respective [plugins](https://github.com/falcosecurity/plugins) repos' subfolder.

Interested in contributing your custom rules? Visit the [contributing](#contributing) section below and join the Falco community now!

## Falco Rules Files Registry

The Falco Rules Files Registry contains metadata and information about rules files distributed by the Falcosecurity organization. The registry serves as an additional method of making the rules files available to the community, complementing the process of retrieving the rules files from this repository. 

Note: _Currently, the registry includes only rules for the syscall call data source; for other data sources see the [plugins repository](https://github.com/falcosecurity/plugins)._

<!-- Check out the sections below to know how to [register your rules](#registering-a-new-rule) and see rules currently contained in the registry. -->

<!--
### Registering a new Rules file

Registering your rule inside the registry helps ensure that some technical constraints are respected. Moreover, this is a great way to share your ruleset and make it available to the community. We encourage you to register your ruleset in this registry before publishing it.

The registration process involves adding an entry about your rule inside the [registry.yaml](./registry.yaml) file by creating a Pull Request in this repository. Please be mindful of a few constraints that are automatically checked and required for your rule to be accepted:

- The `name` field is mandatory and must be **unique** across all the rule in the registry
- The rule `name` must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9-_\-]*$` (however, its not reccomended to use `_` in the name)
- The `path` field should specify the path to the rule in this repository
- The `url` field should point to the ruleset file in the source code

For reference, here's an example of an entry for a rule:
```yaml
- name: falco-rules
  description: Falco rules that are loaded by default
  authors: The Falco Authors
  contact: https://falco.org/community
  maintainers:
    - name: The Falco Authors
      email: cncf-falco-dev@lists.cncf.io
  path: rules/falco_rules.yaml
  license: apache-2.0
  url: https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
```

You can find the full registry specification here: *(coming soon...)*

### Registered Rules

Please refer to the automatically generated [rules overview](https://falcosecurity.github.io/rules/overview/) document file for a detailed list of all the rules currently registered.

-->

## Contributing

If you are interested in helping and wish to contribute, we kindly request that you review our general [contribution guidelines](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md) and, more specifically, the dedicated [rules contributing guide](CONTRIBUTING.md) hosted in this repository. Please be aware that our reviewers will ensure compliance with the rules' acceptance criteria.

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).

