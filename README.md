# Falco Rules

👷‍♀️ **Under active development** 👷‍♂️

[![License](https://img.shields.io/github/license/falcosecurity/plugins?style=for-the-badge)](./LICENSE)

Note: *This repository has been created upon this [proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20221129-artifacts-distribution.md#move-falco-rules-to-their-own-repo) and is not yet ready for use. The progress tracker can be found [here](https://github.com/falcosecurity/evolution/issues/229).*

This repository contains the [Rule Registry](#rule-registry) and the [rules officially maintained](#falcusecurity-rules) by the Falcosecurity organization. [Rules](https://falco.org/docs/rules) tell [Falco](https://github.com/falcosecurity/falco) what to do. Please refer to the [official documentation](https://falco.org/docs/rules) to better understand the rules' concepts. 

## Rule Registry

The Registry contains metadata and information about every rule known and recognized by the Falcosecurity organization. These rules are developed for Falco and made available to the community. Check out the sections below to know how to [register your rules](#registering-a-new-rule) and see rules currently contained in the registry.

### Registering a new Rule

Registering your rule inside the registry helps ensure that some technical constraints are respected. Moreover, this is a great way to share your rule project with the community and engage with it, thus gaining new users and **increasing its visibility**. We encourage you to register your rule in this registry before publishing it.

The registration process involves adding an entry about your rule inside the [registry.yaml](./registry.yaml) file by creating a Pull Request in this repository. Please be mindful of a few constraints that are automatically checked and required for your rule to be accepted:

- The `name` field is mandatory and must be **unique** across all the rule in the registry
- The rule `name` must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9-_\-]*$` (however, its not reccomended to use `_` in the name, unless you are trying to match the name of a source or for particular reasons)
- The `path` field should specify the path to the rule in this repository
- The `url` field should point to the plugin source code

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

Please refer to the automatically generated [rules_inventory/rules_overview.md](https://github.com/falcosecurity/rules/blob/main/rules_inventory/rules_overview.md#falco-rules---detailed-overview) file for a detailed list of all the rules currently registered.

## Hosted Rules

Another purpose of this repository is to host and maintain the rules owned by the Falcosecurity organization. All the rules are contained inside the [rules](https://github.com/falcosecurity/rules/tree/main/rules) folder.

The `master` branch contains the most up-to-date state of development. Please check our [Release Process](./RELEASE.md) to know how rules are released. Dev builds are published each time a Pull Request gets merged into `master`, whereas stable builds are released and published only when a new release gets tagged.

If you wish to contribute your plugin to the Falcosecurity organization, you just need to open a Pull Request to add it inside the `rules` folder and to add it inside the registry. In order to be hosted in this repository, plugins must be licensed under the [Apache 2.0 License](./LICENSE). 

## Contributing

If you want to help and wish to contribute, please review our [contribution guidelines](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md). Code contributions are always encouraged and welcome!

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).

