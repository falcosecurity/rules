# Release Process

Official Falcosecurity rules releases are automated using GitHub Actions. Each ruleset is released individually and each version is tied to a specific git tag.

## Releasing a ruleset

In this repo, each ruleset is a standalone YAML file in the `/rules` directory (e.g. `falco_rules.yaml`, `application_rules.yaml`, ...). Each ruleset is released and versioned individually. When we release a ruleset, we do the following process:

1. Determine a new version for the given ruleset (see the [section below](#versioning-a-ruleset))
2. Create a new Git tag with the name convention `*name*-rules-*version*` (e.g. `falco-rules-0.1.0`, `application-rules-0.1.0`, ...). The naming convention is required due to this repository being a [monorepo](https://en.wikipedia.org/wiki/Monorepo) and in order to be machine-readable.
3. A GitHub action will validate the repository [registry](./registry.yaml) and release the new OCI artifact in the packages of this repository

## Versioning a ruleset

The version of the official Falco rulesets is compatible with [SemVer](https://semver.org/) and must be meaningful towards the changes in its structure and contents. To define a new version `x.y.z` for a given ruleset, consider the following guidelines. 

**NOTE:** *The versioning guidelines also apply to any versioned ruleset not maintained in this repository (such as the ones in [falcosecurity/plugins](https://github.com/falcosecurity/plugins)), including the ones distributed by third parties. These are best practices that guarantee the correct behavior of Falco when updating a given ruleset to a new version.*

- `z` _(patch number)_ is incremented when you make backward-compatible changes. In this case, the ruleset can be updated in a given Falco without needing to update Falco, its plugins, or its configuration. Examples:
    - Adding one or more lists, macros, or rules
    - Enabling at default one or more rules that used to be disabled
    - Adding or removing items for one or more lists
    - Adding or removing exceptions for one or more Falco rules (without needing a `required_engine_version`)
    - Changing the condition for one or more rules or macros by still preserving their logical security scope (e.g. making them less noisy)
- `y` _(minor number)_ is incremented when you add functionality in a backward-compatible manner. In order to be accepted, the new ruleset may mandates updating the version of Falco, changing its configuration, or updating/installing one or more plugins. Examples:
    - Incrementing the `required_engine_version` number
    - Incrementing the `required_plugin_versions` version requirement for one or more plugin
    - Adding a new plugin version requirement in `required_plugin_versions`
- `x` _(major number)_ is incremented when you make incompatible content changes which change the expected behavior and outcome of the ruleset. Incompatibilities may arise when relying on the ruleset from other rulesets (e.g. appending conditions or overriding the definition of a list, macro, or rule). Examples:
    - Renaming or removing a list, macro, or rule
    - Disabling at default one or more rules that used to be enabled
    - Changing the logical security scope of one or more rules or macros (e.g. a rule stops detecting an entire spectrum of events that it used to detect, or starts serving a substantially different purpose)
    - Adapting the ruleset to a Falco engine version introducing backward-incompatible changes in the expected ruleset language definitions or file format

When more than one version numbers need to be incremented, the most dominant takes precedence. For example, incrementing the `z` patch number would be enough when adding a new rule, however you must increment the `y` minor number in case the new rule uses a new field or condition operator that increases the `required_engine_version`.
