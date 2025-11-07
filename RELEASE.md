# Release Process

Official Falcosecurity rules releases are automated using GitHub Actions. Each ruleset is released individually and each version is tied to a specific git tag.

## Releasing a ruleset

In this repo, each ruleset is a standalone YAML file in the `/rules` directory (e.g. `falco_rules.yaml`, `application_rules.yaml`, ...). Each ruleset is released and versioned individually. When we release a ruleset, we do the following process:

1. Make sure that the `./github/FALCO_VERSIONS` file contains the most recent versions of Falco with which the given ruleset validates successfully.
  - When releasing a ruleset, the versions must be explicit stable Falco releases (e.g. not using `latest` or `master`), so that the new tag will provide an history of the Falco versions on which the ruleset was tested
  - If the ruleset does not validate with a stable Falco release (it can happen close to the time of a Falco release), it's ok to use a `master` version, which however needs to be patched with an additional commit [on the ruleset's release branch](#patching-a-ruleset) once the next stable Falco release gets published.
2. Determine a new version for the given ruleset (see the [section below](#versioning-a-ruleset)).
3. Create a new Git tag with the name convention `*name*-rules-*version*` (e.g. `falco-rules-0.1.0`, `application-rules-0.1.0`, ...). The naming convention is required due to this repository being a [monorepo](https://en.wikipedia.org/wiki/Monorepo) and in order to be machine-readable.
4. A GitHub action will validate the repository [registry](./registry.yaml) and release the new OCI artifact in the packages of this repository.

## Patching a ruleset

Patches on an already-released ruleset can anytime on a per-need basis. Assuming a release Git tag in the form of `*name*-rules-*version*`, with version being in the form of `X.Y.Z` (e.g. `falco-rules-0.1.0`), the process is as follows:

1. If not already created, create a release branch starting from the first tag of the released ruleset.
  a. Checkout the first ruleset release tag: e.g. `git checkout falco-rules-0.1.0`
  b. Create a new branch with the naming convention `release/*name*-rules-X.Y.x`, starting from the tag: e.g. `git checkout -b release/falco-rules-0.1.x`
  c. As for step #1 of the [*Releasing a ruleset section*](#releasing-a-ruleset), make sure that `./github/FALCO_VERSIONS` contains all the **stable** Falco versions with which the ruleset validates successfully, by adding an extra commit to the release branch in case changes are required.
  d. Open a [PR in falcosecurity/test-infra](https://github.com/falcosecurity/test-infra/edit/master/config/config.yaml) to add `release/*name*-rules-X.Y.x` as protected branch to the `prow/config.yaml`, for example:
    ```yaml
    rules:
      branches:
        main:
          protect: true
        ...
        "release/falco-rules-0.1.x":
          protect: true
    ```
2. Open one or more PRs agains the release branch of the released ruleset.
  a. Wait for all the CI checks to pass.
  b. Check the automatic versioning suggestions provided by the CI (see [an example](https://github.com/falcosecurity/rules/pull/74#issuecomment-1571867580)), and make sure that **only patch changes** are present.
  c. Considering the automatic versioning suggestions, and at discretion of the domain knowledge of the repository maintainers, decide whether the PR should be merged or not.
3. Bump the ruleset version **patch** number by 1 and create a new Git tag from the release branch (e.g. `falco-rules-0.1.1`).
4. A GitHub action will validate the repository [registry](./registry.yaml) and release the new OCI artifact in the packages of this repository.

## Versioning a ruleset

The version of the official Falco rulesets is compatible with [SemVer](https://semver.org/) and must be meaningful towards the changes in its structure and contents. To define a new version `x.y.z` for a given ruleset, consider the following guidelines.

Our automation will detect most of the following criteria and suggest a summary with all the changes relative to each of the three versioning categories (patch, minor, major). This provides a changelog and valuable suggestion on the next version to be assigned to each ruleset. However, be mindful that the versioning process cannot totally automated and always requires human attention (e.g. we can't automatically detect subtle semantic changes in rules). The automated jobs will use the versions of Falco defined in `./github/FALCO_VERSIONS` for validating and checking rulesets. The versions must be line-separated and ordered from the most recent to the least recent. Any [published container image tag](https://hub.docker.com/r/falcosecurity/falco/tags) is a valid Falco version entry, including `master`, `latest`, and any other stable release tag (e.g. `0.35.0`). `master` indicates the most recent dev version of Falco built from mainline, and can be used for using a not-yet-published version of Falco in case we want to run the CI with a new in-development feature.

**NOTE:** *The versioning guidelines also apply to any versioned ruleset not maintained in this repository (such as the ones in [falcosecurity/plugins](https://github.com/falcosecurity/plugins)), including the ones distributed by third parties. These are best practices that guarantee the correct behavior of Falco when updating a given ruleset to a new version.*

- `z` _(patch number)_ is incremented when you make backward-compatible changes. In this case, the ruleset can be updated in a given Falco without needing to update Falco, its plugins, or its configuration. Examples:
    - Decrementing `required_engine_version`
    - Decrementing plugin version requirement in `required_plugin_versions`
    - Adding alternatives entries to an already-existing plugin version requirement in `required_plugin_versions`
    - Removing a plugin version requirement with all its alternatives in `required_plugin_versions`
    - Enabling at default one or more rules that used to be disabled
    - Adding or removing items for one or more lists
    - Adding one or more tags to a rule
    - Increasing the priority of a rule
    - Changing the output fields of a rule (without increasing `required_engine_version`)
    - Adding or removing exceptions for one or more Falco rules (without increasing `required_engine_version`)
    - Changing the condition for one or more rules by still preserving their logical security scope (e.g. making them less noisy, matching more events than before)
- `y` _(minor number)_ is incremented when you add functionality in a backward-compatible manner. In order to be accepted, the new ruleset may mandate updating the version of Falco, changing its configuration, or updating/installing one or more plugins. Examples:
    - Incrementing `required_engine_version`
    - Incrementing the `required_plugin_versions` version requirement for one or more plugin
    - Adding a new plugin version requirement (with or without `alternatives`) in `required_plugin_versions`
    - Adding one or more lists, macros, or rules
    - Adapting the ruleset to a Falco engine version introducing *backward-compatible* changes in the expected ruleset language definitions or file format. For now, this can't happen without also bumping `required_engine_version` since it is a simple progressive number. However, this may change in the future if we consider adopting a sem-ver-like version scheme.
- `x` _(major number)_ is incremented when you make incompatible content changes which change the expected behavior and outcome of the ruleset. Incompatibilities may arise when relying on the ruleset from other rulesets (e.g. appending conditions or overriding the definition of a list, macro, or rule). Examples:
    - Removing a plugin version requirement alternative (without removing the whole dependency) in `required_plugin_versions`
    - Renaming or removing a list, macro, or rule
    - Changing the event source of a rule
    - Disabling at default one or more rules that used to be enabled
    - Removing one or more tags from a rule
    - Decreasing the priority of a rule
    - Changing in any way the set of matched events matched by a macro
    - Changing the logical security scope of one or more macros or rules (e.g. a rule starts serving a substantially different purpose, or matches less events than before)
    - Adapting the ruleset to a Falco engine version introducing *backward-incompatible* changes in the expected ruleset language definitions or file format

When more than one version numbers need to be incremented, the most dominant takes precedence. For example, incrementing the `z` patch number would be enough when minorly chaning a rule's condition to make it less noisy, however you must increment the `y` minor number in case the new condition uses a new field or operator that requires increasing the `required_engine_version`.
