# Falco Rules

[![Latest release](https://img.shields.io/github/v/release/falcosecurity/rules?style=for-the-badge)](https://github.com/falcosecurity/rules/releases/latest) [![Docs](https://img.shields.io/badge/docs-latest-green.svg?style=for-the-badge)](https://falco.org/docs/rules)  [![Rules Overview](https://img.shields.io/badge/docs-latest-green.svg?label=Rules%20Overview&style=for-the-badge)](https://falcosecurity.github.io/rules/) [![Supported Fields](https://img.shields.io/badge/docs-latest-green.svg?label=Supported%20Fields&style=for-the-badge)](https://falco.org/docs/reference/rules/supported-fields/)

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) [![License](https://img.shields.io/github/license/falcosecurity/rules?style=for-the-badge)](./LICENSE)

This repository has been created upon this [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20221129-artifacts-distribution.md#move-falco-rules-to-their-own-repo) and contains the officially managed [Falco Rules](#falco-rules) by The Falco Project, along with the [Falco Rules Files Registry](#falco-rules-files-registry).

## Falco Rules

Rules tell [Falco](https://github.com/falcosecurity/falco) what to do. These rules are pre-defined detections for various security threats, abnormal behaviors, and compliance-related monitoring.

<style>
    .container {
        display: flex;
        align-items: flex-start;
        margin-bottom: 20px;
    }

    .container img {
        flex: none;
        margin-right: 15px;
    }

    .container p {
        margin: 0;
    }
</style>

<div class="container">
    <img src="docs/images/start.png" alt="Image" width="21" height="21">
    <p>Explore the <a href="https://falco.org/docs/rules">Official Documentation</a> for a starting point and better understanding of rule concepts. Users can modify the community-contributed Falco rules to fit their needs or use them as examples. In most cases, users also create their own custom rules. Keep in mind that the rules in this repository are related to Falco's primary monitoring functions, specifically for syscalls and container events. Meanwhile, Falco plugin rules are stored within the respective subfolders of the <a href="https://github.com/falcosecurity/plugins">Plugins</a> repository.</p>
</div>

<div class="container">
    <img src="docs/images/insight.png" alt="Image" width="20" height="26">
    <p>Because Falco rules, especially Sandbox and Incubating rules, are dynamic, it's crucial to stay updated. As threats and systems evolve, Falco evolves with each release. Therefore, regularly check the <a href="https://falcosecurity.github.io/rules/">Rules Overview Document</a>, Falco's <a href="https://falco.org/docs/reference/rules/supported-fields/">Supported Fields</a>, and Falco's release notes with every new release. It is recommended to consistently use the most recent <a href='https://github.com/falcosecurity/falco/releases/latest'>Falco Release</a> to avoid compatibility issues, which are enforced by the <i>required_engine_version</i>.</p>
</div>

<div class="container">
    <img src="docs/images/setting.png" alt="Image" width="23" height="23">
    <p>Important: The Falco project only guarantees that the most recent rules releases are compatible with the latest Falco release. Discover all rule files in the <a href="rules/">rules/</a> folder. Refer to our <a href="./RELEASE.md">Release Process</a> and <a href="CONTRIBUTING.md#rules-maturity-framework">Rules Maturity Framework</a> for rule categorization, release procedures, and usage guidelines. Published upon tagging a new release, the <i>maturity_stable</i> rules in the <a href="rules/falco_rules.yaml">falco_rules.yaml</a> file are included in the default Falco release package. Other maturity-level rules are released separately, requiring explicit installation and possible customization for effective <a href="CONTRIBUTING.md#justification-of-rules-maturity-framework-for-falco-adoption">Adoption</a>.</p>
</div>

<div class="container">
    <img src="docs/images/announce.png" alt="Image" width="20" height="20">
    <p>Starting from rules version 3.0.0, the <i>required_engine_version</i> follows semantic versioning and only functions with Falco version >= 0.37.0. Since rules version <a href="#falco-rules-2x">2.0.0</a>, we've modified our rules' shipping and distribution process. With Falco >= 0.37.0, <i>selective rules overrides</i> aim to further streamline the adoption and customization of upstream rules.</p>
</div>

<div class="container">
    <img src="docs/images/cross.png" alt="Image" width="20" height="20">
    <p>Be cautious: The <i>main</i> branch has the latest development. Before using rules from the <i>main</i> branch, check for compatibility. Changes like new output fields might cause incompatibilities with the latest stable Falco release. The Falco Project advises using rules only from the release branches. Lastly, we'd like to highlight the importance of regular engineering effort to effectively adopt Falco rules. Considering that each adopter's system and monitoring needs are unique, it's advisable to view the rules as examples.</p>
</div>

## Falco Rules Files Registry

The Falco Rules Files Registry contains metadata and information about rules files distributed by the Falcosecurity organization. The registry serves as an additional method of making the rules files available to the community, complementing the process of retrieving the rules files from this repository. 

Note: _Currently, the registry includes only rules for the syscall call data source; for other data sources see the [plugins repository](https://github.com/falcosecurity/plugins)._

### Naming Convention

Rule files must be located in the [/rules](rules) folder of this repository and are named according to the following convention: `<ruleset>_rules.yaml`.

The `<ruleset>` portion represents the _ruleset_ name, which must be an alphanumeric string, separated by `-`, entirely in lowercase, and beginning with a letter.

Rule files are subsequently released using Git tags. The tag name should follow the pattern `<ruleset>-rules-<version>`, where `<version>` adheres to [Semantic Versioning](https://semver.org/). See [RELEASE.md](RELEASE.md) for more details about our release process.

For instance, the _falco_ ruleset is stored under [/rules/falco_rules.yaml](rules/falco_rules.yaml), and its version _1.0.0_ was released using the [falco-rules-1.0.0](https://github.com/falcosecurity/rules/releases/tag/falco-rules-1.0.0) tag.

Note: _This convention applies to this repository only. Falco application does not impose any naming convention for naming rule files._

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

## Falco Rules 2.x

Since version 2.0.0, the rules distributed from this repository have been split into three parts:

- [Stable](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) Falco rules. Those are the only ones that are bundled in the Falco by default. It is very important to have a set of stable rules vetted by the community. To learn more about the criterias that are required for a rule to become stable, see the [contributing guide](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md).
- [Incubating](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml) rules, which provide a certain level of robustness guarantee but have been identified by experts as catering to more specific use cases, which may or may not be relevant for each adopter.
- [Sandbox](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml) rules, which are more experimental.

Previously, Falco used to bundle all the community rules in its default distribution. Today you can choose which set of rules you want to load in your distribution, depending on your preferred installation method:

### Helm Chart

If you are using the official Helm chart, you can add the incubating and/or sandbox repository in your [falcoctl config](https://github.com/falcosecurity/charts/blob/f1062000e2e61332b3a8ea892a1765e4f4a60ec6/falco/values.yaml#L406) and by enabling them in the corresponding `falco.yaml` file.

For instance, in order to install the Helm chart and load all the available Falco rules with automatic update on all of them, you can run

```
helm install falco falcosecurity/falco --set "falcoctl.config.artifact.install.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" --set "falcoctl.config.artifact.follow.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" --set "falco.rules_file={/etc/falco/k8s_audit_rules.yaml,/etc/falco/rules.d,/etc/falco/falco_rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml}"
```

Where the option `falcoctl.config.artifact.install.refs` governs which rules are downloaded at startup, `falcoctl.config.artifact.follow.refs` identifies which rules are automatically updated and `falco.rules_file` indicates which rules are loaded by the engine.

### Host installation

If you are managing your Falco installation you should be aware of which directories contain the rules. Those are governed by the `rules_file` configuration option in your [falco.yaml](https://github.com/falcosecurity/falco/blob/ab6d76e6d2a076ca1403c91aa62213d2cadb73ea/falco.yaml#L146). Normally, there is also a `rules.d` directory that you can use to upload extra rules or you can add your custom files.

Now you can simply download incubating or sandbox rules from [the repository](https://download.falco.org/?prefix=rules/), uncompress and copy the file there.


## Contributing

If you are interested in helping and wish to contribute, we kindly request that you review our general [contribution guidelines](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md) and, more specifically, the dedicated [rules contributing guide](CONTRIBUTING.md) hosted in this repository. Please be aware that our reviewers will ensure compliance with the rules' acceptance criteria.

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).
