# Contributing

Thank you for your interest in contributing to Falco's rules!

This repository includes a dedicated guide for contributing rules, outlining the definitions of the rules maturity framework and the criteria for rule acceptance. This guide inherits from the general [contributing](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md) guide.

All rules must be licensed under the [Apache 2.0 License](./LICENSE).


**Table of Contents**

* [Rules Maturity Framework](#rules-maturity-framework)
* [Rules Acceptance Criteria](#rules-acceptance-criteria)


# Rules Maturity Framework

The rules maturity framework was established following this [proposal](proposals/20230605-rules-adoption-management-maturity-framework.md). 

At a high level, The Falco Project maintains community-contributed syscall and container event-based [rules](https://github.com/falcosecurity/rules/blob/main/rules/), with `maturity_stable` tagged rules being included in the Falco release package. Other maturity-level rules are released separately, requiring explicit installation and possible customization for effective. In essence, there are now dedicated rule files for each maturity level.

The next sections will dive deeper into how the framework works and offer guidance on selecting a maturity level for specific rules.

## Overall Guidelines

As specified in the tags section of the [Style Guide of Falco Rules](https://falco.org/docs/rules/style-guide/#tags), every rule upstreamed to The Falco Project must include a maturity level as its first tag.

A new rule typically starts as `maturity_sandbox` and, in some cases, as `maturity_incubating`. However, it cannot immediately be at the `maturity_stable` level.

Only rules at the `maturity_stable` level are distributed with the Falco release package and live in the established `falco_rules.yaml` file. All rules at the remaining maturity levels can be found in the Falco rules file according to their respective levels, and they need to be installed separately. They are made available to the adopter through the same means as the `falco_rules.yaml` file, either by directly retrieving them from this repository or by fetching them via `falcoctl`. Adopters have the flexibility to choose how they install and customize the upstream rules to suit their needs.

Rules files:

```
falco_rules.yaml
falco-incubating_rules.yaml
falco-sandbox_rules.yaml
falco-deprecated_rules.yaml
```

Falco offers configurability through the [falco.yaml](https://github.com/falcosecurity/falco/blob/master/falco.yaml) file, enabling support for the unique use cases of adopters. This configurability allows adopters to determine which rules should be loaded based on tags and other properties of the rules. With Falco 0.36 and beyond, it's now possible to apply multiple rules that match the same event, eliminating concerns about rule prioritization based on the "first match wins" principle.

Special note regarding *plugins* rules: The rules for different Falco [plugins](https://github.com/falcosecurity/plugins) are currently not integrated into this rules maturity framework.


## Maturity Levels

The levels:

- **maturity_stable** indicates that the rule has undergone thorough evaluation by experts with hands-on production experience. These experts have determined that the rules embody best practices and exhibit optimal robustness, making it more difficult for attackers to bypass Falco. These rules are highly relevant for addressing broader threats and are recommended for customization to specific environments if necessary. They primarily focus on universal system-level detections, such as generic reverse shells or container escapes, which establish a solid baseline for threat detection across diverse industries. This inherent bias against including more application-specific detections is due to their potential lack of broad relevance or applicability. However, to mitigate this bias, the maintainers reserve the right to make judgments on a case-by-case basis.
- **maturity_incubating** indicates that the rules address relevant threats, provide a certain level of robustness guarantee, and adhere to best practices in rule writing. Furthermore, it signifies that the rules have been identified by experts as catering to more specific use cases, which may or may not be relevant for each adopter. This category is expected to include a larger number of application-specific rules.   
- **maturity_sandbox** indicates that the rule is in an experimental stage. The potential for broader usefulness and relevance of "sandbox" rules is currently being assessed. These rules can serve as inspiration and adhere to the minimum acceptance criteria for rules.
- **maturity_deprecated** indicates that, upon re-assessment, the rule was deemed less applicable to the broader community. Each adopter needs to determine the relevance of these rules on their own. They are kept as examples but are no longer actively supported or tuned by The Falco Project.

In summary, the rules maturity tag reflects the robustness, relevance, applicability, and stability of each predefined rule in the [falcosecurity/rules](https://github.com/falcosecurity/rules/blob/main/rules/) repository. It serves as general guidance to determine which rules may provide the highest return on investment.

## Justification of Rules Maturity Framework for Falco Adoption

A rules maturity framework has been introduced for Falco users to facilitate the adoption of non-custom rules more effectively. This framework ensures a smooth transition for adopters, whether they use rules generically or for specific use cases. A smooth adoption process is defined by making it easy for adopters to understand each rule and also gain an understanding of not just what the rule is doing, but also how beneficial it can be under various circumstances. 
Additionally, due to this framework, adopters should find themselves with a clearer understanding of which rules can likely be adopted as-is versus which rules may require significant engineering efforts to evaluate and adopt.

The rules maturity framework aligns with the [status](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#status) levels used within The Falco Project repositories, namely "Stable", "Incubating", "Sandbox" and "Deprecated".

Not every rule has the potential to evolve and reach the "stable" level. This is because "stable" rules should address a broader range of attacks rather than being overly specific—such as detecting a single narrow CVE for a less common type of application, which could be easily bypassed. However, this does not mean that very specific rules do not provide value; on the contrary, they can serve a very specific purpose. These more specific rules may be better suited for custom adoption rather than integration into the upstream Falco rules.

The new framework aims to help adopters easily identify the nature of a rule, whether it's more behavioral or signature-based. This is accomplished by providing clearer descriptions. You can explore this in more detail in the [Rules Overview Document](https://falcosecurity.github.io/rules/).

The maturity level of the rules, however, does not directly reflect their potential for generating noise in the adopters' environment. This is due to the unique and constantly changing nature of each environment, especially in cloud environments, making it challenging to accurately predict the impact of rules.

Newcomers to Falco are encouraged to start by configuring their setup with introductory rules labeled as `maturity_stable`. These rules, which are currently based on syscall and container events live in the established [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) file.

As users become more familiar with Falco and better understand their unique environment, they can gradually fine-tune the rules to meet their specific requirements. Tuning rules goes hand in hand with assessing the performance overhead and adjusting Falco's [configuration](https://github.com/falcosecurity/falco/blob/master/falco.yaml) accordingly. This consideration is important to keep in mind as there are usually limitations to the budget allocated for security monitoring.

Once adopters have integrated the stable default rules with low False Positives and acceptable performance overhead consistently, they can add a next set of rules. This set may include rules with `maturity_incubating` or `maturity_sandbox`, offering more specific detections and/or broader monitoring, depending on the rule.

# Rules Acceptance Criteria

The [maintainers](OWNERS) of this repository kindly reserve the right to make case-by-case decisions regarding rules acceptance and initial maturity leveling.

The high-level principles that guide the review process for contributors and reviewers are as follows:

- Each rule aligns with the project's best interests as per our [governance](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md).
- Each rule conforms to the [Style Guide of Falco Rules](https://falco.org/docs/rules/style-guide/).
- In particular, the [Rules Maturity Framework](#rules-maturity-framework) is honored.

> Note: Any rule that would require using the `-A` flag (enabling high-volume syscalls) cannot be accepted beyond `maturity_sandbox` and `enabled: false` due to performance impact reasons. At the moment, we discourage upstream rules based on high-volume syscalls. However, this assessment may change as Falco evolves.

*Correctness*

As part of the review process, the following aspects will be thoroughly checked to effectively enforce the [Style Guide of Falco Rules](https://falco.org/docs/rules/style-guide/).

- Correctness of the expression language, both syntactically and grammatically.
- Consistency with the name/description.
- If any tests are present, they must pass. During the initial review process and subsequent changes, manual testing should also be conducted to verify that the rule is capable of detecting the cyber threat(s) it aims to detect. In some cases, conducting more realistic tests, like deploying the rules on actual servers before acceptance, will be necessary.

*Robustness*

To enhance the effectiveness of detection, priority is given to behavioral detections, as opposed to string matching on process command arguments or other fields. This preference is based on the ease with which the latter can be circumvented. The same principle applies when selecting the most robust system call for detecting a specific threat. However, there is a place and purpose for more signature-based detections. The existing rules tagged with `maturity_stable` serve as a good starting point to explore a variety of useful rules that cover various attack vectors and employ both signature and behavior-based detection styles. Lastly, The Falco Project favors broader rules over narrow ones addressing a single, less common CVE for an application.

*Relevance*

Determining relevance is often the most subjective criterion, as it requires expertise in offensive security, cyber defense, and real-world production settings for accurate assessment. Questions such as whether these threats are a priority for most organizations or if we can provide enough context for a security analyst to appropriately act on the alerts as part of their incident response workflows are top of mind when assessing the overall relevance. Relevance is a key factor that indirectly reflects both robustness and significance, but more importantly, it indicates whether a particular security threat is significant to most adopters and, consequently, beneficial to broadly detect.

Here are some aspects that can be discussed during the review process in order to decide if a rule has the potential to be effectively operationalized by most adopters:

- Cover relevant attack vectors across various industries.
- Emphasize behavior-detection style + profiling over pure signatures (exceptions to this guideline apply).
- Evaluate the rule's effectiveness across diverse workloads (e.g. nodes serving web applications, databases, transactional processing, general compute or CI jobs).
- Guidance and templates to assist with tuning can be provided given Falco's current capabilities.
