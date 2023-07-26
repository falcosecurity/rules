# Contributing

Thank you for your interest in contributing to Falco's rules!

This repo contains a dedicated rules contributing guide that highlights the rules maturity framework definitions as well as the criteria for rules acceptance. This guide inherits from the general [contributing](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md) guide.

All rules must be licensed under the [Apache 2.0 License](./LICENSE).


**Table of Contents**

* [Rules Maturity Framework](#rules-maturity-framework)
* [Rules Acceptance Criteria](#rules-acceptance-criteria)


# Rules Maturity Framework

The rules maturity framework was introduced based on this [proposal](proposals/20230605-rules-adoption-management-maturity-framework.md). As specified in the tags section of the [Style Guide of Falco Rules](https://falco.org/docs/rules/style-guide/#tags), every rule upstreamed to The Falco Project must include a maturity level as its first tag.

A new rule typically starts as `maturity_sandbox` and, in some cases, as `maturity_incubating`. However, it cannot immediately be at the `maturity_stable` level.

Only rules at the `maturity_stable` level are enabled by default.

Falco offers configurability through the [falco.yaml](https://github.com/falcosecurity/falco/blob/master/falco.yaml) file, enabling support for the unique use cases of adopters. This configurability allows adopters to determine which rules should be loaded based on tags and other properties of the rules.


## Maturity Levels

The levels (the maturity tag must be the first one in the rule's `tags` array):

- **maturity_stable** (enabled by default) indicates that the rule has undergone thorough evaluation by experts with hands-on production experience. These experts have determined that the rules embody best practices and exhibit optimal robustness, making it more difficult for attackers to bypass Falco. These rules are highly relevant for addressing broader threats and are recommended for customization to specific environments if necessary. They primarily focus on universal system-level detections, such as generic reverse shells or container escapes, which establish a solid baseline for threat detection across diverse industries. This inherent bias against including more application-specific detections is due to their potential lack of broad relevance or applicability. However, to mitigate this bias, a grey area will be reserved, enabling case-by-case judgments to be made.
- **maturity_incubating** (disabled by default) indicates that the rules address relevant threats, provide a certain level of robustness guarantee, and adhere to best practices in rule writing. Furthermore, it signifies that the rules have been identified by experts as catering to more specific use cases, which may or may not be relevant for each adopter. This category is expected to include a larger number of application-specific rules.   
- **maturity_sandbox** (disabled by default) indicates that the rule is in an experimental stage. The potential for broader usefulness and relevance of "sandbox" rules is currently being assessed. These rules can serve as inspiration and adhere to the minimum acceptance criteria for rules.
- **maturity_deprecated** (disabled by default), indicates that, upon re-assessment, the rule was deemed less applicable to the broader community. Each adopter needs to determine the relevance of these rules on their own. They are kept as examples but are no longer actively supported or tuned by The Falco Project.

The rules maturity tag reflects the robustness, relevance, applicability, and stability of each predefined rule in the [falcosecurity/rules](https://github.com/falcosecurity/rules/blob/main/rules/) repository. It serves as general guidance to determine which rules may provide the highest return on investment. 

## Justification of Rules Maturity Framework for Falco Adoption

A rules maturity framework has been introduced for Falco users to facilitate the adoption of non-custom rules more effectively. This framework ensures a smooth transition for adopters, whether they use rules generically or for specific use cases. A smooth adoption process is defined by making it easy for adopters to understand each rule and also gain an understanding of not just what the rule is doing, but also how beneficial it can be under various circumstances. Additionally, adopters should have a clear idea of which rules can likely be adopted as-is versus which rules may require significant engineering efforts to evaluate and adopt.

The rules maturity framework aligns with the [status](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#status) levels used within The Falco Project repositories, namely "Stable", "Incubating", "Sandbox" and "Deprecated".

Not every rule has the potential to evolve and reach the "stable" level. This is because "stable" rules should address a broader category of attacks rather than being overly specific and easily bypassed. However, this does not mean that very specific rules do not provide value; on the contrary, they can serve a very specific purpose. The intention of the new framework is to make it clearer for adopters to recognize that they need to evaluate such rules for their own environment.

The maturity level of the rules, however, does not directly reflect their potential for generating noise in the adopters' environment. This is due to the unique and constantly changing nature of each environment, especially in cloud environments, making it challenging to accurately predict the impact of rules.

Newcomers to Falco will be encouraged to start by configuring their setup with introductory rules labeled as "Falco's default rules" (`maturity_stable`). These rules, which are currently based on syscall and container events, will live in the established [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) file. 

As users become more familiar with Falco and better understand their unique environments, they can gradually fine-tune the default rules to meet their specific requirements. Tuning rules goes hand in hand with assessing the performance overhead and adjusting Falco's [configuration](https://github.com/falcosecurity/falco/blob/master/falco.yaml) accordingly. This consideration is important to keep in mind as there are usually limitations to the budget allocated for security monitoring.

Once adopters have integrated the stable default rules with low false positives and acceptable performance consistently, they can add a next set of rules. This set may include rules with `maturity_incubating` or `maturity_sandbox`,  offering more specific detections and/or broader monitoring, depending on the rule.

# Rules Acceptance Criteria

The [maintainers](OWNERS) of this repository reserve the right to make case-by-case decisions regarding rules acceptance and initial maturity leveling.

The high-level principles that guide the review process for contributors and reviewers are as follows:

- Each rule aligns with the project's best interests as per our [governance](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md).
- Each rule conforms to the [Style Guide of Falco Rules](https://falco.org/docs/rules/style-guide/).
- In particular, the [Rules Maturity Framework](#rules-maturity-framework) is honored.

> Note: Any rule that would require using the `-A` flag (enabling high-volume syscalls) cannot be accepted beyond `maturity_sandbox` due to performance impact reasons.

*Correctness*

As part of the review process, the following aspects will be thoroughly checked to effectively enforce the [Style Guide of Falco Rules](https://falco.org/docs/rules/style-guide/).

- Correctness of the expression language, both syntactically and grammatically.
- Consistency with the name/description.
- If any tests are present, they must pass. During the initial review process and subsequent changes, manual testing should also be conducted to verify that the rule is capable of detecting the cyber threat(s) it aims to detect. In some cases, more realistic testing will be necessary, such as deploying tests to production servers or, at the very least, QA servers.

*Robustness*

To enhance the effectiveness of detection, priority is given to behavioral detections, as opposed to string matching on process command arguments or other fields. This preference is based on the ease with which the latter can be circumvented. The same principle applies when selecting the most robust system call for detecting a specific threat. However, there is a place and purpose for more signature-based detections. The existing [upstream rules](rules/falco_rules.yaml) tagged with `maturity_stable` serve as a good starting point to explore a variety of useful rules that cover various attack vectors and employ both signature and behavior-based detection styles.

*Relevance*

Determining relevance is often the most subjective criterion, as it requires expertise in offensive security, cyber defense, and real-world production settings for accurate assessment. Questions such as whether these threats are a priority for most organizations or if we can provide enough context for a security analyst to appropriately act on the alerts as part of their incident response workflows are top of mind when assessing the overall relevance. Relevance is a key factor that indirectly reflects both robustness and significance, but more importantly, it indicates whether a particular security threat is significant to most adopters and, consequently, beneficial to broadly detect.

Here are some aspects that can be discussed during the review process in order to decide if a rule has the potential to be effectively operationalized by most adopters:

- Cover relevant attack vectors across various industries.
- Emphasize behavior-detection style + profiling over pure signatures (exceptions to this guideline apply).
- Evaluate the rule's effectiveness across diverse workloads (e.g. nodes serving web applications, databases, transactional processing, general compute or CI jobs).
- Guidance and templates to assist with tuning can be provided given Falco's current capabilities.

