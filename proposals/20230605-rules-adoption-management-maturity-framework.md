# Falco Rules Adoption, Management and Maturity Framework

## Objective

The objective is to outline key enhancements and improvements to Falco, focusing on optimizing its rule adoption, customization, and management capabilities. The proposal also introduces a rules maturity framework to provide a structured approach for assessing and categorizing rules.

In more detail, this proposal aims to address the expectations of adopters by providing clear guidelines for rule contribution, including processes and criteria. It also aims to provide guidance on rule customization and tuning to help adopters optimize the detection capabilities of Falco for their specific environments. Lastly, the proposal aims to empower adopters by providing them with the necessary knowledge and resources to effectively manage and customize rules. 

The proposed timeline for the initial completion of each item is the Falco 0.36 release, with further improvements being continuously added based on feedback.


## Current State

This section highlights the current (as of June 6, 2023) procedures and resources for rules creation and adoption and serves as an assessment:

- The Falco Project website provides detailed explanations on how to [write](https://falco.org/docs/rules/) Falco rules along with references such as the [supported fields](https://falco.org/docs/reference/rules/supported-fields/) for conditions and outputs.
- Community members contribute rules via opening a PR against the [falcosecurity/rules](https://github.com/falcosecurity/rules) repo.
- [Tutorials](https://falco.org/docs/tutorials/) and [blog posts](https://falco.org/tags/rules/) related to rules are available on the Falco website, along with numerous references to webinars and conference talks.
- Falco features a CLI tool called [falcoctl](https://github.com/falcosecurity/falcoctl) to manage the lifecycle of rules (installation, updates), see [blog post](https://falco.org/blog/falcoctl-install-manage-rules-plugins/).
- The rules framework of Falco is battle-tested and proven to be reliable in production environments. It is used by a diverse range of [organizations](https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md).
- Existing rules yaml files
  - Main Falco rules ([falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)) based on syscall and container events.
  - [application_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/application_rules.yaml) also contains rules based on network-related syscalls, which may seem misleading if you expect those rules to be present in the regular "falco_rules.yaml" file.
  - Plugins rules are based on third-party data sources that Falco hooks into, in addition to or instead of kernel tracing, e.g. [k8s_audit_rules.yaml](https://github.com/falcosecurity/plugins/blob/master/plugins/k8saudit/rules/k8s_audit_rules.yaml), [github.yaml](https://github.com/falcosecurity/plugins/blob/master/plugins/github/rules/github.yaml), [okta_rules.yaml](https://github.com/falcosecurity/plugins/blob/master/plugins/okta/rules/okta_rules.yaml) or [aws_cloudtrail_rules.yaml](https://github.com/falcosecurity/plugins/blob/master/plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml).
- Rules include a concise description and a sense of `priority` to determine the level at which they should be loaded and activated. Furthermore, there is a key called `tag` that includes additional filter fields and information. This information may indicate whether a rule is designed to detect abnormal behavior in workloads running on the host or in containers. The tag field may also include details about the corresponding Mitre Attack phase and [TTP](https://attack.mitre.org/tactics/enterprise/) (Tactics, Techniques, and Procedures) codes.
- Falco provides an [overview](https://github.com/falcosecurity/rules/blob/main/rules_inventory/rules_overview.md) document that summarizes rules related to syscalls and container events and an experimental interactive [rules explorer website](https://github.com/Issif/falco-rules-explorer).
- Falco's website features [FAQ](https://falco.org/about/faq/) and [About](https://falco.org/about/) pages providing detailed technical information.


## Proposed Improvements

### Highlight and Outline Primary Use Cases

Adopters will be presented with clear primary use cases to better understand how Falco can be leveraged. These use cases will encompass "Threat Detection" and "Compliance". Rules specifically related to compliance will be tagged with "compliance" in the existing tag list.

> Falco serves two main use cases:
> - Threat Detection: Rule violations as indicators of compromise.
> - Compliance: Detecting unauthorized changes to files under PCI/DSS.


### Rules Maturity Framework

A rules maturity framework will be developed for Falco users to better facilitate the adoption of non-custom rules. This framework ensures a smooth transition for adopters, whether they use rules generically or for specific use cases.

The maturity level of the rules, however, does not directly reflect their potential for generating noise in the adopters' environment. This is due to the unique and constantly changing nature of each environment, especially in cloud environments, making it challenging to accurately predict the impact of rules.

Newcomers to Falco will be encouraged to start by configuring their setup with introductory rules labeled as "Falco's default rules" (maturity: "Stable"). These rules will be based on syscall and container events and will live in the established [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml). 

As users become more familiar with Falco and better understand their unique environments, they can gradually fine-tune the default rules to meet their specific requirements. Tuning rules goes hand in hand with assessing the performance overhead and adjusting Falco's [configuration](https://github.com/falcosecurity/falco/blob/master/falco.yaml) accordingly. This consideration is crucial to convey to adopters, as it is important to keep in mind that there are usually limitations to the budget allocated for security monitoring.

Once adopters have integrated the stable default rules with low false positives and acceptable performance consistently, they can add a next set of rules (maturity: "Incubating") for more specific detections. These efforts will be accompanied by guidance on rule customization and broader educational initiatives focusing on Linux OS runtime security.

> Experts in the field, with expertise in areas such as offensive security, Linux kernel tracing, production deployment, cyber security, threat detection, compliance, data analysis, and data science, will be responsible for assessing the maturity level of rules. These experts have a deep familiarity with Falco.

> Rules maturity will adopt the [status](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#status) levels used to indicate the maturity of each repository within The Falco Project, that is, "Stable", "Incubating", "Sandbox", "Deprecated". Each rule must go through the "Incubating" state before advancing to "Stable" as a minimum requirement. Only "Stable" rules will be enabled by default. 


Rules maturity levels:

- **Stable** (enabled by default) indicates that the rule has been thoroughly evaluated by experts in the field who have hands-on production experience. These experts have determined that the rule addresses a highly relevant threat and recommend that adopters adjust the rule to their specific environment. "Stable" rules embody the utmost best practices and demonstrate optimal robustness in relation to Falco's current capabilities.      
- **Incubating** (disabled by default) indicates that rules have been identified by experts as catering to more specific use cases that may or may not be relevant for each adopter. However, these rules address relevant threats, provide some level of robustness guarantee, and adhere to best practices in rule writing.    
- **Sandbox** (disabled by default), indicates that the rule is in an experimental stage. The potential for broader usefulness and relevance of "Sandbox" rules is currently being assessed. The rule can serve as an inspiration and adheres to the minimum acceptance criteria for rules.
- **Deprecated** (disabled by default), indicates that after re-assessing the rule, it was deemed less applicable to the broader community, and each adopter needs to determine their relevance on their own. These rules are kept as examples, but they are no longer actively supported or tuned by The Falco Project.


> Falco introduces a new key called "maturity" to each rule with levels including "Stable", "Incubating", "Sandbox" and "Deprecated" to guide the adoption process. This key reflects the robustness and relevance of each predefined rule in the [falcosecurity/rules](https://github.com/falcosecurity/rules/blob/main/rules/) repository, but it does not directly indicate the potential noise it may generate.    


### Define Rule Contribution Process

A guide will be established to facilitate the contribution of new rules or updates to existing ones. This guide will serve as an extension to the generic Falco [contributing guide](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md). This guide will outline clear acceptance criteria for each maturity level and establish minimum requirements for rule creation. These criteria will be utilized to assess the acceptance or rejection of a rule.

This guide will also include information on how the community is intended to share rules. As a general principle, rhe project's main objective is to curate an optimal set of "Stable" rules that are included in the main [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) file and also published as OCI artifacts. However, there may be opportunities to create additional platforms for ad-hoc rules sharing that do not necessarily need to meet the strict criteria set by the Falco maintainers.


The minimum criteria for rules creation shall include:

*Correctness*

The rule must be both syntactically and grammatically correct and should evaluate to true during successful end-to-end tests. Furthermore, it needs to accurately detect the intended cyber threats, specifically the Tactics, Techniques, and Procedures (TTPs).


*Robustness*

To enhance the effectiveness of detection, priority is given to behavioral detections, as opposed to simple string matching on process command arguments or other fields. This preference is based on the ease with which the latter can be circumvented. The same principle applies when selecting the most robust system call for detecting a specific threat at a particular point in time or attack scenario. For concrete examples of more robust rules, please refer to Appendix 1.


*Relevance*

Determining relevance is often the most subjective criterion, as it requires expertise in offensive security, cyber defense, and real-world production settings for accurate assessment. Questions such as whether these threats are a priority for most organizations or if we can provide enough context for a security analyst to appropriately act on the alerts as part of their incident response workflows are top of mind when assessing the overall relevance. Relevance is a key factor that indirectly reflects both robustness and significance, but more importantly, it indicates whether a particular security threat is significant to most adopters and, consequently, beneficial to detect.

Possible criteria:

- Cover relevant attack vectors across various industries.
- Emphasize profiling over signatures.
- Effectiveness of the rule across diverse workloads.
- Guidance and templates are provided to assist with tuning.

*Testing*

How was the rule tested? The desired testing approach includes not only functional end-to-end tests in virtual machines (VMs) but also deployments in real-world infrastructure. The Falco maintainers will provide guidance and support to contributors throughout the testing process, recognizing that it will vary significantly for each rule due to its unique nature.


### Guidance on Rule Customization and Tuning

Each rule tagged as "Stable" will provide clear guidance on how it can be tuned, customized, or combined with other rules if applicable. Over time, a catalog of general best tuning practices will be developed. For specific examples, please refer to Appendix 2. 


### Setting Expectations for Adopters

Setting clear expectations for adopters of Falco is crucial. While Falco is a powerful security monitoring tool, it's important to be aware of its limitations and maintain realistic expectations. Please refer to Appendix 3 for specific examples of current limitations of Falco.

Adopters should understand the importance of consulting the latest [documentation](https://falco.org/) and updates to ensure they have accurate and up-to-date information. Additionally, the project [roadmap](https://github.com/orgs/falcosecurity/projects/5) offers valuable insights into features that are currently being developed or planned for future releases. Keeping informed about the roadmap helps adopters understand the direction of Falco's development and the potential enhancements that may be available in the future for writing more powerful detections.

In addition, effectively utilizing Falco requires expertise in various domains, including offensive security, Linux kernel tracing, production deployment, cyber security, threat detection, compliance, data analysis, and data science. Depending on the specific domain it may be easier to get started or require a little ramping up.

## Key Results for Falco 0.36

In summary, the following action items are planned to be completed leading up to the Falco 0.36 release: 

- Clearly communicate Falco's primary uses: threat detection and compliance.
- Establish specific criteria for each rules maturity level and define general criteria for creating, contributing, and updating rules based on their respective maturity levels.
- Create a clear PR template for the rules repo that references the criteria for rules acceptance.
- Offer guidance and templates for rules tuning purposes.
- Audit each existing rule and assign a maturity level to it. Ensure a minimum set of 20 or more diverse rules are identified as "Stable" and enabled by default. These rules should cover a wide range of top cyber threats and have the potential to effectively detect indicators of compromise related to those threats.
- Audit the existing rules from a compliance perspective and tag them with the "compliance" tag if applicable. By the release of Falco 0.36, ensure that there are at least three template Falco rules in the "Incubating" state specifically designed for "compliance" use cases.
- Add support for the new "maturity" key in the Falco binary.
- Update Falco's website to concisely document new processes and information, making it a single source of truth for creating, tuning, or contributing rules.

As a result of these changes, Falco's principles for rules adoption, maturity, and management will be updated. However, adopters can continue to use Falco as they have been doing before.

## Appendix


### Appendix 1

Here are some examples of more robust rules with a brief description of why they are considered more robust and behavioral-based rather than relying too heavily on signatures:

<details>
    <summary>Detect release_agent File Container Escapes</summary>
      <p> 
        Detecting attempts to escape a container is a crucial detection for modern container orchestration systems like Kubernetes. This rule stands out due to its inclusion of preconditions, which verify the necessary privileges of the container. Without these preconditions, the specific TTPs associated with container escape are not feasible.
      </p> 
      <p>
        The rule is based on the open syscall while monitoring file writing activities, specifically looking for a string match on the file name "release_agent". This approach is robust because Linux expects the cgroup's release_agent file to be named in this manner.
      </p> 
      <p>
        One downside of the rule is that it addresses only one specific TTP. Enabling additional rules like "Change thread namespace" can enhance coverage for other container escape methods.
      </p> 
</details> 


<details>
    <summary>Drop and execute new binary in container</summary>
      <p> 
        The Falco 0.34 release <a href="https://falco.org/blog/falco-0-34-0/#even-more-ways-of-catching-suspicious-executions"> note</a> provides a concise summary of how high-value kernel signals can greatly simplify the task of detecting suspicious executions that occur when a malicious implant is dropped and executed. Instead of relying on complex checks for executable paths, the focus shifts to identifying executables that were not part of the container image and were executed from the container's upper overlayfs layer shortly after being dropped.
      </p> 
      <p>
        This approach narrows detection scope, increases tractability, and eliminates the need for inspecting unfamiliar or unusual executable paths. By leveraging high-value kernel signals, detections become more precise, removing ambiguity and providing crucial context.
      </p> 
</details> 

</br>


### Appendix 2

Tuning Falco rules can vary in complexity and involve tradeoffs based on the environment. While some tuning processes are straightforward, there are cases that require nuanced adjustments. It's essential for adopters to be aware that on-host rule tuning may have limitations.

In some scenarios, adopters may benefit from acknowledging that operationalizing detections could require additional data analysis and correlation. This implies that adopting organizations may need to leverage data lake systems for further analysis and contextual correlation of the generated alerts, going beyond rule tuning.

Here are some general tricks for tuning on-host rules:

<details>
    <summary>Profiling</summary>
      <p> 
        Profiling the environment can be effective in detecting abnormal behaviors that may be considered normal in system-critical applications but outliers in standard applications. Implementing a simple allow list, such as for container names or namespaces, can already provide valuable assistance. This approach also aligns with the practice of clearly defining the crown jewel applications for which robust detections are desired.
      </p> 
</details> 

<details>
    <summary>Linux concepts / behavioral indicators</summary>
      <p> 
        Another aspect of tuning a detection involves considering behavioral aspects related to Linux concepts. For example, a detection can be tuned based on the presence of a shell or a Java process in the parent process lineage, or detecting file manipulations while maintaining manual interactive shell access to a container. By incorporating these behavioral indicators, the detection can become more specific, relevant, and effective in identifying potential security threats.
      </p> 
</details> 

</br>


### Appendix 3

Examples of existing gaps in Falco for threat detection, as of June 6, 2023, include:

<details>
    <summary>Deep kernel-level monitoring</summary>
      <p> 
        Falco operates at the kernel level but does not provide deep visibility into all aspects of kernel internals. It focuses on monitoring system calls and other observable events but may not capture low-level kernel activities.
      </p> 
</details> 

<details>
    <summary>Network packet inspection</summary>
      <p> 
        Falco's primary focus is on monitoring system calls, and while it can detect network-related system calls, it may not offer extensive network packet inspection capabilities. Additionally, when considering modern cloud architectures with load balancers in front of application backend servers, there are inherent limitations in L3/4 network monitoring. Lastly, keeping in mind that Falco runs on each host in isolation, it means that certain correlations and detailed network introspection are still being extended and improved upon.
      </p> 
</details> 

<details>
    <summary>Full-stack application monitoring</summary>
      <p> 
        Essentially, Falco is designed to monitor the Linux kernel and system-level activities. While it can capture certain application-related events, it may not provide comprehensive monitoring and visibility into the full application stack. However, there are exceptions where Falco has expanded its monitoring coverage to additional data sources using the <a href="https://falco.org/docs/plugins/"> plugins</a> framework. One notable example is the integration with Kubernetes audit logs, which provides monitoring at the control plane level within a Kubernetes infrastructure. In addition, Falco's underlying libraries possess the capability to capture abnormal behavior at higher levels of the stack, such as analyzing HTTP requests. However, this potential is currently not exposed in Falco.
      </p> 
</details> 


<details>
    <summary>Advanced behavior analysis / anomaly detection</summary>
      <p> 
        Falco excels at detecting known patterns and rules-based anomalies. However, it currently may have limitations when it comes to advanced behavior analysis, on host anomaly detection, or identifying zero-day exploits that do not exhibit known patterns.
      </p> 
</details> 

</br>

Consult the project [roadmap](https://github.com/orgs/falcosecurity/projects/5) and official [documentation](https://falco.org/) for up to date information on Falco's current capabilities.
