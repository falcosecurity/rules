import pandas as pd
import yaml
import argparse
import datetime
import os
import sys
import re

"""
Usage:
pip install -r .github/scripts/requirements.txt
python .github/scripts/rules_overview_generator.py --rules_dir=rules > docs/index.md
"""

BASE_MITRE_URL_TECHNIQUE="https://attack.mitre.org/techniques/"
BASE_MITRE_URL_TACTIC="https://attack.mitre.org/tactics/"
BASE_PCI_DSS="https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf"
BASE_NIST="https://csf.tools/reference/nist-sp-800-53/r5/"
COLUMNS=['maturity', 'rule', 'desc', 'workload', 'mitre_phase', 'mitre_ttp', 'extra_tags', 'compliance_pci_dss', 'compliance_nist', 'extra_tags_list', 'mitre_phase_list', 'compliance_pci_dss_list', 'compliance_nist_list', 'enabled']

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules_dir', help='Path to falco rules directory containing all rules yaml files.')
    return parser.parse_args()

def rules_to_df(rules_dir):
    l = []
    for rules_filename in os.listdir(rules_dir):
        if not 'falco' in rules_filename:
            continue
        with open(os.path.join(rules_dir, rules_filename), 'r') as f:
            items = yaml.safe_load(f)
            for item in items:
                if 'rule' in item and 'tags' in item:
                    if len(item['tags']) > 0:
                        item['maturity'], item['workload'], item['mitre_phase'], item['mitre_ttp'], item['compliance_pci_dss'], item['compliance_nist'], item['extra_tags'] = [], [], [], [], [], [], []
                        for i in item['tags']:
                            if i.startswith('maturity_'):
                                item['maturity'].append(i) # should be just one per rule, be resilient and treat as list as well
                            elif i.startswith('PCI_DSS_'):
                                item['compliance_pci_dss'].append('[{}]({})'.format(i, BASE_PCI_DSS))
                            elif i.startswith('NIST_800-53_'):
                                # NIST links: revisit in the future, could be fragile
                                item['compliance_nist'].append('[{}]({}{}/{})'.format(i, BASE_NIST, re.search('NIST_800-53_(.*)-', i, re.IGNORECASE).group(1).lower(), \
                                    i.replace('NIST_800-53_', '').lower()))
                            elif i in ['host', 'container']:
                                item['workload'].append(i)
                            elif i.startswith('mitre_'):
                                item['mitre_phase'].append(i)
                            elif i.startswith('T'):
                                if i.startswith('TA'):
                                    item['mitre_ttp'].append('[{}]({}{})'.format(i, BASE_MITRE_URL_TACTIC, i.replace('.', '/')))
                                else:
                                    item['mitre_ttp'].append('[{}]({}{})'.format(i, BASE_MITRE_URL_TECHNIQUE, i.replace('.', '/')))
                            else:
                                item['extra_tags'].append(i) 
                        item['workload'].sort()
                        item['mitre_phase'].sort()
                        item['mitre_ttp'].sort()
                        item['compliance_pci_dss'].sort()
                        item['compliance_nist'].sort()
                        item['mitre_phase_list'] = item['mitre_phase']
                        item['extra_tags_list'] = item['extra_tags']
                        item['compliance_pci_dss_list'] = item['compliance_pci_dss']
                        item['compliance_nist_list'] = item['compliance_nist']
                        item['enabled'] = (item['enabled'] if 'enabled' in item else True) 
                        l.append([', '.join(item[x]) if x in ['maturity', 'workload', 'mitre_phase', 'mitre_ttp', 'compliance_pci_dss', 'compliance_nist', 'extra_tags'] else item[x] for x in COLUMNS])

    if not l:
        sys.exit('No valid rules in any of the falco_rules.* files in the rules_dir or no falco_rules.* files in the rules_dir in the first place, exiting ...')
    df = pd.DataFrame.from_records(l, columns=COLUMNS)
    return df.sort_values(by=['maturity','rule'], inplace=False)

def print_markdown(df):
    n_rules=len(df)
    df_overview = df.drop(['extra_tags_list', 'mitre_phase_list', 'compliance_pci_dss_list', 'compliance_nist_list'], axis=1)
    df_stable = df_overview[(df_overview['maturity'] == 'maturity_stable')]
    df_incubating = df_overview[(df_overview['maturity'] == 'maturity_incubating')]
    df_sandbox = df_overview[(df_overview['maturity'] == 'maturity_sandbox')]
    df_deprecated = df_overview[(df_overview['maturity'] == 'maturity_deprecated')]

    print('# Falco Rules Overview\n')
    print('Last Updated: {}\n'.format(datetime.date.today()))
    print('This auto-generated document is derived from the `falco*_rules.yaml` files files within the [rules](https://github.com/falcosecurity/rules/blob/main/rules/) directory of the main branch in the official Falco [rules repository](https://github.com/falcosecurity/rules/tree/main).\n')
    print('The Falco project maintains a total of {} [rules](https://github.com/falcosecurity/rules/blob/main/rules/), of which {} rules are included in the default Falco package and labeled with [maturity_stable](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md#rules-maturity-framework). Rules at the remaining maturity levels may need extra customization to ensure effective adoption. Consequently, certain rules are intentionally disabled by default, irrespective of their maturity level.\n'.format(n_rules, len(df_stable)))
    print('This document provides an extensive overview of community-contributed syscall and container event-based rules. It offers resources for learning about these rules, promoting successful adoption, and driving future enhancements.\n')
    print('\n[Stable Falco Rules](#stable-falco-rules) | [Incubating Falco Rules](#incubating-falco-rules) | [Sandbox Falco Rules](#sandbox-falco-rules) | [Deprecated Falco Rules](#deprecated-falco-rules) | [Falco Rules Stats](#falco-rules-stats)\n')
    print('\nThe tables below can be scrolled to the right.\n')
    
    print('\n## Stable Falco Rules\n')
    print('\n{} stable Falco rules ({:.2f}% of rules) are enabled by default:\n'.format(len(df_stable), (100.0 * len(df_stable) / n_rules)))
    print(df_stable.to_markdown(index=False))
    
    print('\n## Incubating Falco Rules\n')
    print('\n{} incubating Falco rules ({:.2f}% of rules):\n'.format(len(df_incubating), (100.0 * len(df_incubating) / n_rules)))
    print(df_incubating.to_markdown(index=False))
    
    print('\n## Sandbox Falco Rules\n')
    print('\n{} sandbox Falco rules ({:.2f}% of rules):\n'.format(len(df_sandbox), (100.0 * len(df_sandbox) / n_rules)))
    print(df_sandbox.to_markdown(index=False))
    
    print('\n## Deprecated Falco Rules\n')
    print('\n{} deprecated Falco rules ({:.2f}% of rules):\n'.format(len(df_deprecated), (100.0 * len(df_deprecated) / n_rules)))
    print(df_deprecated.to_markdown(index=False))
    
    print('\n# Falco Rules Stats\n')
    print('\n### Falco rules per workload type:\n')
    df1 = df.groupby('workload').agg(rule_count=('workload', 'count'))
    df1['percentage'] = round(100.0 * df1['rule_count'] / df1['rule_count'].sum(), 2).astype(str) + '%'
    print(df1.to_markdown(index=True))

    print('\n### Falco rules per [Mitre Attack](https://attack.mitre.org/) phase:\n')
    df2 = df[['rule', 'maturity', 'mitre_phase_list']].explode('mitre_phase_list')
    df2.rename(columns={'mitre_phase_list':'mitre_phase'}, inplace=True)
    df2.sort_values(by=['mitre_phase','rule'], inplace=True)
    df2['rule'] = df[['maturity', 'rule']].agg(': '.join, axis=1)
    df2 = df2.groupby('mitre_phase').agg({'rule': lambda x: ['\n'.join(list(x)), len(list(x))]})
    df2['rules'] = df2['rule'].apply(lambda x: x[0])
    df2['percentage'] = df2['rule'].apply(lambda x: round((100.0 * x[1] / n_rules), 2)).astype(str) + '%'
    print(df2.drop('rule', axis=1).to_markdown(index=True))
    
    print('\n### Compliance-related Falco rules:\n')
    df3 = df
    df3['compliance_tag'] = df['compliance_pci_dss_list'] + df['compliance_nist_list']
    df3.sort_values(by=['rule'], inplace=True)
    df3 = df3[['rule', 'compliance_tag', 'maturity']].explode('compliance_tag')
    df3 = df3.groupby('compliance_tag').agg({'rule': lambda x: ['\n'.join(list(x)), len(list(x))]})
    df3['rules'] = df3['rule'].apply(lambda x: x[0])
    # df3['percentage'] = df3['rule'].apply(lambda x: round((100.0 * x[1] / n_rules), 2)).astype(str) + '%'
    print(df3.drop('rule', axis=1).to_markdown(index=True))

    
if __name__ == '__main__':
    args_parsed = arg_parser()
    rules_dir = args_parsed.rules_dir
    
    if not rules_dir or not os.path.isdir(rules_dir):
        sys.exit('No valid rules directory provided via --rules_dir arg, exiting ...')

    print_markdown(rules_to_df(rules_dir))
