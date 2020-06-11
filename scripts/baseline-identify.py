#!/usr/bin/env python3
# filename: baseline_identify.py
# description: Identify which rules fall on specific baselines.

import argparse
import io
import yaml
import os
from string import Template
from itertools import groupby
import glob


# File path setup
file_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(file_dir)

# import profile_manifests.plist
baselines_file = os.path.join(parent_dir, 'includes', '800-53_baselines.yaml')
with open(baselines_file) as r:
    baselines = yaml.load(r, Loader=yaml.SafeLoader)

low_rules = []
mod_rules = []
high_rules = []

# Create sections and rules
for rule in sorted(glob.glob(parent_dir + '/rules/*/*.yaml')):
    with open(rule) as r:
        rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    try:
        rule_yaml['references']['800-53r4']
    except KeyError:
        nist_80053r4 = 'N/A'
    else:
        #nist_80053r4 = ulify(rule_yaml['references']['800-53r4'])
        nist_80053r4 = rule_yaml['references']['800-53r4']
    
    for control in nist_80053r4:
        if control in baselines['low']:
            #print("rule: {} contains: {} which falls on low baseline".format(rule_yaml['id'], control))
            if rule_yaml['id'] not in low_rules:
                low_rules.append(rule_yaml['id'])
        if control in baselines['moderate']:
            #print("rule: {} contains: {} which falls on moderate baseline".format(rule_yaml['id'], control))
            if rule_yaml['id'] not in mod_rules:
                mod_rules.append(rule_yaml['id'])
        if control in baselines['high']:
            #print("rule: {} contains: {} which falls on high baseline".format(rule_yaml['id'], control))
            if rule_yaml['id'] not in high_rules:
                high_rules.append(rule_yaml['id'])
    
print("{} Rules belong on LOW baseline".format(len(low_rules)))
for rule in low_rules:
    print("      - {}".format(rule))

print("\n {} Rules that belong on MODERATE baseline".format(len(mod_rules)))
for rule in mod_rules:
    print("      - {}".format(rule))

print("\n {} Rules that belong on HIGH baseline".format(len(high_rules)))
for rule in high_rules:
    print("      - {}".format(rule))