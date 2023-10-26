#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given keyword, and output a baseline file

import os.path
import glob
import os
import yaml
import argparse
import csv

class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)

def str_presenter(dumper, data):
    """configures yaml for dumping multiline strings
    Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
    if data.count('\n') > 0:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')

yaml.add_representer(type(None), represent_none)
yaml.add_representer(str, str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)

def get_rule_yaml(rule_file, custom=False):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.yaml', recursive=True)]
    file_name = os.path.basename(rule_file)

    if custom:
        print(f"Custom settings found for rule: {rule_file}")
        try:
            override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        except IndexError:
            override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
        with open(override_path) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open(rule_file) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    
    try:
        og_rule_path = glob.glob('../rules/**/{}'.format(file_name), recursive=True)[0]
    except IndexError:
        #assume this is a completely new rule
        og_rule_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
    
    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)
    og.close()

    for yaml_field in og_rule_yaml:
        try:
            if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
            else:
                if isinstance(rule_yaml[yaml_field], list):
                    resulting_yaml[yaml_field] = og_rule_yaml[yaml_field] + rule_yaml[yaml_field]
                
                if yaml_field == "references":
                    resulting_yaml["references"] = og_rule_yaml['references']
                    if "srg" in og_rule_yaml["references"].items():
                        all_srgs = og_rule_yaml["references"]["srg"] + rule_yaml["references"]["custom"]["srg"]
                    else:
                        all_srgs = rule_yaml["references"]["custom"]["srg"]
                    new_srgs = list(set(all_srgs))
                    if "N/A" in new_srgs:
                        new_srgs.remove("N/A")
                     
                    resulting_yaml["references"]["srg"] = new_srgs
                    
                
                    print(f'new srgs for {rule_file} - {new_srgs}')

        except KeyError as e:
            resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
            # print(f"key error {e} for {rule_file}")
    
    if "stig" not in resulting_yaml['tags']:
        resulting_yaml["references"]["srg"] = ["N/A"]
        resulting_yaml["references"]["cci"] = ["N/A"]
        resulting_yaml["references"]["disa_stig"] = ["N/A"]

    return resulting_yaml

def collect_rules():
    all_rules = []
    for rule in sorted(glob.glob('../rules/**/*.yaml',recursive=True)) + sorted(glob.glob('../custom/rules/**/*.yaml',recursive=True)) :
        rule_yaml = get_rule_yaml(rule, custom=False)    
        all_rules.append(rule_yaml)

    return all_rules

def main():

    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    # stash current working directory
    original_working_directory = os.getcwd()

    # switch to the scripts directory
    os.chdir(file_dir)

    all_rules = collect_rules() 

    for rule in all_rules:
        nr_filename = f'{rule["id"]}.yaml'
        nr_folder = rule["id"].split("_")[0]
        nr_build_path = os.path.join("../build/newrules", nr_folder)
        if not os.path.exists(nr_build_path):
            os.makedirs(nr_build_path)
        nr_path = os.path.join(nr_build_path, nr_filename)
        with open(nr_path, "w") as f:
            yaml.dump(rule,f, Dumper=MyDumper, sort_keys=False, width=float("inf"))

    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()