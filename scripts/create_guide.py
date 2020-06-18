#!/usr/bin/env python3
# filename: create_guide.py
# description: Create AsciiDoc guide from YAML

import argparse
import io
import yaml
import os
from string import Template
from itertools import groupby
import glob

# Convert a list to AsciiDoc
def ulify(elements):
    string = "\n"
    for s in elements:
        string += "* " + str(s) + "\n"
    return string

def group_ulify(elements):
    string = "\n * "
    for s in elements:
        string += str(s) + ", "
    return string[:-2]


# Setup argparse
parser = argparse.ArgumentParser(
    description='Given a baseline, create an AsciiDoc guide.')
parser.add_argument("baseline", default=None,
                    help="Baseline YAML file used to create the guide.", type=argparse.FileType('rt'))
parser.add_argument("-o", "--output", default=None,
                    help="Output file", type=argparse.FileType('wt'))

try:
    results = parser.parse_args()
    output_basename = os.path.basename(results.baseline.name)
    output_filename = os.path.splitext(output_basename)[0]
    if results.output:
        output_file = results.output
    else:
        output_file = open("../build/{}.adoc".format(output_filename), 'w')
    print('Profile YAML:', results.baseline.name)
    print('Output file:', output_file.name)
except IOError as msg:
    parser.error(str(msg))

# Read the profile YAML details
profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)

# Setup AsciiDoc templates
with open('../templates/adoc_rule.adoc') as adoc_rule_file:
    adoc_rule_template = Template(adoc_rule_file.read())

with open('../templates/adoc_supplemental.adoc') as adoc_supplemental_file:
    adoc_supplemental_template = Template(adoc_supplemental_file.read())

with open('../templates/adoc_rule_no_setting.adoc') as adoc_rule_no_setting_file:
    adoc_rule_no_setting_template = Template(adoc_rule_no_setting_file.read())

with open('../templates/adoc_section.adoc') as adoc_section_file:
    adoc_section_template = Template(adoc_section_file.read())

with open('../templates/adoc_header.adoc') as adoc_header_file:
    adoc_header_template = Template(adoc_header_file.read())

with open('../templates/adoc_footer.adoc') as adoc_footer_file:
    adoc_footer_template = Template(adoc_footer_file.read())

# Create header
header_adoc = adoc_header_template.substitute(
    profile_title = profile_yaml['title'],
    description = profile_yaml['description'],
    html_header_title=profile_yaml['title'],
    html_title = profile_yaml['title'].split(':')[0],
    html_subtitle = profile_yaml['title'].split(':')[1],
    pdf_version = "0.9, 2020-06-17",
    html_version = "0.9, 2020-06-17",
    logo = "nist.png"

)

# Output header
output_file.write(header_adoc)

# Create sections and rules
for sections in profile_yaml['profile']:
    section_yaml_file=sections['section'].lower() + '.yaml'
    #check for custom section
    if section_yaml_file in glob.glob1('../custom/sections/', '*.yaml'):
        print(f"Custom settings found for section: {sections['section']}")
        override_section = os.path.join('../custom/sections', sections['section'] + '.yaml')
        with open(override_section) as r:
            section_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open('../sections/' + sections['section'] + '.yaml') as s:
            section_yaml = yaml.load(s, Loader=yaml.SafeLoader)

    # Read section info and output it
    

    section_adoc = adoc_section_template.substitute(
        section_name = section_yaml['name'],
        description = section_yaml['description']
    )

    output_file.write(section_adoc)

    
    # Read all rules in the section and output them
    
    for rule in sections['rules']:
        print(rule)
        rule_path = glob.glob('../rules/*/{}.yaml'.format(rule))
        rule_file = (os.path.basename(rule_path[0]))

        #check for custom rule
        if rule_file in glob.glob1('../custom/rules/', '*.yaml'):
            print(f"Custom settings found for rule: {rule_file}")
            override_rule = os.path.join('../custom/rules', rule_file)
            with open(override_rule) as r:
                rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        else:
            with open(rule_path[0]) as r:
                rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        
        

        # Determine if the references exist and set accordingly
        try:
            rule_yaml['references']['cci']
        except KeyError:
            cci = 'N/A'
        else:
            cci = ulify(rule_yaml['references']['cci'])

        try:
            rule_yaml['references']['cce']
        except KeyError:
            cce = 'N/A'
        else:
            cce = ulify(rule_yaml['references']['cce'])

        try:
            rule_yaml['references']['800-53r4']
        except KeyError:
            nist_80053r4 = 'N/A'
        else:
            #nist_80053r4 = ulify(rule_yaml['references']['800-53r4'])
            nist_80053r4 = rule_yaml['references']['800-53r4']
            
        try:
            rule_yaml['references']['disa_stig']
        except KeyError:
            disa_stig = 'N/A'
        else:
            disa_stig = ulify(rule_yaml['references']['disa_stig'])

        try:
            rule_yaml['references']['srg']
        except KeyError:
            srg = 'N/A'
        else:
            srg = ulify(rule_yaml['references']['srg'])
        
        try:
            rule_yaml['fix']
        except KeyError:
            rulefix = "No fix Found"
        else:
            rulefix = rule_yaml['fix']#.replace('|', '\|')
  
        try:
            rule_yaml['tags']
        except KeyError:
            tags = 'none'
        else:
            tags = rule_yaml['tags']

        try:
            result = rule_yaml['result']
        except KeyError:
            result = 'N/A'
    
        if "integer" in result:
            result_value=result['integer']
        elif "boolean" in result:
            result_value=result['boolean']
        elif "string" in result:
            result_value=result['string']
        else:
            result_value = 'N/A'
        
        # process nist controls for grouping
        nist_80053r4.sort()
        res = [list(i) for j, i in groupby(nist_80053r4, lambda a: a.split('(')[0])]
        nist_controls = ''
        for i in res:
            nist_controls += group_ulify(i)
            
        if 'supplemental' in tags:
            rule_adoc = adoc_supplemental_template.substitute(
                rule_title=rule_yaml['title'].replace('|', '\|'),
                rule_id=rule_yaml['id'].replace('|', '\|'),
                rule_discussion=rule_yaml['discussion'],
            )
        # elif ('permanent' in tags) or ('inherent' in tags) or ('n_a' in tags):
        #     rule_adoc = adoc_rule_no_setting_template.substitute(
        #         rule_title=rule_yaml['title'].replace('|', '\|'),
        #         rule_id=rule_yaml['id'].replace('|', '\|'),
        #         rule_discussion=rule_yaml['discussion'].replace('|', '\|'),
        #         rule_check=rule_yaml['check'],  # .replace('|', '\|'),
        #         rule_fix=rulefix,
        #         rule_80053r4=nist_controls,
        #         rule_disa_stig=disa_stig,
        #         rule_srg=srg
        #     )
        else:
            rule_adoc = adoc_rule_template.substitute(
                rule_title = rule_yaml['title'].replace('|', '\|'),
                rule_id = rule_yaml['id'].replace('|', '\|'),
                rule_discussion = rule_yaml['discussion'].replace('|', '\|'),
                rule_check = rule_yaml['check'],#.replace('|', '\|'),
                rule_fix = rulefix,
                rule_cci = cci,
                rule_80053r4 = nist_controls,
                rule_cce = cce,
                rule_srg = srg,
                rule_result = result_value
            )

        output_file.write(rule_adoc)

# Create footer
footer_adoc = adoc_footer_template.substitute(
)

# Output footer
output_file.write(footer_adoc)
