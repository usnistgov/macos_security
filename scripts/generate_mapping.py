#!/usr/bin/env python3

import sys
import csv
import os
import io
import glob
import yaml
import re
import argparse
from pathlib import Path


def get_rule_yaml(rule_file, custom=False):

    global resulting_yaml
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
        resulting_yaml['customized'] = ["customized rule"]

    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)

    for yaml_field in og_rule_yaml:
        #print('processing field {} for rule {}'.format(yaml_field, file_name))
        if yaml_field == "references":
            if not 'references' in resulting_yaml:
                resulting_yaml['references'] = {}
            for ref in og_rule_yaml['references']:
                try:
                    if og_rule_yaml['references'][ref] == rule_yaml['references'][ref]:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                    else:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                except KeyError:
                    #  reference not found in original rule yaml, trying to use reference from custom rule
                    try:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                    except KeyError:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                try:
                    if "custom" in rule_yaml['references']:
                        resulting_yaml['references']['custom'] = rule_yaml['references']['custom']
                        if 'customized' in resulting_yaml:
                            if 'customized references' not in resulting_yaml['customized']:
                                resulting_yaml['customized'].append("customized references")
                        else:
                            resulting_yaml['customized'] = ["customized references"]
                except:
                    pass
        elif yaml_field == "tags":
            # try to concatenate tags from both original yaml and custom yaml
            try:
                if og_rule_yaml["tags"] == rule_yaml["tags"]:
                    #print("using default data in yaml field {}".format("tags"))
                    resulting_yaml['tags'] = og_rule_yaml['tags']
                else:
                    #print("Found custom tags... concatenating them")
                    resulting_yaml['tags'] = og_rule_yaml['tags'] + rule_yaml['tags']
            except KeyError:
                resulting_yaml['tags'] = og_rule_yaml['tags']
        else:
            try:
                if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                    #print("using default data in yaml field {}".format(yaml_field))
                    resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
                else:
                    #print('using CUSTOM value for yaml field {} in rule {}'.format(yaml_field, file_name))
                    resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                    if 'customized' in resulting_yaml:
                        resulting_yaml['customized'].append("customized {}".format(yaml_field))
                    else:
                        resulting_yaml['customized'] = ["customized {}".format(yaml_field)]
            except KeyError:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]

    return resulting_yaml

def sort_nicely( l ):
# """ Sort the given list in the way that humans expect.
# """
    convert = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
    l.sort( key=alphanum_key )


def main():
    file_dir = os.path.dirname(os.path.abspath(__file__))

    os.chdir(file_dir)

    nist_header = ""
    other_header = ""
    sub_directory = ""
    def dir_path(string):
        if os.path.isdir(string):
            return string
        else:
            raise NotADirectoryError(string)

    home = str(Path.home())

    parser = argparse.ArgumentParser(description='Easily generate custom rules from compliance framework mappings')
    parser.add_argument("CSV", default=None, help="CSV to create custom rule files from a mapping.", type=argparse.FileType('rt'))
    parser.add_argument("-f", "--framework", default="800-53r5", help="Specify framework for the source. If no framework is specified, the default is 800-53r5.", action="store")

    try:
        results = parser.parse_args()
        print("Mapping CSV: " + results.CSV.name)
        print("Source compliance framework: " + str(results.framework))


    except IOError as msg:

        parser.error(str(msg))


    version_file = "../VERSION.yaml"
    with open(version_file) as r:
        version_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    for rule in glob.glob('../rules/**/*.yaml',recursive=True) + glob.glob('../custom/rules/**/*.yaml',recursive=True):

        sub_directory = rule.split(".yaml")[0].split("/")[2]

        if "supplemental" in rule or "srg" in rule:
            continue

        # with open(rule) as r:
        #     rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        rule_yaml = get_rule_yaml(rule, custom=False)

        control_array = []
        # print("----------------------")
        # print(rule_yaml)
        # print()
        with open(results.CSV.name, newline='',encoding='utf-8-sig') as csvfile:
            csv_reader = csv.DictReader(csvfile,dialect='excel')
            modded_reader = csv_reader
            dict_from_csv = dict(list(modded_reader)[0])


            list_of_column_names = list(dict_from_csv.keys())


            nist_header = list_of_column_names[1]
            other_header = list_of_column_names[0]




        with open(results.CSV.name, newline='',encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile,dialect='excel')

            for row in reader:

                if results.framework != nist_header:
                    sys.exit(str(results.framework) + " not found in CSV")

                if "N/A" in row[nist_header]:
                    continue

                controls = row[nist_header].split(',')

                duplicate = ""
                csv_duplicate = ""
                for control in controls:

                        try:

                            rule_yaml['references']

                            if "/" in str(results.framework):

                                framework_main = results.framework.split("/")[0]
                                framework_sub = results.framework.split("/")[1]

                                references = []
                                if "custom" not in rule_yaml['references']:
                                    references = rule_yaml['references'][framework_main][framework_sub]
                                else:
                                    references = rule_yaml['references']['custom'][framework_main][framework_sub]

                                for yaml_control in references:
                                    if duplicate == str(yaml_control).split("(")[0]:
                                        continue
                                    if csv_duplicate == str(row[other_header]):

                                        continue
                                    if control.replace(" ",'') == str(yaml_control):

                                        duplicate = str(yaml_control).split("(")[0]
                                        csv_duplicate = str(row[other_header])

                                        row_array = str(row[other_header]).split(",")
                                        for item in row_array:
                                            control_array.append(item)
                                            print(rule_yaml['id'] + " - " + str(results.framework) + " " + str(yaml_control) + " maps to " + other_header + " " + item)


                            else:

                                references = []
                                if "custom" not in rule_yaml['references']:
                                    references = rule_yaml['references'][results.framework]
                                else:
                                    references = rule_yaml['references']['custom'][results.framework]

                                for yaml_control in references:
                                    if duplicate == str(yaml_control).split("(")[0]:
                                        continue
                                    if csv_duplicate == str(row[other_header]):
                                        continue

                                    if control.replace(" ",'') == str(yaml_control):
                                        duplicate = str(yaml_control).split("(")[0]
                                        csv_duplicate = str(row[other_header])
                                        row_array = str(row[other_header]).split(",")
                                        for item in row_array:
                                            control_array.append(item)
                                            print(rule_yaml['id'] + " - " + str(results.framework) + " " + str(yaml_control) + " maps to " + other_header + " " + item)

                        except:
                            continue

        if len(control_array) == 0:
            continue

        custom_rule = '''references:
  custom:
    {}:'''.format(other_header)

        for control in control_array:
            custom_rule = custom_rule + '''
      - {}'''.format(control)

        custom_rule = custom_rule + '''
tags:
  - {}'''.format(other_header)

        if os.path.isdir("../build/" + other_header) == False:
            os.mkdir("../build/" + other_header)
        if os.path.isdir("../build/" + other_header + "/rules/") == False:
            os.mkdir("../build/" + other_header + "/rules/")
        if os.path.isdir("../build/" + other_header + "/rules/" + sub_directory) == False:
            os.mkdir("../build/" + other_header + "/rules/" + sub_directory)

        try:
            with open("../build/" + other_header + "/rules/" + sub_directory + "/" + rule_yaml['id'] + ".yaml", 'w') as r:
                custom_yaml = r.read()

                custom_yaml = custom_yaml.replace(other_header + ": ", custom_rule)
                with open("../build/" + other_header + "/rules/" + sub_directory + "/" + rule_yaml['id'] + ".yaml", 'w') as fw:
                    fw.write(custom_yaml)
        except:
                with open("../build/" + other_header + "/rules/" + sub_directory + "/" + rule_yaml['id'] + ".yaml", 'w') as fw:
                    fw.write(custom_rule)


    for rule in glob.glob("../build/" + other_header + "/rules/*/*"):
        if "supplemental" in rule or "srg" in rule:
            continue

        with open(rule) as r:
            custom_rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        othercontrols = []

        if other_header in custom_rule_yaml['references']['custom']:

            for control in custom_rule_yaml['references']['custom'][other_header]:

                if str(control) in othercontrols:
                    continue
                else:

                    othercontrols.append(str(control))

            sort_nicely(othercontrols)

            refs = "    "

            custom_rule = '''references:
  custom:
    {}:'''.format(other_header)

        for control in othercontrols:
            custom_rule = custom_rule + '''
      - {}'''.format(control)

        custom_rule = custom_rule + '''
tags:
  - {}'''.format(other_header)

        with open(rule, 'w') as rite:
            rite.write(custom_rule)


    audit = []
    auth = []
    icloud = []
    os_section = []
    pwpolicy = []
    system_settings = []
    sysprefs = []
    inherent = []
    na = []
    perm = []

    for rule in glob.glob('../build/' + other_header + '/rules/*/*.yaml'):
        if "supplemental" in rule or "srg" in rule or "baseline" in rule:
            continue

        with open(rule) as r:
            custom_rule = yaml.load(r, Loader=yaml.SafeLoader)
            rule_id = rule.split(".yaml")[0].split("/")[5]


            if other_header in custom_rule['tags']:
                if "inherent" in rule_yaml['tags']:
                    inherent.append(rule_id)
                    continue
                if "permanent" in custom_rule['tags']:
                    perm.append(rule_id)
                    continue
                if "n_a" in custom_rule['tags']:
                    na.append(rule_id)
                    continue

                if "/audit/" in rule:
                    audit.append(rule_id)

                    continue
                if "/auth/" in rule:
                    auth.append(rule_id)
                    continue
                if "/icloud/" in rule:
                    icloud.append(rule_id)
                    continue
                if "/os/" in rule:
                    os_section.append(rule_id)
                    continue
                if "/pwpolicy/" in rule:
                    pwpolicy.append(rule_id)
                    continue
                if "/system_settings/" in rule:
                    system_settings.append(rule_id)
                    continue
                if "/sysprefs/" in rule:
                    sysprefs.append(rule_id)
                    continue


    full_baseline = '''title: "{4} {2} ({3}): Security Configuration - {0}"
description: |
  This guide describes the actions to take when securing a {4} {2} system against the {1}.
authors: |
  |===
  |Name|Organization
  |===
parent_values: recommended
profile:'''.format(other_header,other_header,version_yaml['os'],version_yaml['version'].split(" ")[0],version_yaml['platform'])

    if len(audit) != 0:

        full_baseline = full_baseline + '''
  - section: "Auditing"
    rules:'''
        audit.sort()

        for rule in audit:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)
    if len(auth) != 0:
        full_baseline = full_baseline + '''
  - section: "Authentication"
    rules:'''
        auth.sort()

        for rule in auth:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(sysprefs) != 0:
        full_baseline = full_baseline + '''
  - section: "SystemPreferences"
    rules:'''
        sysprefs.sort()

        for rule in sysprefs:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(system_settings) != 0:
        full_baseline = full_baseline + '''
  - section: "SystemSettings"
    rules:'''
        system_settings.sort()

        for rule in system_settings:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(icloud) != 0:
        full_baseline = full_baseline + '''
  - section: "iCloud"
    rules:'''
        icloud.sort()
        for rule in icloud:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(os_section) != 0 and version_yaml['platform'] == "iOS/iPadOS":
        full_baseline = full_baseline + '''
  - section: "ios"
    rules:'''
        os_section.sort()
        for rule in os_section:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(os_section) != 0 and version_yaml['platform'] == "macOS":
        full_baseline = full_baseline + '''
  - section: "macOS"
    rules:'''
        os_section.sort()
        for rule in os_section:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(pwpolicy) != 0:
        full_baseline = full_baseline + '''
  - section: "PasswordPolicy"
    rules:'''
        pwpolicy.sort()
        for rule in pwpolicy:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(inherent) != 0:
        full_baseline = full_baseline + '''
  - section: "Inherent"
    rules:'''
        inherent.sort()
        for rule in inherent:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(perm) != 0:
        full_baseline = full_baseline + '''
  - section: "Permanent"
    rules:'''
        perm.sort()
        for rule in perm:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    if len(na) != 0:
        full_baseline = full_baseline + '''
  - section: "not_applicable"
    rules:'''
        na.sort()
        for rule in na:
            full_baseline = full_baseline + '''
      - {}'''.format(rule)

    listofsupplementals = str()
    for supp_rule in glob.glob('../rules/supplemental/*.yaml',recursive=True):
        listofsupplementals = listofsupplementals + '''- {}
      '''.format(os.path.basename(supp_rule).split(".")[0])
    full_baseline = full_baseline + '''
  - section: "Supplemental"
    rules:
      {}
    '''.format(listofsupplementals)



    try:
        if os.path.isdir("../build/" + other_header.lower() + "/baseline/") == False:
            os.mkdir("../build/" + other_header.lower() + "/baseline")

        with open("../build/" + other_header.lower() + "/baseline/" + other_header.lower().replace(" ","_") + ".yaml",'w') as fw:
            fw.write(full_baseline)
            print(other_header.lower().replace(" ","_") + ".yaml baseline file created in build/" + other_header + "/baseline/")

        print("Move all of the folders in rules into the custom folder.")
    except:
        print("No controls mapped were found in rule files.")
if __name__ == "__main__":
    main()
