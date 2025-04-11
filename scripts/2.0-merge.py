#!/usr/bin/env python3

import glob
import os
import shutil
import yaml
import json
from collections import defaultdict

class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)

def str_presenter(dumper, data):
    """configures yaml for dumping multiline strings
    Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
    clean_data = data.replace(" \n", "\n")
    if clean_data.count('\n') > 0:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', clean_data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', clean_data)

yaml.add_representer(str, str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)    

def replace_na_with_none(data):
    if isinstance(data, dict):
        return {key: replace_na_with_none(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [replace_na_with_none(item) for item in data]
    else:
        return None if data == "N/A" else data
        
def remove_none_fields(data, parent_key=None):
    if isinstance(data, dict):
        # If the current dictionary has a key named 'platforms', leave it unchanged
        if parent_key == "platforms":
            return data
        
        result = {}
        for key, value in data.items():
            processed_value = remove_none_fields(value, key)  # Pass the key to track parent
            if processed_value is not None:
                result[key] = processed_value
        return result if result else None
    elif isinstance(data, list):
        # Process each item in the list
        processed_list = [remove_none_fields(item, parent_key) for item in data]
        # Remove None values and keep only valid items
        filtered_list = [item for item in processed_list if item is not None]
        return filtered_list if filtered_list else None
    else:
        # Return the value itself if it's not a dict or list
        return data if data is not None else None

def restructure_mobileconfig(rule_yaml):
    if "mobileconfig_info" in rule_yaml.keys() and rule_yaml['mobileconfig_info'] is not None:
        mobileconfig_info_obj = []
        for obj, data in rule_yaml["mobileconfig_info"].items():
            payload = {}
            payload["PayloadType"] = obj
            
            # generate list of keys for payload content
            payload_content = []
            for k, v in data.items():
                payload_content.append({k:v})
            payload["PayloadContent"] = payload_content

            mobileconfig_info_obj.append(payload)
        return mobileconfig_info_obj
    else:
        return {}


def get_introduced(payloadtype, key, os):
    version = "-1"
    for item in payloadtype['payloadkeys']:
        if item['key'] == key:
            try:
                if os in item['supportedOS'].keys():
                    version = item['supportedOS'][os]["introduced"]
                else:
                    # try go get introduced from payload parent
                    if os in payloadtype['payload']['supportedOS'].keys():
                        version = payloadtype['payload']['supportedOS'][os]["introduced"]
            except KeyError:
                # try go get introduced from payload parent
                if os in payloadtype['payload']['supportedOS'].keys():
                    version = payloadtype['payload']['supportedOS'][os]["introduced"]
    return version

def correct_result_key(result_dict):
    if isinstance(result_dict, str):
        return {}
    new_result = result_dict.copy()
    for k, v in result_dict.items():
        if k == "boolean" and isinstance(v, int):
            new_result["integer"] = v
            new_result.pop("boolean")
    return new_result

def remove_lines_containing(text, substring):
    lines = text.splitlines()
    filtered_lines = [line for line in lines if substring not in line]
    return '\n'.join(filtered_lines)

def cleanup_fix(fix_text):
    new_result = fix_text.strip().replace(" \n","\n")
    new_result = remove_lines_containing(new_result, "----")
    new_result = remove_lines_containing(new_result, "[source,bash]")

    return new_result
    
def main():
    files_created = []
    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    original_working_directory = os.getcwd()

    os.chdir(file_dir)
    build_path = os.path.join(parent_dir, 'rules')
    # build_path = os.path.join(parent_dir, 'build', 'rules', 'v2.0')
    if not (os.path.isdir(build_path)):
        try:
            os.makedirs(build_path)
        except OSError:
            print(f"Creation of the directory {build_path} failed")

    # load apple device-management profile for referencing
    apple_profiles = {}
    for apple_profile_file in glob.glob("../_work/apple/mdm/profiles/*.yaml"):
        with open(apple_profile_file) as p:
            apple_yam = yaml.load(p, Loader=yaml.SafeLoader)
            payloadtype = apple_yam["payload"]["payloadtype"]
            apple_profiles[payloadtype] = apple_yam
    
    # load odv.json for reference
    with open("../includes/odv.json") as o:
        odv_json = json.load(o)

    # load discussions.yaml for reference
    with open("../includes/discussions.yaml") as y:
        discussions_yaml = yaml.load(y, Loader=yaml.SafeLoader)

    # os_supported = ["sequoia", "sonoma", "ventura", "monterey", "big_sur", "catalina", "ios_18", "ios_17", "ios_16", "visionos_2.0"]
    os_supported = ["sequoia", "sonoma", "ventura", "ios_18", "ios_17", "ios_16", "visionos_2.0"]
    # for os_list in glob.glob("../_work/*"):
    #     os_supported.add(os_list.split("/")[2])

    all_rules = {}
    for os_version in os_supported:
        for os_rule in glob.glob("../_work/{}/rules/*/*".format(os_version)):
            if "supplemental" in os_rule:
                continue
            # Initialize list for the OS version if not already done
            if os_version not in all_rules:
                all_rules[os_version] = []

            with open(os_rule) as r:
                rule_yam = yaml.load(r, Loader=yaml.SafeLoader)
                rule_yaml = replace_na_with_none(rule_yam)
                # restructure the mobileconfig object
                new_mobileconfig = restructure_mobileconfig(rule_yaml)
                rule_yaml['mobileconfig_info'] = new_mobileconfig
                if "This is implemented by a Configuration Profile" in rule_yaml['fix']:
                    rule_yaml.pop("fix")
                all_rules[os_version].append(rule_yaml)

    # print(json.dumps(all_rules))
    id_to_os = defaultdict(list)
    for os_version, rules in all_rules.items():
        for rule in rules:
            id_to_os[rule["id"]].append(os_version)

    new_yaml = {}
    duplicates = {id_: os_versions for id_, os_versions in id_to_os.items() if len(os_versions) > 1}
    non_duplicates = {id_: os_versions[0] for id_, os_versions in id_to_os.items() if len(os_versions) == 1}
    
    try:
        if os.path.isfile(build_path) or os.path.islink(build_path):
            os.unlink(build_path)
        elif os.path.isdir(build_path):
            shutil.rmtree(build_path)
    except Exception as e:
        print("Failed to delete %s. Reason: %s" % (build_path, e))

    if non_duplicates:
        for id_, os_versions in non_duplicates.items():
            os_ = os_versions
            
            section = id_.split("_")[0]
            if section == "system":
                section = "system_settings"
            section_build_path = os.path.join(parent_dir,'rules', section)
            
            if not (os.path.isdir(section_build_path)):
                try:
                    os.makedirs(section_build_path)
                except OSError:
                    print(f"Creation of the directory {build_path} failed")      
            
            with open("../_work/{}/rules/{}/{}.yaml".format(os_,section,id_)) as r:
                rule_yam = yaml.load(r, Loader=yaml.SafeLoader)
                rule_yaml = replace_na_with_none(rule_yam)
                new_mobileconfig = restructure_mobileconfig(rule_yaml)
                rule_yaml['mobileconfig_info'] = new_mobileconfig
                if "This is implemented by a Configuration Profile" in rule_yaml['fix']:
                    rule_yaml.pop("fix")
                yaml_file_name = f"{rule_yaml['id']}.yaml"
                yaml_full_path = os.path.join(build_path, section, yaml_file_name)
                
            new_yaml = {
                        "id": rule_yaml['id'],
                        "title": rule_yaml['title'],
                        "discussion": rule_yaml['discussion'],
                        "references": {
                            "nist": {
                                "cce": {
                                    os_: rule_yaml['references']['cce']
                                }
                            }
                        },
                        "platforms": {
                        },
                        "tags": rule_yaml['tags']
                    }
            if "mobileconfig_info" in rule_yaml:
                new_yaml.update({"mobileconfig_info": rule_yaml['mobileconfig_info']})
            if "ddm_info" in rule_yaml:
                new_yaml.update({"ddm_info": rule_yaml['ddm_info']})
            if "odv" in rule_yaml:
                new_yaml.update({"odv": rule_yaml['odv']})
            if os_ == "sequoia" or os_ == "sonoma" or os_ == "ventura" or os_ == "monterey" or os_ == "big_sur" or os_ == "catalina":
                
        
                new_yaml['platforms'] = {"macOS": {}}
                new_yaml['platforms']['macOS'].update({os_:{}})
                
                new_yaml['platforms']['macOS'].update({"check": rule_yaml['check'].strip()})
                if "result" in rule_yaml:
                    new_yaml['platforms']['macOS'].update({"result": rule_yaml['result']})
                new_yaml['platforms']['macOS'].update({os_: {}})
                if "severity" in rule_yaml:
                    new_yaml['platforms']['macOS'][os_].update({"severity": rule_yaml['severity']})

                if "cis_lvl1" in rule_yaml['tags']:
                    # new_yaml['platforms']['macOS'][os_]['benchmarks'].append("cis_lvl1")
                    new_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["cis_lvl1"]})
                    new_yaml['tags'].remove("cis_lvl1")
                if "cis_lvl2" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['macOS'][os_]:
                        new_yaml['platforms']['macOS'][os_]['benchmarks'].append("cis_lvl2")                                
                    else:
                        new_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["cis_lvl2"]})
                    new_yaml['tags'].remove("cis_lvl2")
                if "stig" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['macOS'][os_]:
                        new_yaml['platforms']['macOS'][os_]['benchmarks'].append("disa_stig")                                
                    else:
                        new_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["disa_stig"]})
                    new_yaml['tags'].remove("stig")
                # print(new_yaml)
            if "ddm_info" in rule_yaml:
                new_yaml.update({"ddm_info": rule_yaml['ddm_info']})
                                
            if "vision" in os_:
                new_yaml['tags'].remove("visionos")
                new_yaml['platforms'] = {"visionOS": {}}
                
                new_yaml['platforms']['visionOS'].update({os_: {}})
                if "severity" in rule_yaml:
                    new_yaml['platforms']['visionOS'][os_].update({"severity": rule_yaml['severity']})
                if "supervised" in rule_yaml:
                    new_yaml['platforms']['visionOS'][os_].update({"supervised": rule_yaml['supervised']})

                

            if os_ == "ios_18" or os_ == "ios_17" or os_ == "ios_16":
                new_yaml['tags'].remove("ios")
                new_yaml['platforms'] = {"iOS": {}}
                
                new_yaml['platforms']['iOS'].update({os_: {}})
                if "severity" in rule_yaml:
                    new_yaml['platforms']['iOS'][os_].update({"severity": rule_yaml['severity']})
                if "supervised" in rule_yaml:
                    new_yaml['platforms']['iOS'][os_].update({"supervised": rule_yaml['supervised']})

                if "cis_lvl1_byod" in rule_yaml['tags']:
                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl1_byod"]})
                    new_yaml['tags'].remove("cis_lvl1_byod")
                if "cis_lvl2_byod" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl2_byod")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl2_byod"]})
                    new_yaml['tags'].remove("cis_lvl2_byod")
                if "cis_lvl1_enterprise" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl1_enterprise")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl1_enterprise"]})        
                    new_yaml['tags'].remove("cis_lvl1_enterprise")
                if "cis_lvl2_enterprise" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl2_enterprise")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl2_enterprise"]})
                    new_yaml['tags'].remove("cis_lvl2_enterprise")
                if "ios_stig" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("ios_stig")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["ios_stig"]})
                    new_yaml['tags'].remove("ios_stig")    
                if "ios_stig_byoad" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("ios_stig_byoad")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["ios_stig_byoad"]})
                    new_yaml['tags'].remove("ios_stig_byoad")    
                if "indigo_base" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("indigo_base")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["indigo_base"]})        
                    new_yaml['tags'].remove("indigo_base")
                if "indigo_high" in rule_yaml['tags']:
                    if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                        new_yaml['platforms']['iOS'][os_]['benchmarks'].append("indigo_high")                                
                    else:
                        new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["indigo_high"]})        
                    new_yaml['tags'].remove("indigo_high")


            if "800-53r5" in rule_yaml['references']:
                new_yaml['references']['nist'].update({
                    "800-53r5": rule_yaml['references']['800-53r5']
                })

            
            if "800-171r3" in rule_yaml['references']:
                new_yaml['references']['nist'].update({
                    "800-171r3": rule_yaml['references']['800-171r3']
                })
            if "cci" in rule_yaml['references']:
                new_yaml['references'].update({"disa": {}})
                new_yaml['references']['disa'].update({"cci": rule_yaml['references']['cci']})

            
            if "srg" in rule_yaml['references']:
                if "disa" in new_yaml['references']:
                    new_yaml['references']['disa'].update({"srg": rule_yaml['references']['srg']})
                else:
                    new_yaml['references'].update({"disa": {}})
                    new_yaml['references']['disa'].update({"srg": rule_yaml['references']['srg']})
            if "disa_stig" in rule_yaml['references']:
                if "disa" in new_yaml['references']:
                    new_yaml['references']['disa'].update({"disa_stig": {}})
                    new_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']['disa_stig']})
                else:
                    new_yaml['references'].update({"disa": {}})
                    new_yaml['references']['disa'].update({"disa_stig": {}})
                    new_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']['disa_stig']})
            if "sfr" in rule_yaml['references']:
                if "disa" in new_yaml['references']:
                    new_yaml['references']['disa'].update({"sfr": rule_yaml['references']['sfr']})
                else:
                    new_yaml['references'].update({"disa": {}})
                    new_yaml['references']['disa'].update({"sfr": rule_yaml['references']['sfr']})
            if "cmmc" in rule_yaml['references']:
                if "disa" in new_yaml['references']:
                    new_yaml['references']['disa'].update({"cmmc": rule_yaml['references']['cmmc']})
                else:
                    new_yaml['references'].update({"disa": {}})
                    new_yaml['references']['disa'].update({"cmmc": rule_yaml['references']['cmmc']})
            if "indigo" in rule_yaml['references']:
                if "bsi" in new_yaml['references']:
                    new_yaml['references']['bsi'].update({"indigo": {os_: rule_yaml['references']["indigo"]}})
                else:
                    new_yaml['references'].update({"bsi": {}})
                    new_yaml['references']['bsi'].update({"indigo": {os_: rule_yaml['references']["indigo"]}})
            if "cis" in rule_yaml['references']:
                if "benchmark" in rule_yaml['references']['cis']:
                    if "cis" in new_yaml['references']:
                        new_yaml['references']['cis'].update({"benchmark": {}})
                        new_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})
                    else:
                        new_yaml['references'].update({"cis": {}})
                        new_yaml['references']['cis'].update({"benchmark": {}})
                        new_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})
                if "controls v8" in rule_yaml['references']['cis']:
                    if "cis" in new_yaml['references']:
                        new_yaml['references']['cis'].update({"controls_v8": rule_yaml['references']['cis']['controls v8']})
                    else:
                        new_yaml['references'].update({"cis": {}})
                        new_yaml['references']['cis']['controls_v8'].update(rule_yaml['references']['cis']['controls v8'])
            
            with open(yaml_full_path, 'w') as wfile:
                # print(replace_na_with_none(new_yaml))
                if yaml_full_path not in files_created:
                    files_created.append(yaml_full_path)
                yaml.dump(new_yaml, wfile, Dumper=MyDumper, sort_keys=False, width=float("inf")) 

    if duplicates:
        rules_to_review = []

        # print("Duplicate IDs and their associated OS versions:")
        for id_, os_versions in duplicates.items():
            
            # print(f"ID: {id_}, OS Versions: {os_versions}")
            
            os_specifics = {}
            for os_ in os_versions:
                section = id_.split("_")[0]
                if section == "system":
                    section = "system_settings"
                section_build_path = os.path.join(parent_dir, 'rules', section)
                if not (os.path.isdir(section_build_path)):
                    try:
                        os.makedirs(section_build_path)
                    except OSError:
                        print(f"Creation of the directory {build_path} failed")      
                
                with open("../_work/{}/rules/{}/{}.yaml".format(os_,section,id_)) as r:
                    rule_yam = yaml.load(r, Loader=yaml.SafeLoader)
                    rule_yaml = replace_na_with_none(rule_yam)
                    new_mobileconfig = restructure_mobileconfig(rule_yaml)
                    rule_yaml['mobileconfig_info'] = new_mobileconfig
                    if "This is implemented by a Configuration Profile" in rule_yaml['fix']:
                        rule_yaml.pop("fix")
                    os_specifics.update({os_: {}})
                    
                    # if "discussion" in rule_yaml:
                    #     os_specifics[os_].update({"discussion":rule_yaml['discussion'].strip().replace(" \n","\n")})
                    if "check" in rule_yaml: 
                        os_specifics[os_].update({"check":rule_yaml['check'].strip().replace(" \n","\n")})
                    else:
                        os_specifics[os_].update({"check":""})
                    if "result" in rule_yaml:
                        rule_yaml['result'] = correct_result_key(rule_yaml['result'])
                        os_specifics[os_].update({"result":rule_yaml['result']})
                    else:
                        os_specifics[os_].update({"result":""})
                    if "fix" in rule_yaml:
                        rule_yaml['fix'] = cleanup_fix(rule_yaml['fix'])
                        os_specifics[os_].update({"fix":rule_yaml['fix']})
                    else:
                        os_specifics[os_].update({"fix":""})
                    if "mobileconfig" in rule_yaml:
                        os_specifics[os_].update({"mobileconfig":rule_yaml['mobileconfig_info']})
                    else:
                        os_specifics[os_].update({"mobileconfig":""})
                    
                    yaml_file_name = f"{rule_yaml['id']}.yaml"
                    yaml_full_path = os.path.join(build_path, section, yaml_file_name)
                     
                    if os.path.exists(yaml_full_path):

                     
                        with open(yaml_full_path) as ryam:
                            
                            update_rule_yam = yaml.load(ryam, Loader=yaml.SafeLoader)
                            update_rule_yaml = replace_na_with_none(update_rule_yam)
                            
                            update_rule_yaml['references']['nist']['cce'].update({os_: rule_yaml['references']['cce']})
                
                            if "odv" in rule_yaml:
                                if "odv" in update_rule_yaml:                                            
                                    for k,v in rule_yaml['odv'].items():                                                
                                        
                                        update_rule_yaml['odv'].update({k:v})
                                else:
                                    update_rule_yaml.update("odv", rule_yaml['odv'])
                            
                            if "indigo" in rule_yaml['references']:
                                if "bsi" in update_rule_yaml['references']:
                                    if "indigo" in update_rule_yaml['references']['bsi']:
                                        update_rule_yaml['references']['bsi']['indigo'].update({os_: rule_yaml['references']["indigo"]})
                                    else:
                                        update_rule_yaml['references']['bsi'].update({"indigo":{}})
                                        update_rule_yaml['references']['bsi']['indigo'].update({os_: rule_yaml['references']["indigo"]})
                                else:
                                    update_rule_yaml['references'].update({"bsi":{}})
                                    update_rule_yaml['references']['bsi'].update({"indigo":{}})
                                    update_rule_yaml['references']['bsi']['indigo'].update({os_: rule_yaml['references']['indigo']})

                            if "cis" in rule_yaml['references']:
                                if "benchmark" in rule_yaml['references']['cis']:
                                    if "cis" in update_rule_yaml['references']:
                                        if "benchmark" in update_rule_yaml['references']['cis']:
                                            update_rule_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})
                                        else:
                                            update_rule_yaml['references']['cis'].update({"benchmark":{}})
                                            update_rule_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})
                                    else:
                                        update_rule_yaml['references'].update({"cis":{}})
                                        update_rule_yaml['references']['cis'].update({"benchmark":{}})
                                        update_rule_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})

                            if "disa_stig" in rule_yaml['references']:
                                if "disa" in update_rule_yaml['references']:
                                    if "disa_stig" in update_rule_yaml['references']['disa']:
                                        update_rule_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']["disa_stig"]})
                                    else:
                                        update_rule_yaml['references']['disa'].update({"disa_stig":{}})
                                        update_rule_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']["disa_stig"]})
                                else:
                                    update_rule_yaml['references'].update({"disa":{}})
                                    update_rule_yaml['references']['disa'].update({"disa_stig":{}})
                                    update_rule_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']['disa_stig']})

                            for new_tag in rule_yaml['tags']:
                                if new_tag in update_rule_yaml['tags']:
                                    continue
                                if "cis_lvl1" in new_tag or "cis_lvl2" in new_tag or "stig" in new_tag or new_tag == "ios" or "indigo" in new_tag or "none" in new_tag:
                                    continue
                                if "ios" in new_tag or "visionos" in new_tag:
                                    continue
                                if "800-53r4_low" in new_tag or "800-53r4_moderate" in new_tag or "800-53r4_high" in new_tag:
                                    continue
                                update_rule_yaml['tags'].append(new_tag)
                            
                            if os_ == "visionos_2.0" or "ios" in os_:
                                # print("HELLO")
                                # print(os_)
                                if os_ == "visionos_2.0":
                                    # print("hello vision")
                                    update_rule_yaml['platforms'].update({"visionOS":{}})
                                    update_rule_yaml['platforms']['visionOS'].update({os_: {}})

                                    if "supervised" in rule_yaml:
                                        update_rule_yaml['platforms']['visionOS'][os_].update({"supervised":rule_yaml['supervised']})
                                    # print(update_rule_yaml)
                                else:
                                    
                                    if 'iOS' not in update_rule_yaml['platforms']:
                                        update_rule_yaml['platforms'].update({"iOS":{}})

                                    update_rule_yaml['platforms']['iOS'].update({os_: {}})

                                    if "severity" in rule_yaml:
                                        update_rule_yaml['platforms']['iOS'][os_].update({"severity":rule_yaml['severity']})
                                    
                                    if "supervised" in rule_yaml:
                                        update_rule_yaml['platforms']['iOS'][os_].update({'supervised':rule_yaml['supervised']})
                                    
                                    if "cis_lvl1_byod" in rule_yaml['tags']:
                                        update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl1_byod"]})
                                        if "cis_lvl1_byod" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("cis_lvl1_byod")
                                        
                                    if "cis_lvl2_byod" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl2_byod")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl2_byod"]})
                                        
                                        if "cis_lvl2_byod" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("cis_lvl2_byod")
                                        
                                    if "cis_lvl1_enterprise" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl1_enterprise")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl1_enterprise"]})        
                                        if "cis_lvl1_enterprise" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("cis_lvl1_enterprise")
                                    if "cis_lvl2_enterprise" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl2_enterprise")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl2_enterprise"]})
                                        
                                        if "cis_lvl2_enterprise" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("cis_lvl2_enterprise")
                                    if "ios_stig" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("ios_stig")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["ios_stig"]})
                                        
                                        if "ios_stig" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("ios_stig")  
                                    if "ios_stig_byoad" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("ios_stig_byoad")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["ios_stig_byoad"]})
                                        
                                        if "ios_stig_byoad" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("ios_stig_byoad") 
                                    if "indigo_base" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("indigo_base")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["indigo_base"]})        
                                        
                                        if "indigo_base" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("indigo_base") 
                                    if "indigo_high" in rule_yaml['tags']:
                                        if 'benchmarks' in update_rule_yaml['platforms']['iOS'][os_]:
                                            update_rule_yaml['platforms']['iOS'][os_]['benchmarks'].append("indigo_high")                                
                                        else:
                                            update_rule_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["indigo_high"]})        
                                        
                                        if "indigo_high" in update_rule_yaml['tags']:
                                            update_rule_yaml['tags'].remove("indigo_high") 


                                        
                            if os_ == "sequoia" or os_ == "sonoma" or os_ == "ventura" or os_ == "monterey" or os_ == "big_sur" or os_ == "catalina":
                                if "macOS" not in update_rule_yaml['platforms']:
                                    update_rule_yaml['platforms'].update({"macOS": {}})
                                    update_rule_yaml['platforms']['macOS'].update({os_: {}})
                                else:
                                    if os_ not in update_rule_yaml['platforms']['macOS']:
                                        update_rule_yaml['platforms']['macOS'].update({os_: {}})
                            

                                if "severity" in rule_yaml:
                                    update_rule_yaml['platforms']['macOS'][os_].update({"severity": rule_yaml['severity']})

                                if "cis_lvl1" in rule_yaml['tags']:
                                    update_rule_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["cis_lvl1"]})
                                    
                                if "cis_lvl2" in rule_yaml['tags']:
                                    if 'benchmarks' in update_rule_yaml['platforms']['macOS'][os_]:
                                        update_rule_yaml['platforms']['macOS'][os_]['benchmarks'].append("cis_lvl2")                                
                                    else:
                                        update_rule_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["cis_lvl2"]})
                                    
                                if "stig" in rule_yaml['tags']:
                                    if 'benchmarks' in update_rule_yaml['platforms']['macOS'][os_]:
                                        update_rule_yaml['platforms']['macOS'][os_]['benchmarks'].append("disa_stig")                                
                                    else:
                                        update_rule_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["disa_stig"]})
                                
                        

                                if "check" not in update_rule_yaml['platforms']['macOS']:
                                    if "check" in rule_yaml:
                                        
                                        # update_rule_yaml['platforms']['macOS'].update({"check", rule_yaml['check']})
                                        update_rule_yaml['platforms']['macOS'].update({"check": rule_yaml['check'].strip().replace(" \n","\n")})
                                        # update_rule_yaml['platforms']['macOS'].update({"result", rule_yaml['result']})
                                        update_rule_yaml['platforms']['macOS'].update({"result": rule_yaml['result']})
                                if "fix" not in update_rule_yaml['platforms']['macOS']:
                                    if "fix" in rule_yaml:
                                        rule_yaml['fix'] = cleanup_fix(rule_yaml['fix'])
                                        update_rule_yaml['platforms']['macOS'].update({"fix": rule_yaml['fix']})

                                    
                            if "ddm_info" in rule_yaml:
                                update_rule_yaml.update({"ddm_info": rule_yaml['ddm_info']})

                            with open(yaml_full_path, 'w') as wfile:
                                yaml.dump(update_rule_yaml, wfile, Dumper=MyDumper, sort_keys=False, width=float("inf")) 
                    else:
                        
                        new_yaml = {
                            "id": rule_yaml['id'],
                            "title": rule_yaml['title'],
                            "discussion": rule_yaml['discussion'],
                            "references": {
                                "nist": {
                                    "cce": {
                                        os_: rule_yaml['references']['cce']
                                    }
                                }
                            },
                            "platforms": {
                            },
                            "tags": rule_yaml['tags']
                        }

                        if "none" in new_yaml['tags']:
                            new_yaml['tags'].remove("none")

                        if "800-53r4_low" in new_yaml['tags']:
                            new_yaml['tags'].remove("800-53r4_low")
                        if "800-53r4_moderate" in new_yaml['tags']:
                            new_yaml['tags'].remove("800-53r4_moderate")
                        if "800-53r4_high" in new_yaml['tags']:
                            new_yaml['tags'].remove("800-53r4_high")
                        
                        if "mobileconfig_info" in rule_yaml:
                            new_yaml.update({"mobileconfig_info": rule_yaml['mobileconfig_info']})
                        if "ddm_info" in rule_yaml:
                            new_yaml.update({"ddm_info": rule_yaml['ddm_info']})
                        if "odv" in rule_yaml:
                            new_yaml.update({"odv": rule_yaml['odv']})
                        if os_ == "sequoia" or os_ == "sonoma" or os_ == "ventura" or os_ == "monterey" or os_ == "big_sur" or os_ == "catalina":
                            
                    
                            new_yaml['platforms'] = {"macOS": {}}
                            
                            new_yaml['platforms']['macOS'].update({"check": rule_yaml['check'].strip()})
                            if "result" in rule_yaml:
                                rule_yaml['result'] = correct_result_key(rule_yaml['result'])
                                new_yaml['platforms']['macOS'].update({"result": rule_yaml['result']})
                            new_yaml['platforms']['macOS'].update({os_: {}})
                            if "severity" in rule_yaml:
                                new_yaml['platforms']['macOS'][os_].update({"severity": rule_yaml['severity']})

                            if "cis_lvl1" in rule_yaml['tags']:
                                # new_yaml['platforms']['macOS'][os_]['benchmarks'].append("cis_lvl1")
                                new_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["cis_lvl1"]})
                                new_yaml['tags'].remove("cis_lvl1")
                            if "cis_lvl2" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['macOS'][os_]:
                                    new_yaml['platforms']['macOS'][os_]['benchmarks'].append("cis_lvl2")                                
                                else:
                                    new_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["cis_lvl2"]})
                                new_yaml['tags'].remove("cis_lvl2")
                            if "stig" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['macOS'][os_]:
                                    new_yaml['platforms']['macOS'][os_]['benchmarks'].append("disa_stig")                                
                                else:
                                    new_yaml['platforms']['macOS'][os_].update({ "benchmarks": ["disa_stig"]})
                                new_yaml['tags'].remove("stig")
                            # print(new_yaml)
                        if os_ == "ios_18" or os_ == "ios_17" or os_ == "ios_16":
                            new_yaml['tags'].remove("ios")
                            new_yaml['platforms'].update({"iOS":{}})
                            new_yaml['platforms']['iOS'].update({os_: {}})
                            
                            if "severity" in rule_yaml:
                                new_yaml['platforms']['iOS'][os_].update({"severity": rule_yaml['severity']})
                            if "supervised" in rule_yaml:
                                new_yaml['platforms']['iOS'][os_].update({"supervised": rule_yaml['supervised']})

                            if "cis_lvl1_byod" in rule_yaml['tags']:
                                new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl1_byod"]})
                                new_yaml['tags'].remove("cis_lvl1_byod")
                            if "cis_lvl2_byod" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl2_byod")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl2_byod"]})
                                new_yaml['tags'].remove("cis_lvl2_byod")
                            if "cis_lvl1_enterprise" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl1_enterprise")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl1_enterprise"]})        
                                new_yaml['tags'].remove("cis_lvl1_enterprise")
                            if "cis_lvl2_enterprise" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("cis_lvl2_enterprise")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["cis_lvl2_enterprise"]})
                                new_yaml['tags'].remove("cis_lvl2_enterprise")
                            if "ios_stig" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("ios_stig")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["ios_stig"]})
                                new_yaml['tags'].remove("ios_stig")    
                            if "ios_stig_byoad" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("ios_stig_byoad")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["ios_stig_byoad"]})
                                new_yaml['tags'].remove("ios_stig_byoad")    
                            if "indigo_base" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("indigo_base")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["indigo_base"]})        
                                new_yaml['tags'].remove("indigo_base")
                            if "indigo_high" in rule_yaml['tags']:
                                if 'benchmarks' in new_yaml['platforms']['iOS'][os_]:
                                    new_yaml['platforms']['iOS'][os_]['benchmarks'].append("indigo_high")                                
                                else:
                                    new_yaml['platforms']['iOS'][os_].update({ "benchmarks": ["indigo_high"]})        
                                new_yaml['tags'].remove("indigo_high")
                            

                        if os_ == "visionos_2.0":
                            new_yaml['tags'].remove("visionos")
                            new_yaml['platforms'].update({"visionOS": {}})
                            
                            new_yaml['platforms']['visionOS'].update({os_: {}})

                            if "supervised" in rule_yaml:
                                new_yaml['platforms']['visionOS'][os_].update({"supervised": rule_yaml['supervised']})

                        if "800-53r5" in rule_yaml['references']:
                            new_yaml['references']['nist'].update({
                                "800-53r5": rule_yaml['references']['800-53r5']
                            })

                        
                        if "800-171r3" in rule_yaml['references']:
                            new_yaml['references']['nist'].update({
                                "800-171r3": rule_yaml['references']['800-171r3']
                            })
                        if "cci" in rule_yaml['references']:
                            new_yaml['references'].update({"disa": {}})
                            new_yaml['references']['disa'].update({"cci": rule_yaml['references']['cci']})

                        
                        if "srg" in rule_yaml['references']:
                            if "disa" in new_yaml['references']:
                                new_yaml['references']['disa'].update({"srg": rule_yaml['references']['srg']})
                            else:
                                new_yaml['references'].update({"disa": {}})
                                new_yaml['references']['disa'].update({"srg": rule_yaml['references']['srg']})
                        if "disa_stig" in rule_yaml['references']:
                            if "disa" in new_yaml['references']:
                                new_yaml['references']['disa'].update({"disa_stig": {}})
                                new_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']['disa_stig']})
                            else:
                                new_yaml['references'].update({"disa": {}})
                                new_yaml['references']['disa'].update({"disa_stig": {}})
                                new_yaml['references']['disa']['disa_stig'].update({os_: rule_yaml['references']['disa_stig']})
                        if "sfr" in rule_yaml['references']:
                            if "disa" in new_yaml['references']:
                                new_yaml['references']['disa'].update({"sfr": rule_yaml['references']['sfr']})
                            else:
                                new_yaml['references'].update({"disa": {}})
                                new_yaml['references']['disa'].update({"sfr": rule_yaml['references']['sfr']})
                        if "cmmc" in rule_yaml['references']:
                            if "disa" in new_yaml['references']:
                                new_yaml['references']['disa'].update({"cmmc": rule_yaml['references']['cmmc']})
                            else:
                                new_yaml['references'].update({"disa": {}})
                                new_yaml['references']['disa'].update({"cmmc": rule_yaml['references']['cmmc']})
                        
                        if "cis" in rule_yaml['references']:
                            if "benchmark" in rule_yaml['references']['cis']:
                                if "cis" in new_yaml['references']:
                                    new_yaml['references']['cis'].update({"benchmark": {}})
                                    new_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})
                                else:
                                    new_yaml['references'].update({"cis": {}})
                                    new_yaml['references']['cis'].update({"benchmark": {}})
                                    new_yaml['references']['cis']['benchmark'].update({os_: rule_yaml['references']['cis']['benchmark']})
                            if "controls v8" in rule_yaml['references']['cis']:
                                if "cis" in new_yaml['references']:
                                    new_yaml['references']['cis'].update({"controls_v8": rule_yaml['references']['cis']['controls v8']})
                                else:
                                    new_yaml['references'].update({"cis": {}})
                                    new_yaml['references']['cis']['controls_v8'].update(rule_yaml['references']['cis']['controls v8'])
                        
                        with open(yaml_full_path, 'w') as wfile:
                            yaml.dump(new_yaml, wfile, Dumper=MyDumper, sort_keys=False, width=float("inf")) 
       
            # if os_ == "sequoia" or os_ == "sonoma" or os_ == "ventura" or os_ == "monterey" or os_ == "big_sur" or os_ == "catalina":
            platforms = list(os_specifics.keys())

            # for p in platforms:              
            #     base_os = platforms[0]
            #     if base_os == "ios_16" or base_os == "ios_17" or base_os == "ios_18" or base_os == "visionos_2.0":
            #         base_os = p
            #     if base_os != "ios_16" or base_os != "ios_17" or base_os != "ios_18" or base_os != "visionos_2.0":
            #         break
            base_os = platforms[0]
            base_value = os_specifics[base_os]['mobileconfig']
            
            configprofile_differences = {}

            for platform in platforms[1:]:
                if os_specifics[platform]['mobileconfig'] != base_value:
                    configprofile_differences[platform] = os_specifics[platform]['mobileconfig']
            # print(rule_yaml['id'])
            # print(configprofile_differences)


            # discussion_differences = {}
            # base_value = os_specifics[base_os]['discussion']
            # for platform in platforms[1:]:
            #     if os_specifics[platform]['discussion'] != base_value:
            #         discussion_differences[base_os] = base_value
            #         discussion_differences[platform] = os_specifics[platform]['discussion']


            # if discussion_differences:
            #     print("+++++++++++++++++++")
            #     print(rule_yaml['id'])
            #     print(json.dumps(discussion_differences,indent=4))
            #     print()
            

            for key in ['check', 'fix', 'result', 'mobileconfig']:

                base_os = platforms[0]
                for p in platforms:              
                    base_os = platforms[0]
                    if base_os == "ios_16" or base_os == "ios_17" or base_os == "ios_18" or base_os == "visionos_2.0":
                        base_os = p
                    if base_os != "ios_16" or base_os != "ios_17" or base_os != "ios_18" or base_os != "visionos_2.0":
                        break
                base_value = os_specifics[base_os][key]
                differences = {}
                
                
                
                for platform in platforms[1:]:
                    if ("ios" in platform or "vision" in platform and key == "check") or ("ios" in platform or "vision" in platform and key == "result"):
                        continue
                    if os_specifics[platform][key] != base_value:
                        # print(rule_yaml['id'])
                        # print(base_value)
                        # print(base_os)
                        
                        differences[platform] = os_specifics[platform][key]
                    if key == "result":
                        differences[platform] = os_specifics[platform][key]
                with open(yaml_full_path) as ryam:
                    differences_yam = yaml.load(ryam, Loader=yaml.SafeLoader)
                    differences_yaml = replace_na_with_none(differences_yam)

                if differences:
                    # print(os_specifics)
                    for operating_sys,value in os_specifics.items():
                        
                        if "vision" in operating_sys or "ios" in operating_sys:
                            continue
                        
                        if key == "check":
                            if value['check'] == " " or value['check'] == "":
                                continue
                            # print(base_os)
                            
                            # print(differences)
                            # print("++++++++++++")
                            differences_yaml['platforms']['macOS'][operating_sys].update({"check": value['check']})
                        if key == "result":
                            if value['result'] == " " or value['result'] == "":
                                continue
                            # if "result" in differences_yaml['platforms']['macOS']:
                                # if operating_sys != "sequoia":
                            differences_yaml['platforms']['macOS'][operating_sys].update({"result": value['result']})
                            
                        if key == "fix":
                            differences_yaml['platforms']['macOS'][operating_sys].update({"fix": value['fix']})
                            
                        # if key == "mobileconfig":
                        #     differences_yaml['platforms']['macOS'][operating_sys].update({"mobileconfig": value})
                    if "macOS" in differences_yaml['platforms']:
                        if key == "result":
                            if differences_yaml['id'] not in rules_to_review:
                                rules_to_review.append(differences_yaml['id'])
                            # differences_yaml['platforms']['macOS']['result'] = "$OS_VALUE"
                        if key == "check":
                            if differences_yaml['id'] not in rules_to_review:
                                rules_to_review.append(differences_yaml['id'])
                            # differences_yaml['platforms']['macOS']['check'] = "$OS_VALUE"
                        if key == "fix":
                            if differences_yaml['id'] not in rules_to_review:
                                rules_to_review.append(differences_yaml['id'])
                            # differences_yaml['platforms']['macOS']['fix'] = "$OS_VALUE"
                # if key == "mobileconfig":
                #     differences_yaml['mobileconfig_info'] = "$OS_VALUE"
                
                if configprofile_differences and key == 'mobileconfig':
                    for operating_sys,value in os_specifics.items():
                        

                        if operating_sys == "visionos_2.0":
                            differences_yaml['platforms']['visionOS'][operating_sys].update({"mobileconfig_info": value['mobileconfig']})
                        elif "ios" in operating_sys:
                            differences_yaml['platforms']['iOS'][operating_sys].update({"mobileconfig_info": value['mobileconfig']})
                        elif os_ == "sequoia" or os_ == "sonoma" or os_ == "ventura" or os_ == "monterey" or os_ == "big_sur" or os_ == "catalina":

                            differences_yaml['platforms']['macOS'][operating_sys].update({"mobileconfig_info": value['mobileconfig']})
                        # print(differences_yaml['id'])
                        # print(value['mobileconfig'])
                        # print(operating_sys)
                    #differences_yaml['mobileconfig_info'] = "$OS_VALUE"

                with open(yaml_full_path, 'w') as wfile:
                    yaml.dump(differences_yaml, wfile, Dumper=MyDumper, sort_keys=False, width=float("inf")) 


            with open(yaml_full_path, 'r') as r_again:
                re_order_ya = yaml.load(r_again, Loader=yaml.SafeLoader)
                re_order_yam = replace_na_with_none(re_order_ya)
            
            yaml_key_order = ['id', 'title', 'discussion', 'references', 'platforms', 'odv', 'tags', 'mobileconfig_info', 'ddm_info']
            ordered_keys = sorted(re_order_yam.keys(), key=lambda k: (yaml_key_order.index(k) if k in yaml_key_order else len(yaml_key_order), k))
            re_order_yam = {key: re_order_yam[key] for key in ordered_keys}
            
            priority_os_order = ['sequoia', 'sonoma', 'ventura', 'monterey', 'big_sur', 'catalina', 'ios_18', 'ios_17', 'ios_16', 'visionos_2.0']
            ordered_keys = sorted(re_order_yam['references']['nist']['cce'].keys(), key=lambda k: (priority_os_order.index(k) if k in priority_os_order else len(priority_os_order), k))
            re_order_yam['references']['nist']['cce'] = {key: re_order_yam['references']['nist']['cce'][key] for key in ordered_keys}
            if "disa" in re_order_yam['references']:
                if "disa_stig" in re_order_yam['references']['disa']:
                    ordered_keys = sorted(re_order_yam['references']['disa']['disa_stig'].keys(), key=lambda k: (priority_os_order.index(k) if k in priority_os_order else len(priority_os_order), k))
                    re_order_yam['references']['disa']['disa_stig'] = {key: re_order_yam['references']['disa']['disa_stig'][key] for key in ordered_keys}
            if "cis" in re_order_yam['references']:
                if "benchmark" in re_order_yam['references']['cis']:
                    ordered_keys = sorted(re_order_yam['references']['cis']['benchmark'].keys(), key=lambda k: (priority_os_order.index(k) if k in priority_os_order else len(priority_os_order), k))
                    re_order_yam['references']['cis']['benchmark'] = {key: re_order_yam['references']['cis']['benchmark'][key] for key in ordered_keys}

            priority_macos_order = ['check','result','fix','sequoia','sonoma','ventura', 'monterey', 'big_sur', 'catalina']
            priority_ios_order = ['ios_18', 'ios_17', 'ios_16']
            platform_order = ['macOS', 'iOS', 'visionOS']
            # print(re_order_yam)
            ordered_keys = sorted(re_order_yam['platforms'].keys(), key=lambda k: (platform_order.index(k) if k in platform_order else len(platform_order), k))
            re_order_yam['platforms'] = {key: re_order_yam['platforms'][key] for key in ordered_keys}

            if "macOS" in re_order_yam['platforms']:
                ordered_keys = sorted(re_order_yam['platforms']['macOS'].keys(), key=lambda k: (priority_macos_order.index(k) if k in priority_macos_order else len(priority_macos_order), k))
                re_order_yam['platforms']['macOS'] = {key: re_order_yam['platforms']['macOS'][key] for key in ordered_keys}
            if "iOS" in re_order_yam['platforms']:
                
                ordered_keys = sorted(re_order_yam['platforms']['iOS'].keys(), key=lambda k: (priority_ios_order.index(k) if k in priority_ios_order else len(priority_ios_order), k))
                re_order_yam['platforms']['iOS'] = {key: re_order_yam['platforms']['iOS'][key] for key in ordered_keys}
            

            if "mobileconfig_info" in re_order_yam:
                if re_order_yam['mobileconfig_info'] == None:
                    re_order_yam.pop('mobileconfig_info')

            
            with open(yaml_full_path, 'w') as wfile:
                if yaml_full_path not in files_created:
                    files_created.append(yaml_full_path)
                yaml.dump(re_order_yam, wfile, Dumper=MyDumper, sort_keys=False, width=float("inf")) 

    print("review the following rules across branches for minor differences")
    for r in rules_to_review:
        print(r)


    unknown_keys = []
    odv_rules = []
    for file in files_created:
        with open(file) as newyamlfile:
            _yaml = yaml.load(newyamlfile, Loader=yaml.SafeLoader)
            if "srg" in _yaml['tags']:
                _yaml['tags'].remove("srg")
            if "visionos" in _yaml['tags']:
                _yaml['tags'].remove("visionos")
     
            _yaml = replace_keys_by_path(_yaml)

            # update discussions
            for d in discussions_yaml:
                if _yaml['id'] == d['id']:
                    _yaml['discussion'] = d['discussion']

            # move permanent, inherant check/fix info into discussions
            if "macOS" in _yaml['platforms'] and "check" in _yaml['platforms']['macOS']:
                if "requirement is NA" in _yaml['platforms']['macOS']['check'] or "inherently" in _yaml['platforms']['macOS']['check'] or "does not meet finding" in _yaml['platforms']['macOS']['check'] or "technology does support this requirement" in _yaml['platforms']['macOS']['check'] or "technology partially supports" in _yaml['platforms']['macOS']['check']:
                    check_text = _yaml['platforms']['macOS']['check']
                    fix_text = _yaml['platforms']['macOS']['fix']
                    _yaml['platforms']['macOS'].pop('check')
                    _yaml['platforms']['macOS'].pop('fix')
                    _yaml['discussion'] += f'\nNOTE: {check_text}'
                
                # clean up any redundent checks
                
                for _os in _yaml['platforms']['macOS'].keys():
                    
                    if _os == "check" or _os == "fix" or _os == "result":
                        continue

                    _yaml['platforms']['macOS'][_os]['assessment'] = {}
                    
                    if "check" in _yaml['platforms']['macOS'][_os]:
                        if _yaml['platforms']['macOS']['check'] == _yaml['platforms']['macOS'][_os]['check']:
                            print(f'{_yaml["id"]} - main check matches check of {_os}')
                            _yaml['platforms']['macOS'][_os].pop('check')
                            # if "result" in _yaml['platforms']['macOS'][_os]:
                            #     _yaml['platforms']['macOS'][_os].pop('result')
                        # move it into compliance object
                        
                    if "check" in _yaml['platforms']['macOS'][_os]:
                        _yaml['platforms']['macOS'][_os]['assessment']['check'] = {}
                        _yaml['platforms']['macOS'][_os]['assessment']['check']['shell'] = _yaml['platforms']['macOS'][_os]['check']
                        _yaml['platforms']['macOS'][_os].pop('check')
                    if "result" in _yaml['platforms']['macOS'][_os] and "check" in _yaml['platforms']['macOS'][_os]['assessment']:
                        _yaml['platforms']['macOS'][_os]['assessment']['check']['result'] = _yaml['platforms']['macOS'][_os]['result']
                        _yaml['platforms']['macOS'][_os].pop('result')
                    elif "result" in _yaml['platforms']['macOS'][_os]:
                        _yaml['platforms']['macOS'][_os].pop('result')

                    if "fix" in _yaml['platforms']['macOS'][_os]:
                        if _yaml['platforms']['macOS']['fix'] == _yaml['platforms']['macOS'][_os]['fix']:
                            print(f'{_yaml["id"]} - main fix matches fix of {_os}')
                            _yaml['platforms']['macOS'][_os].pop('fix')
                        
                    # move it into compliance object
                    if "fix" in _yaml['platforms']['macOS'][_os]:
                        _yaml['platforms']['macOS'][_os]['assessment']['fix'] = _yaml['platforms']['macOS'][_os]['fix']
                        _yaml['platforms']['macOS'][_os].pop('fix')
                    
                    if _yaml['platforms']['macOS'][_os]['assessment'] == {}:
                        _yaml['platforms']['macOS'][_os].pop('assessment')
                
                _yaml['platforms']['macOS']['assessment'] = {}
                if "check" in _yaml['platforms']['macOS']:
                    _yaml['platforms']['macOS']['assessment']['check'] = {}
                    _yaml['platforms']['macOS']['assessment']['check']['shell'] = _yaml['platforms']['macOS']['check']
                    _yaml['platforms']['macOS'].pop('check')

                if "result" in _yaml['platforms']['macOS']:
                    _yaml['platforms']['macOS']['assessment']['check']['result'] = _yaml['platforms']['macOS']['result']
                    _yaml['platforms']['macOS'].pop('result')
                
                if "fix" in _yaml['platforms']['macOS']:
                    _yaml['platforms']['macOS']['assessment']['fix'] = _yaml['platforms']['macOS']['fix']
                    _yaml['platforms']['macOS'].pop('fix')
                


            # add the introduced data here 
            if "mobileconfig_info" in _yaml.keys():
                os_list = list(_yaml['platforms'].keys())

                for mobileconfig_payload in _yaml['mobileconfig_info']:
                    payloadtype = mobileconfig_payload['PayloadType']
                    payloadkeys = mobileconfig_payload['PayloadContent']
                    # just get first key, since we can't identify multiple introduce versions
                    payloadkey = next(iter(payloadkeys[0]))

                    for opsys in os_list:
                        if payloadtype in apple_profiles.keys():
                            version = get_introduced(apple_profiles[payloadtype], payloadkey, opsys)
                            if version == "-1":
                                unknown_keys.append(payloadkey)
                            _yaml['platforms'][opsys]['introduced'] = version
                        else:
                            unknown_keys.append(payloadkey)
                            _yaml['platforms'][opsys]['introduced'] = "-1"
                
                for platform in _yaml['platforms'].keys():
                    for _os in _yaml['platforms'][platform].keys():
                        if _os == "check" or _os == "fix" or _os == "result" or _os == "introduced":
                            continue
                        if "mobileconfig_info" in _yaml['platforms'][platform][_os].keys() and _yaml['mobileconfig_info'] == _yaml['platforms'][platform][_os]['mobileconfig_info']:
                            _yaml['platforms'][platform][_os].pop("mobileconfig_info")


            if "odv" in _yaml.keys():
                description = _yaml['odv']['hint']
                datatype = None
                validation = None
                for r in odv_json:
                    if r["ruleId"] == _yaml['id']:
                        datatype = r["type"]
                        if "note" in r.keys():
                            description = r["note"]
                        if "validation" in r.keys():
                            validation = r["validation"]

                
                _yaml['odv']['hint'] = {}
                _yaml['odv']['hint']['datatype'] = datatype
                _yaml['odv']['hint']['description'] = description
                _yaml['odv']['hint']['validation'] = validation
                odv_rules.append(_yaml['id'])


          
            
                
    
        with open(file, "w") as nf:
            yaml.dump(remove_none_fields(_yaml), nf, Dumper=MyDumper, sort_keys=False, width=float("inf")) 

    print("\n\nthe following keys are not found in apple git")
    for k in unknown_keys:
        print(k)   

    print("\n\nthe following rules have ODVs to update")
    for k in odv_rules:
        print(k)   
     
def replace_keys_by_path(data, path=None):
    if path is None:
        path = []

    if isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            current_path = path + [k]
            new_k = k
            if k == 'visionos_2.0':
                if path == ['references', 'nist', 'cce']:
                    new_k = 'visionos_2'
                elif path == ['references', 'disa', 'disa_stig']:
                    new_k = 'visionos_2'
                elif path == ['platforms', 'visionOS']:
                    new_k = '2.0'
                # else:
                #     new_k = k  # leave as-is
            if k == 'ios_18':
                if path == ['platforms', 'iOS']:
                    new_k = '18.0'
                # else:
                #     new_k = k  # leave as-is
            # Determine the replacement key
            if k == 'ios_16':
                if path == ['platforms', 'iOS']:
                    new_k = '16.0'
                # else:
                #     new_k = k  # leave as-is            
            if k == 'ios_17':
                if path == ['platforms', 'iOS']:
                    new_k = '17.0'
                # else:
                #     new_k = k  # leave as-is
            if k == 'ios_18':
                if path == ['platforms', 'iOS']:
                    new_k = '18.0'
                # else:
                #     new_k = k  # leave as-is
            if k == 'ventura':
                if path == ['references', 'nist', 'cce']:
                    new_k = 'macos_13'
                elif path == ['references', 'disa', 'disa_stig']:
                    new_k = 'macos_13'
                elif path == ['references', 'cis', 'benchmark']:
                    new_k = 'macos_13'
                elif path == ['platforms', 'macOS']:
                    new_k = '13.0'
                # else:
                #     new_k = k  # leave as-is
            if k == 'sonoma':
                if path == ['references', 'nist', 'cce']:
                    new_k = 'macos_14'
                elif path == ['references', 'disa', 'disa_stig']:
                    new_k = 'macos_14'
                elif path == ['references', 'cis', 'benchmark']:
                    new_k = 'macos_14'                    
                elif path == ['platforms', 'macOS']:
                    new_k = '14.0'
                # else:
                #     new_k = k  # leave as-is
            if k == 'sequoia':
                if path == ['references', 'nist', 'cce']:
                    new_k = 'macos_15'
                elif path == ['references', 'disa', 'disa_stig']:
                    new_k = 'macos_15'
                elif path == ['references', 'cis', 'benchmark']:
                    new_k = 'macos_15'                    
                elif path == ['platforms', 'macOS']:
                    new_k = '15.0'
                # else:
                #     new_k = k  # leave as-is
            # else:
            #     new_k = k

            new_data[new_k] = replace_keys_by_path(v, current_path)
        return new_data

    elif isinstance(data, list):
        return [replace_keys_by_path(item, path) for item in data]
    else:
        return data

if __name__ == "__main__":
    main()
