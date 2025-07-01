#!/usr/bin/env python3
# filename: generate_scap.py
# description: Input a keyword for the baseline, output the scap/oval/xccdf

import sys
import os
import os.path
import yaml
import glob
import re
import warnings
from pathlib import Path
from datetime import datetime
import shutil
from time import sleep
import argparse
from xml.sax.saxutils import escape

warnings.filterwarnings("ignore", category=DeprecationWarning) 

def validate_file(arg):
    if (file := Path(arg)).is_file():
        return file
    else:
        raise FileNotFoundError(arg)

def format_mobileconfig_fix(mobileconfig):
    """Takes a list of domains and setting from a mobileconfig, and reformats it for the output of the fix section of the guide.
    """
    rulefix = ""
    for domain, settings in mobileconfig.items():
        if domain == "com.apple.ManagedClient.preferences":
            rulefix = rulefix + \
                (f"NOTE: The following settings are in the ({domain}) payload. This payload requires the additional settings to be sub-payloads within, containing their defined payload types.\n\n")
            rulefix = rulefix + format_mobileconfig_fix(settings)
        else:
            rulefix = rulefix + (
                f"Create a configuration profile containing the following keys in the ({domain}) payload type:\n\n")
            rulefix = rulefix + "[source,xml]\n----\n"
            for item in settings.items():
                rulefix = rulefix + (f"<key>{item[0]}</key>\n")

                if type(item[1]) == bool:
                    rulefix = rulefix + \
                        (f"<{str(item[1]).lower()}/>\n")
                elif type(item[1]) == list:
                    rulefix = rulefix + "<array>\n"
                    for setting in item[1]:
                        rulefix = rulefix + \
                            (f"    <string>{setting}</string>\n")
                    rulefix = rulefix + "</array>\n"
                elif type(item[1]) == int:
                    rulefix = rulefix + \
                        (f"<integer>{item[1]}</integer>\n")
                elif type(item[1]) == str:
                    rulefix = rulefix + \
                        (f"<string>{item[1]}</string>\n")
                elif type(item[1]) == dict:
                    rulefix = rulefix + "<dict>\n"
                    for k,v in item[1].items():
                        if type(v) == dict:
                            rulefix = rulefix + \
                                (f"    <key>{k}</key>\n")
                            rulefix = rulefix + \
                                (f"    <dict>\n")
                            for x,y in v.items():
                                rulefix = rulefix + \
                                    (f"      <key>{x}</key>\n")
                                rulefix  = rulefix + \
                                    (f"      <string>{y}</string>\n")
                            rulefix = rulefix + \
                            (f"    </dict>\n")
                            break
                        if isinstance(v, list):
                            rulefix = rulefix + "    <array>\n"
                            for setting in v:
                                rulefix = rulefix + \
                                    (f"        <string>{setting}</string>\n")
                            rulefix = rulefix + "    </array>\n"
                        else:
                            rulefix = rulefix + \
                                    (f"    <key>{k}</key>\n")
                            rulefix = rulefix + \
                                    (f"    <string>{v}</string>\n")
                    rulefix = rulefix + "</dict>\n"
         
            rulefix = rulefix + "----\n\n"

    return rulefix

def replace_ocil(xccdf, x):
    regex = r'''([\r\n].*?)(?:=?\r|\n)(.*?(?:def:{}\").*)'''.format(x)
    substr = '''<check system="http://scap.nist.gov/schema/ocil/2"><check-content-ref href="ocil.xml"/>'''
    result = re.sub(regex, substr, xccdf, 0, re.MULTILINE)
    return result

def disa_stig_rules(stig_id, stig):
    newtitle = str()
    regex = r"<title>(SRG.*\d)<\/title>.*.{}".format(stig_id)
    matches = re.search(regex,stig)
    #SRG
    if matches:   
        newtitle = str(matches.group(1))

    regex = r"Rule id=\"(.*\S)\" we.*.{}".format(stig_id)
    matches = re.search(regex,stig)
    #RuleID
    if matches:
        newtitle = newtitle + ", " + str(matches.group(1).split("_")[0])
            
    # srg-123-456. SV-7891234
    return newtitle	

def create_args():
    
    parser = argparse.ArgumentParser(
        description="Easily generate xccdf, oval, or scap datastream. If no option is defined, it will generate an scap datastream file.")
    parser.add_argument("-x", "--xccdf", default=None,
                        help="Generate an xccdf file.", action="store_true")
    parser.add_argument("-o", "--oval", default=None,
                        help="Generate an oval file of the checks.", action="store_true")
    parser.add_argument("-l", "--list_tags", default=None,
                        help="List the available keyword tags to search for.", action="store_true")
    parser.add_argument("-b", "--baseline", default="None",
                        help="Choose a baseline to generate an xml file for, if none is specified it will generate for every rule found.", action="store")
    parser.add_argument('--disastig','-d', default=None, type=validate_file, help="DISA STIG File", required=False)                        

    return parser.parse_args()

def generate_scap(all_rules, all_baselines, args, stig):
    
    export_as = ""

    version_file = "../VERSION.yaml"
    with open(version_file) as r:
        version_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        
    if args.xccdf:
        export_as = "xccdf"
    
    if args.oval:
        export_as = "oval"
        if "ios" in version_yaml['cpe']:
            print("OVAL generation is not available on iOS")
            exit()
        if "visionOS" in version_yaml['cpe']:
            print("OVAL generation is not available on visionOS")
            exit()

    if args.oval == None and args.xccdf == None:
        export_as = "scap"
        if "ios" in version_yaml['cpe']:
            print("iOS will only export as XCCDF")
            export_as = "xccdf"
        if "visionos" in version_yaml['cpe']:
            print("visionOS will only export as XCCDF")
            export_as = "xccdf"

    now = datetime.now()
    date_time_string = now.strftime("%Y-%m-%dT%H:%M:%S")

    filenameversion = version_yaml['version'].split(",")[1].replace(" ", "_")[1:]
    output = "../build/macOS_{0}_Security_Compliance_Benchmark-{1}".format(version_yaml['os'],filenameversion)
    if "ios" in version_yaml['cpe']:
        output = "../build/iOS_{0}_Security_Compliance_Benchmark-{1}".format(version_yaml['os'],filenameversion)
    if "visionos" in version_yaml['cpe']:
        output = "../build/visionOS_{0}_Security_Compliance_Benchmark-{1}".format(version_yaml['os'],filenameversion)    
    if export_as == "xccdf":
        output = output + "_xccdf.xml"
    
    if export_as == "oval":
        output = output + "_oval.xml"

    if export_as == "scap":
        output = output + ".xml"

    oval_definition = str()
    oval_test = str()
    oval_object = str()
    oval_state = str()
    oval_variable = str()
    xccdf_profiles = str()
    total_scap = str()
    scap_groups = str()
    xccdf_rules = str()
    x = 1
    d = 1

    ovalPrefix = '''<?xml version="1.0" encoding="UTF-8"?>
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="   http://oval.mitre.org/XMLSchema/oval-definitions-5             https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/oval-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/independent-definitions-schema.xsd    http://oval.mitre.org/XMLSchema/oval-definitions-5#macos       https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/macos-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#unix        https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/unix-definitions-schema.xsd">
      <generator>
        <oval:schema_version xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">5.11.2</oval:schema_version>
        <oval:timestamp xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">{0}</oval:timestamp>
        <terms_of_use>Copyright (c) 2020, NIST.</terms_of_use>
        <oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">macOS Security Compliance Project</oval:product_name>
      </generator>'''.format(date_time_string)

    ostype = "macOS"
    if "ios" in version_yaml['cpe'] or "visionos" in version_yaml['cpe']:
        ostype = "iOS/iPadOS"
        if "visionos" in version_yaml['cpe']:
            ostype = "visionOS"

    xccdfPrefix = '''<?xml version="1.0" encoding="UTF-8"?>
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_gov.nist.mscp.content_benchmark_macOS_{1}" style="SCAP_1.3" resolved="true" xml:lang="en">
      <status date="{3}">draft</status>
      <title>{4} {1}: Security Configuration</title>
      <description>
        {4} {1}: Security Configuration
      </description>
      
      
      <reference href="https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3">
        <title xmlns="http://purl.org/dc/elements/1.1/">Security Content Automation Protocol</title>
        <publisher xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</publisher>
      </reference>
      <version time="{0}" update="https://github.com/usnistgov/macos_security">{2}</version>
      <metadata>
        <creator xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</creator>
        <publisher xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</publisher>
        <source xmlns="http://purl.org/dc/elements/1.1/">https://github.com/usnistgov/macos_security/releases/latest</source>
        <contributor xmlns="http://purl.org/dc/elements/1.1/">Bob Gendler - National Institute of Standards and Technology</contributor>
        <contributor xmlns="http://purl.org/dc/elements/1.1/">Dan Brodjieski - National Aeronautics and Space Administration</contributor>
        <contributor xmlns="http://purl.org/dc/elements/1.1/">Allen Golbig - Jamf</contributor>
      </metadata>
    '''.format(date_time_string, version_yaml['os'], version_yaml['version'],date_time_string.split("T")[0] + "Z", ostype)

    scapPrefix = '''<?xml version="1.0" encoding="UTF-8"?>
<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" id="scap_gov.nist.mscp.content_collection_macOS_{1}" schematron-version="1.3">
  <data-stream timestamp="{0}" id="scap_gov.nist.mscp.content_datastream_macOS_{1}" scap-version="1.3" use-case="CONFIGURATION">
    <dictionaries>
      <component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{1}_macOS-cpe-dictionary.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{1}_macOS-cpe-dictionary.xml">
        <catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
          <uri name="macOS-cpe-oval.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{1}_macOS-cpe-oval.xml"/>
        </catalog>
      </component-ref>
    </dictionaries>
    <checklists>
      <component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{1}_xccdf.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{1}_xccdf.xml">
        <catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
            <uri name="oval.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{1}_check_1"/>
            <uri name="ocil.xml" uri="#scap_gov.nist.mscp.content_cref_macOS_{1}_check_2"/>
        </catalog>
      </component-ref>
    </checklists>
    <checks>
      <component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{1}_macOS-cpe-oval.xml" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{1}_macOS-cpe-oval.xml"/>
      <component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{1}_check_1" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{1}_check_1"/>
      <component-ref xmlns:ns0="http://www.w3.org/1999/xlink" id="scap_gov.nist.mscp.content_cref_macOS_{1}_check_2" ns0:type="simple" ns0:href="#scap_gov.nist.mscp.content_comp_macOS_{1}_check_2"/>
    </checks>
  </data-stream>
  <component id="scap_gov.nist.mscp.content_comp_macOS_{1}_xccdf.xml" timestamp="{0}">
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_gov.nist.mscp.content_benchmark_macOS_{1}" style="SCAP_1.3" resolved="true" xml:lang="en">
      <status date="{4}">draft</status>
      <title>macOS {1}: Security Configuration</title>
      <description>
        macOS {1}: Security Configuration
      </description>
      
      
      <reference href="https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3">
        <title xmlns="http://purl.org/dc/elements/1.1/">Security Content Automation Protocol</title>
        <publisher xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</publisher>
      </reference>
      <reference href="macOS-cpe-dictionary.xml">platform-cpe-dictionary</reference>
      <reference href="macOS-cpe-oval.xml">platform-cpe-oval</reference>
      <platform idref="cpe:2.3:{2}:*:*:*:*:*:*:*"/>
      <version time="{0}" update="https://github.com/usnistgov/macos_security">{3}</version>
      <metadata>
        <creator xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</creator>
        <publisher xmlns="http://purl.org/dc/elements/1.1/">National Institute of Standards and Technology</publisher>
        <source xmlns="http://purl.org/dc/elements/1.1/">https://github.com/usnistgov/macos_security/releases/latest</source>
        <contributor xmlns="http://purl.org/dc/elements/1.1/">Bob Gendler - National Institute of Standards and Technology</contributor>
        <contributor xmlns="http://purl.org/dc/elements/1.1/">Dan Brodjieski - National Aeronautics and Space Administration</contributor>
        <contributor xmlns="http://purl.org/dc/elements/1.1/">Allen Golbig - Jamf</contributor>
      </metadata>
    '''.format(date_time_string, version_yaml['os'], version_yaml['cpe'], version_yaml['version'],date_time_string.split("T")[0] + "Z")

    generated_baselines = {}
    
    for rule in all_rules:
        
        if glob.glob('../custom/rules/**/{}.yaml'.format(rule),recursive=True):
            rule_file = glob.glob('../custom/rules/**/{}.yaml'.format(rule),recursive=True)[0]
            custom=True
    
        elif glob.glob('../rules/*/{}.yaml'.format(rule)):
            rule_file = glob.glob('../rules/*/{}.yaml'.format(rule))[0]
            custom=False
        odv_label = str()
        og_rule_yaml = get_rule_yaml(rule_file, custom)
        

        loop = 1
        if "odv" in og_rule_yaml:
            loop = len(og_rule_yaml['odv'])
            
            if args.baseline != "None":
                loop = 1
        for a in range(0, loop):
            
            rule_yaml = get_rule_yaml(rule_file, custom)
            
            try:           
                
                # # odv_label = list(rule_yaml['odv'].keys())[a]
                # # odv_label.remove('hint')
                if args.baseline != "None":
                    odv_label = args.baseline
                    if args.baseline not in list(rule_yaml['odv'].keys())[a]:
                        odv_label = "recommended"
                # if args.baseline not in list(rule_yaml['odv'].keys())[a]:
                #     odv_label = "recommended"
                else:
                    odv_label = list(rule_yaml['odv'].keys())[a]

                    
                    

                # if odv_label == "hint":
                #     continue
                
                

                odv_value = str(rule_yaml['odv'][odv_label])
                rule_yaml['title'] = rule_yaml['title'].replace("$ODV",str(odv_value))
                rule_yaml['discussion'] = rule_yaml['discussion'].replace("$ODV",odv_value)
                rule_yaml['check'] = rule_yaml['check'].replace("$ODV",odv_value)
                
                rule_yaml['fix'] = rule_yaml['fix'].replace("$ODV",odv_value)
                


                
                if "result" in rule_yaml:
                    for result_value in rule_yaml['result']:
                        if "$ODV" == rule_yaml['result'][result_value]:
                            rule_yaml['result'][result_value] = rule_yaml['result'][result_value].replace("$ODV",odv_value)
                
                if rule_yaml['mobileconfig_info']:
                    for mobileconfig_type in rule_yaml['mobileconfig_info']:
                        if isinstance(rule_yaml['mobileconfig_info'][mobileconfig_type], dict):
                            for mobileconfig_value in rule_yaml['mobileconfig_info'][mobileconfig_type]:
                                
                                if "$ODV" in str(resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value]):
                                    if type(resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value]) == dict:
                                        for k,v in resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value].items():
                                            if v == "$ODV":
                                                resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value][k] = odv_value
                                    else:
                                        resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value] = odv_value
                                    
                
            except:
                odv_label = "recommended"
            if args.disastig and args.oval:
                rule_yaml['title'] = disa_stig_rules(rule_yaml['references']['disa_stig'][0], stig)   

            for baseline in all_baselines:
                    found_rules = []
                    for tag in rule_yaml['tags']:
                        if tag == baseline:
                            if odv_label != "recommended" and odv_label == tag or odv_label == "custom":
                            
                                if baseline in generated_baselines:
                                    generated_baselines[baseline].append(rule_yaml['id'] + "_" + odv_label)
                                else:
                                    generated_baselines[baseline] = [rule_yaml['id'] + "_" + odv_label]
                                continue
                            elif odv_label == "recommended" or odv_label == "custom":
                                
                                if "odv" in rule_yaml:
                                    if baseline not in rule_yaml['odv']:
                                        if baseline in generated_baselines:
                                            
                                            generated_baselines[baseline].append(rule_yaml['id'] + "_" + odv_label)
                                        else:
                                            generated_baselines[baseline] = [rule_yaml['id'] + "_" + odv_label]
                                else:
                                    if baseline in generated_baselines:
                                            
                                        generated_baselines[baseline].append(rule_yaml['id'] + "_" + odv_label)
                                    else:
                                        generated_baselines[baseline] = [rule_yaml['id'] + "_" + odv_label]

            if odv_label == "hint":
                continue
            result = str()
            if "result" in rule_yaml:
                result = "\nResult: {}".format(rule_yaml['result'])

            else:
                result = ""
            severity = str()

            if severity in rule_yaml:
                if isinstance(rule_yaml["severity"], str):
                    severity = f'{rule_yaml["severity"]}'
                if isinstance(rule_yaml["severity"], dict):
                    try:
                        severity = f'{rule_yaml["severity"][args.baseline]}'
                    except KeyError:
                        severity = "unknown"
            else:
                severity = "unknown"

            check_rule = str()
            if "inherent" in rule_yaml['tags'] or "n_a" in rule_yaml['tags'] or "permanent" in rule_yaml['tags']:
                check_rule = '''
            <check system="http://scap.nist.gov/schema/ocil/2">
            <check-content-ref href="ocil.xml"/></check>'''
            else:
                check_rule = '''<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <check-content-ref href="oval.xml" name="oval:mscp:def:{0}"/>
            </check>'''.format(x)
            references = str()
            
            if "800-53r5" in rule_yaml['references'] and rule_yaml['references']['800-53r5'][0] != "N/A":
                references = references + "<reference href=\"https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final\">NIST SP 800-53r5: "
                for nist80053 in rule_yaml['references']['800-53r5']:
                    references = references + nist80053 + ", "
                references = references[:-2] + "</reference>"
            if "800-53r4" in rule_yaml['references'] and rule_yaml['references']['800-53r4'][0] != "N/A":
                references = references + "<reference href=\"https://csrc.nist.gov/publications/detail/sp/800-53/rev-4/final\">NIST SP 800-53r4: "
                for nist80053 in rule_yaml['references']['800-53r4']:
                    references = references + nist80053 + ", "
                references = references[:-2] + "</reference>"
            if "800-171r3" in rule_yaml['references'] and rule_yaml['references']['800-171r3'][0] != "N/A":
                references = references + "<reference href=\"https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final\">NIST SP 800-171r3: "
                for nist800171 in rule_yaml['references']['800-171r3']:
                    references = references + nist800171 + ", "
                references = references[:-2] + "</reference>"
            if "disa_stig" in rule_yaml['references'] and rule_yaml['references']['disa_stig'][0] != "N/A":
                references = references + "<reference href=\"https://public.cyber.mil/stigs/downloads/\">DISA STIG(s): "
                for disa_stig in rule_yaml['references']['disa_stig']:
                    references = references + disa_stig + ", "
                references = references[:-2] + "</reference>"
            if "cis" in rule_yaml['references']:
                if "benchmark" in rule_yaml['references']['cis'] and rule_yaml['references']['cis']['benchmark'][0] != "N/A":
                    references = references + "<reference href=\"https://www.cisecurity.org/cis-benchmarks/\">CIS Benchmark: "
                    for benchmark in rule_yaml['references']['cis']['benchmark']:
                        references = references + benchmark + ", "
                    references = references[:-2] + "</reference>"
                if "controls v8" in rule_yaml['references']['cis'] and rule_yaml['references']['cis']['controls v8'][0] != "N/A":
                    references = references + "<reference href=\"https://www.cisecurity.org/controls\">CIS Controls V8: "
                    for v8controls in rule_yaml['references']['cis']['controls v8']:
                        references = references + str(v8controls) + ", "
                    references = references[:-2] + "</reference>"
            
            for k,v in rule_yaml['references'].items():
                if k == "cci" or k == "srg":
                    continue
                if k == "custom":
                    
                    
                    for i,u in rule_yaml['references']['custom'].items():
                        references = references + '<reference href="#">{0}: '.format(i)
                        for refs in rule_yaml['references']['custom'][i]:
                            references = references + '{0}, '.format(str(refs))
                        references = references[:-2] +  "</reference>"


            cce = str()
            if "cce" not in rule_yaml['references'] or rule_yaml['references']['cce'] == "N/A":
                cce = "CCE-11111-1"
            else:
                cce = rule_yaml['references']['cce'][0]

            if export_as == "scap":
                mobileconfig_info = ""
                if rule_yaml['mobileconfig']:
                    mobileconfig_info = escape(format_mobileconfig_fix(rule_yaml['mobileconfig_info']))
                xccdf_rules = xccdf_rules + '''
            <Rule id="xccdf_gov.nist.mscp.content_rule_{0}" selected="false" role="full" severity="{1}" weight="1.0">
            <title>{2}</title>
            <description>{3}
            
            {4}
            
            {5}</description>{9}
            <ident system="https://ncp.nist.gov/cce">{6}</ident>
            <fixtext>{7}</fixtext>
            {8}
            </Rule>
            '''.format(rule_yaml['id'] + "_" + odv_label, severity, rule_yaml['title'], rule_yaml['discussion'].replace("<","&lt;").replace(">","&gt;").replace("&","&amp;").rstrip(), rule_yaml['check'].replace("<","&lt;").replace(">","&gt;").replace("&","&amp;").rstrip(), result, cce,rule_yaml['fix'].replace("<","&lt;").replace(">","&gt;").replace("&","&amp;")  + "\n" + mobileconfig_info, check_rule, references)

            if export_as == "xccdf":
                mobileconfig_info = ""
                if rule_yaml['mobileconfig']:
                    mobileconfig_info = escape(format_mobileconfig_fix(rule_yaml['mobileconfig_info']))

                xccdf_rules = xccdf_rules + '''
            <Rule id="xccdf_gov.nist.mscp.content_rule_{0}" selected="false" role="full" severity="{1}" weight="1.0">
            <title>{2}</title>
            <description>{3}
            
            {4}
            
            {5}</description>{8}
            <ident system="https://ncp.nist.gov/cce">{6}</ident>
            <fixtext>{7}</fixtext>
            
            </Rule>
            '''.format(rule_yaml['id'] + "_" + odv_label, severity, rule_yaml['title'], rule_yaml['discussion'].replace("<","&lt;").replace(">","&gt;").replace("&","&amp;").rstrip(), rule_yaml['check'].replace("<","&lt;").replace(">","&gt;").replace("&","&amp;").rstrip(), result, cce,rule_yaml['fix'].replace("<","&lt;").replace(">","&gt;").replace("&","&amp;") + "\n" + mobileconfig_info, references)
                continue
                

            
            if "inherent" in rule_yaml['tags'] or "n_a" in rule_yaml['tags'] or "permanent" in rule_yaml['tags']:
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "time_machine" in rule_yaml['id'] and "encrypted" in rule_yaml['id']:
                print(rule_yaml['id'] + " - Manual Check Required")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "objectIsForcedForKey" in rule_yaml['check']:
                print(rule_yaml['id'] + " - Manual Check")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "bluetooth" in rule_yaml['id'] and "unpaired" in rule_yaml['id']:
                print(rule_yaml['id'] + " - Manual Check Required")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if rule_yaml['check'][0] != "/" and "[source,bash]" not in rule_yaml['fix']:
                print(rule_yaml['id'] + " - Manual Check")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "hint" in rule_yaml['check'] and "dscl" in rule_yaml['check']:
                print(rule_yaml['id'] + " - no relevant oval")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "manual" in rule_yaml['tags']:
                print(rule_yaml['id'] + " - Manual Check")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "eficheck" in rule_yaml['check']:
                print(rule_yaml['id'] + " - eficheck - no relevant oval")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "newsyslog.conf" in rule_yaml['check'] or "asl.conf" in rule_yaml['check'] or "aslmanager" in rule_yaml['check']:
                print(rule_yaml['id'] + " - Manual Check Required")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "/usr/bin/pwpolicy getaccountpolicies" in rule_yaml['check']:
                print(rule_yaml['id'] + " - pwpolicy getaccountpolicies - no relevant oval")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "find" in rule_yaml['check'].split(" ")[0] and rule_yaml['id'] != "os_home_folders_secure":
                print(rule_yaml['id'] + " - no relevant oval")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "/usr/sbin/firmwarepasswd" in rule_yaml['check']:
                print(rule_yaml['id'] + " - no relevant oval")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            if "os_home_folders_secure" in rule_yaml['id']:
                oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria>
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label, rule_yaml['discussion'],rule_yaml['id'] + "_" + odv_label,x)

                oval_test = oval_test + '''
                    <file_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" check="all" check_existence="all_exist" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </file_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                oval_object = oval_object + '''
            <file_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" comment="{}_object" id="oval:mscp:obj:{}" version="1">
            <path datatype="string" operation="equals" var_ref="oval:mscp:var:{}"></path>
            <filename xsi:nil="true"/>
            
            </file_object>

            <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="user home directory" id="oval:mscp:obj:{}" version="1">
                <username operation="pattern match">.*</username>
                <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
            </accountinfo_object>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x+999,x+999)

                oval_state = oval_state + '''
                <file_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <uread datatype="boolean">true</uread>
            <uwrite datatype="boolean">true</uwrite>
            <uexec datatype="boolean">true</uexec>
            <gread datatype="boolean">false</gread>
            <gwrite datatype="boolean">false</gwrite>
            <gexec datatype="boolean">false</gexec>
            <oread datatype="boolean">false</oread>
            <owrite datatype="boolean">false</owrite>
            <oexec datatype="boolean">false</oexec>
            </file_state>

        <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="accountinfo_state" id="oval:mscp:ste:{}" version="1">
                <username operation="pattern match">^[^_\s].*</username>
                <uid datatype="int" operation="not equal">0</uid>
                <gid datatype="int" operation="not equal">0</gid>
                <login_shell operation="not equal">/usr/bin/false</login_shell>
            </accountinfo_state>'''.format(rule_yaml['id'] + "_" + odv_label,x,x+999)

                oval_variable = oval_variable + '''
                    <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="home directory variable">
                <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
        </local_variable>'''.format(x,x+999)
                x = x + 1
                continue
            
            if rule_yaml['mobileconfig']:
                if "spctl" in rule_yaml['check']:
                    
                    if "verbose" in rule_yaml['check']:
                        xccdf_rules = replace_ocil(xccdf_rules,x)
                        x = x + 1
                        continue
                    else:
                        
                        oval_definition = oval_definition + '''
            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title>
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria>
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />

                </criteria>
            </definition>'''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x)

                        oval_test = oval_test + '''
            <gatekeeper_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}"/>
                <state state_ref="oval:mscp:ste:{}" />
            </gatekeeper_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                        oval_object = oval_object + '''
            <gatekeeper_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
            </gatekeeper_object>'''.format(x,rule_yaml['id'])

                        oval_state = oval_state + '''
            <gatekeeper_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <enabled datatype="boolean" operation="equals">true</enabled>
            </gatekeeper_state>'''.format(rule_yaml['id'] + "_" + odv_label,x)

                    
                    x += 1
                    continue
                
                for payload_type, info in rule_yaml['mobileconfig_info'].items():
                    
                    if payload_type == "com.apple.systempolicy.control":
                        continue
                    if payload_type == "com.apple.ManagedClient.preferences":
                        for payload_domain, settings in info.items():
                            oval_definition = oval_definition + '''
                            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                            <metadata> 
                                <title>{}</title>
                                <reference source="CCE" ref_id="{}"/>
                                <reference source="macos_security" ref_id="{}"/>
                                <description>{}</description> 
                            </metadata>'''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip())
                            if len(settings) > 1:
                                oval_definition = oval_definition + '''<criteria operator="AND">'''
                            else:
                                oval_definition = oval_definition + '''<criteria>'''
                            
                            for key, value in settings.items():
                                state_kind = ""
                                if type(value) == bool:
                                    state_kind = "boolean"
                                elif type(value) == int:
                                    state_kind = "int"
                                elif type(value) == str:
                                    state_kind = "string"
                                
                                dz = d + 5000
                                oval_definition = oval_definition + '''<criterion comment="{}" test_ref="oval:mscp:tst:{}" />'''.format(rule_yaml['id'] + '_' + odv_label + "_" + str(d), dz)

                                oval_test = oval_test + '''
                    <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                        <object object_ref="oval:mscp:obj:{}" />
                        <state state_ref="oval:mscp:ste:{}" />
                    </plist511_test>
                
                
                '''.format(rule_yaml['id'] + "_" + odv_label + "_" + str(d),dz,dz,dz)
                                if payload_domain == "com.apple.dock":
                                    
                                    oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                    <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                    <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
                </plist511_object>
                    <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(x+1999,key,dz,x,key)

                                    oval_variable = oval_variable + '''
        <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="user managed pref variable">
            <concat>
                    <literal_component datatype="string">/Library/Managed Preferences/</literal_component>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                    <literal_component datatype="string">/com.apple.dock.plist</literal_component>
            </concat>
        </local_variable>'''.format(x,x+1999)

                                else:
                                    oval_object = oval_object + '''
                        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                            <filepath>/Library/Managed Preferences/{}.plist</filepath>
                            <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>

                        </plist511_object>
                        '''.format(rule_yaml['id'] + "_" + odv_label,dz,payload_domain,key)
                                    
                                
                                oval_state = oval_state + '''
                                    <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                        <value_of datatype="{}" operation="equals">{}</value_of>
                        </plist511_state>
                        '''.format(rule_yaml['id'] + "_" + odv_label,dz,state_kind,value)
                                d += 1
                                x += 1
                        oval_definition = oval_definition + '''</criteria> </definition>'''
                        continue
                    for key, value in info.items():
                        if key == "familyControlsEnabled":
                            xpath_search = ""
                            if len(info) > 1:
                                
                                xpath_search = info['pathBlackList']
                                oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip().replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                                oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)
                                ""
                                oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath>/Library/Managed Preferences/com.apple.applicationaccess.new.plist</filepath>
                    <xpath>boolean(plist/dict/array/string/text() = "{}")</xpath>
            </plist511_object>
            '''.format(rule_yaml['id'] + "_" + odv_label,x,str(xpath_search).replace('[',"").replace(']',"").replace("'",""))
                            
                                oval_state = oval_state + '''
                        <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="boolean" operation="equals">true</value_of>
            </plist511_state>
            '''.format(rule_yaml['id'] + "_" + odv_label,x)
                                
                                x = x + 1
                                continue
                            else:
                                
                                oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x)

                                oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)
                                                                
                                oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath>/Library/Managed Preferences/{}.plist</filepath>'''.format(rule_yaml['id'] + "_" + odv_label,x,payload_type)
                    
                                state_kind = ""
                                if type(value) == bool:
                                    oval_object = oval_object + '''
    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
    </plist511_object>'''.format(key)
                                    state_kind = "boolean"
                                elif type(value) == int:
                                    state_kind = "int"
                                    oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)
                                elif type(value) == str:
                                    state_kind = "string"
                                    oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)

                                oval_state = oval_state + '''
                        <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="{}" operation="equals">{}</value_of>
            </plist511_state>
            '''.format(rule_yaml['id'] + "_" + odv_label,x,state_kind,value)

                                x = x + 1
                                continue
                        if payload_type == "com.apple.finder":
                            oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title>
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip().replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                            oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                            oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
            </plist511_object>
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
            '''.format(x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                                                    
                            state_kind = ""
                            if type(value) == bool:
                                oval_object = oval_object + '''
    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
    </plist511_object>'''.format(key)
                                state_kind = "boolean"
                            elif type(value) == int:
                                state_kind = "int"
                                oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)
                            elif type(value) == str:
                                state_kind = "string"
                                oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)

                            oval_state = oval_state + '''
                    <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
        <value_of datatype="{}" operation="equals">{}</value_of>
        </plist511_state>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,state_kind,value)


                            oval_variable = oval_variable +           '''    
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="user managed pref">
                <concat>
                    <literal_component datatype="string">/Library/Managed Preferences/</literal_component>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                    <literal_component datatype="string">/com.apple.finder.plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+1999)
                            x += 1
                            continue
                        
                        if payload_type == "com.apple.DiscRecording":
                            oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title>
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip().replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                            oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                            oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
            </plist511_object>
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
            '''.format(x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                            
                            state_kind = ""
                            if type(value) == bool:
                                oval_object = oval_object + '''
    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
    </plist511_object>'''.format(key)
                                state_kind = "boolean"
                            elif type(value) == int:
                                state_kind = "int"
                                oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)
                            elif type(value) == str:
                                state_kind = "string"
                                oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)

                            oval_state = oval_state + '''
                    <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
        <value_of datatype="{}" operation="equals">{}</value_of>
        </plist511_state>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,state_kind,value)


                            oval_variable = oval_variable +           '''    
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="user managed pref">
                <concat>
                    <literal_component datatype="string">/Library/Managed Preferences/</literal_component>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                    <literal_component datatype="string">/com.apple.DiscRecording.plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+1999)
                            x += 1
                            continue      
                        if payload_type == "com.apple.Safari" and key == "AutoOpenSafeDownloads":
                            oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title>
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip().replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                            oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                            oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
            </plist511_object>
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
            '''.format(x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                            
                            state_kind = ""
                            if type(value) == bool:
                                oval_object = oval_object + '''
    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
    </plist511_object>'''.format(key)
                                state_kind = "boolean"
                            elif type(value) == int:
                                state_kind = "int"
                                oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)
                            elif type(value) == str:
                                state_kind = "string"
                                oval_object = oval_object + '''
    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
    </plist511_object>'''.format(key)

                            oval_state = oval_state + '''
                    <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
        <value_of datatype="{}" operation="equals">{}</value_of>
        </plist511_state>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,state_kind,value)


                            oval_variable = oval_variable +           '''    
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="user managed pref">
                <concat>
                    <literal_component datatype="string">/Library/Managed Preferences/</literal_component>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                    <literal_component datatype="string">/com.apple.Safari.plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+1999)
                            x += 1
                            continue                                                       
                        if payload_type == "com.apple.systempreferences" and key == "DisabledPreferencePanes" or payload_type == "com.apple.systempreferences" and key == "HiddenPreferencePanes" or payload_type == "com.apple.systempreferences" and key == "DisabledSystemSettings": 
                            
                            oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title>
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip().replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                            oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                            oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
            </plist511_object>
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                <xpath>/plist/dict/key[string()="{}"]/following-sibling::*[1]/string[string()="{}"]/text()</xpath>
            </plist511_object>  
            '''.format(x+1999,rule_yaml['id'] + "_" + odv_label,x,x,key,str(value).strip('[]').strip("'"))
                            
                    
                            oval_state = oval_state + '''
        
            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="string" operation="equals">{}</value_of>
            </plist511_state>
        
            '''.format(rule_yaml['id'] + "_" + odv_label,x,str(value).strip('[]').strip("'"))

                            oval_variable = oval_variable +           '''    
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="user managed pref">
                <concat>
                    <literal_component datatype="string">/Library/Managed Preferences/</literal_component>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                    <literal_component datatype="string">/com.apple.systempreferences.plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+1999)
                            x += 1
                            continue
                        
                        state_kind = ""
                        if type(value) == bool:
                            state_kind = "boolean"
                        elif type(value) == int:
                            state_kind = "int"
                        elif type(value) == str:
                            state_kind = "string"
                            try:
                                int(value)
                                state_kind = "int"
                            except:
                                pass

                        elif type(value) == dict:
                            state_kind = "string"
                        else:
                            
                            continue
                        
                        oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title>
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip().replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                        oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
        '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)
                        
                        oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath>/Library/Managed Preferences/{}.plist</filepath>'''.format(rule_yaml['id'] + "_" + odv_label,x,payload_type)
                        
                        if state_kind == "boolean":
                            oval_object = oval_object + '''
                <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
            </plist511_object>'''.format(key)
                        else:
                            if payload_type == "com.apple.mobiledevice.passwordpolicy" and "customRegex" in info:
                                oval_object = oval_object + '''
                            <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format("passwordContentRegex")
                                oval_state = oval_state + '''
                        <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="{}" operation="equals">{}</value_of>
            </plist511_state>
            '''.format(rule_yaml['id'] + "_" + odv_label,x,state_kind,value['passwordContentRegex'])
                                x += 1
                                continue
                            else:
                                oval_object = oval_object + '''
                                <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                </plist511_object>'''.format(key)
                          
                        oval_state = oval_state + '''
                        <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="{}" operation="equals">{}</value_of>
            </plist511_state>
            '''.format(rule_yaml['id'] + "_" + odv_label,x,state_kind,value)
                        x += 1
                        continue
            else:
                command = rule_yaml['check'].split("/")
                if "sntp" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - No relevant oval test")
                    xccdf_rules = replace_ocil(xccdf_rules,x)
                    x += 1
                    continue
                if "xprotect status" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - No relevant oval test")
                    xccdf_rules = replace_ocil(xccdf_rules,x)
                    x += 1
                    continue
                if "SPStorageDataType" in rule_yaml['check']:
                    
                    print(rule_yaml['id'] + " - No relevant oval test")
                    xccdf_rules = replace_ocil(xccdf_rules,x)
                    x += 1
                    continue
                try:
                    if "fdesetup" in command[3]:
                        
                        print(rule_yaml['id'] + " - No relevant oval test")
                        xccdf_rules = replace_ocil(xccdf_rules,x)
                        x += 1
                        continue
                except:
                    pass
                try:
                    if "profiles" in command[3]:
                        if "/usr/bin/profiles status -type enrollment" in rule_yaml['check']:
                            oval_definition = oval_definition  + '''
                            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                            <title>{}</title>
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria operator="OR">
                        <criterion comment="com.apple.extensiblesso" test_ref="oval:mscp:tst:{}" />
                        <criterion comment="com.apple.syspolicy.kernel-extension-policy" test_ref="oval:mscp:tst:{}" />
                        <criterion comment="com.apple.TCC.configuration-profile-policy" test_ref="oval:mscp:tst:{}" />
                    </criteria> 
                </definition>'''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),x,x+899,x+799)

                            oval_test = oval_test + '''
                                <file_test id="oval:mscp:tst:{}" version="1" comment="com.apple.extensiblesso_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>
                <file_test id="oval:mscp:tst:{}" version="1" comment="com.apple.syspolicy.kernel-extension-policy_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>
                <file_test id="oval:mscp:tst:{}" version="1" comment="com.apple.TCC.configuration-profile-policy_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>'''.format(x,x,x+899,x+899,x+799,x+799)

                            oval_object = oval_object + '''
                            <file_object id="oval:mscp:obj:{}" version="1" comment="com.apple.extensiblesso_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <filepath operation="equals">/Library/Managed Preferences/com.apple.extensiblesso.plist</filepath>
                </file_object>
                <file_object id="oval:mscp:obj:{}" version="1" comment="com.apple.syspolicy.kernel-extension-policy_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <filepath operation="equals">/Library/Managed Preferences/com.apple.syspolicy.kernel-extension-policy.plist</filepath>
                </file_object>
                <file_object id="oval:mscp:obj:{}" version="1" comment="com.apple.syspolicy.kernel-extension-policy_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <filepath operation="equals">/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy.plist</filepath>
                </file_object> '''.format(x,x+899,x+799)
                        x += 1
                        continue
                except:
                    pass
                try:
                    if "csrutil" in command[3]:
                        if "authenticated-root" in command[3]:
                            
                            print(rule_yaml['id'] + " - No relevant oval test")
                            xccdf_rules = replace_ocil(xccdf_rules,x)
                            x += 1
                            continue
                        oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria>
                </definition>
                '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                        oval_test = oval_test + '''
                            <systemprofiler_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </systemprofiler_test>
                '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                        oval_object = oval_object + '''
                    <systemprofiler_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <data_type>SPSoftwareDataType</data_type>

        <xpath>//*[contains(text(), "system_integrity")]/following-sibling::string[position()=1]/text()</xpath>
                </systemprofiler_object>
                '''.format(rule_yaml['id'] + "_" + odv_label,x)

                        oval_state = oval_state + '''
                                <systemprofiler_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    <data_type>SPSoftwareDataType</data_type>

        <xpath>//*[contains(text(), "system_integrity")]/following-sibling::string[position()=1]/text()</xpath>
        <value_of>integrity_enabled</value_of>
                </systemprofiler_state>
                '''.format(rule_yaml['id'] + "_" + odv_label,x)
                        x += 1
                        continue
                except:
                    pass
                if "pfctl" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - No relevant oval test")
                    xccdf_rules = replace_ocil(xccdf_rules,x)
                    x += 1
                    continue
                if "dump-keychain" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - No relevant oval test")
                    xccdf_rules = replace_ocil(xccdf_rules,x)
                    x += 1
                    continue
                try:
                    if "mdmclient" in command[3]:
                        print(rule_yaml['id'] + " - No relevant oval test")
                        xccdf_rules = replace_ocil(xccdf_rules,x)
                        x += 1
                        continue
                except:
                    pass
                try:
                    if "nvram" in command[3]:
                        print(rule_yaml['id'] + " - No relevant oval test")
                        xccdf_rules = replace_ocil(xccdf_rules,x)
                        x += 1
                        continue
                except:
                    pass

                try:
                    if "pmset" in command[3] and "standby" in rule_yaml['check']:
                        oval_definition = oval_definition + '''
                            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] +"_standbydelayhigh",x, rule_yaml['id'] +"_standbydelaylow",x+877, rule_yaml['id'] +"_highstandbythreshold",x+888)
                        
                        
                        oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="at_least_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'] + "_standbydelayhigh",x,x,x)

                        oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="at_least_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'] + "_standbydelaylow",x+877,x+877,x+877)
                        
                        oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="at_least_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'] + "_highstandbythreshold",x+888,x+888,x+888)

                        
                        standbydelayhigh = str()
                        standbydelaylow = str()
                        highstandbythreshold = str()

                        for line in rule_yaml['fix'].split("----")[1].split("\n"):
                            if line == "":
                                continue
                            if "standbydelayhigh" in line:
                                standbydelayhigh = line.split(" ")[-1].rstrip()
                            if "standbydelaylow" in line:
                                standbydelaylow = line.split(" ")[-1].rstrip()
                            if "highstandbythreshold" in line:
                                highstandbythreshold = line.split(" ")[-1].rstrip()
                            
                        oval_object = oval_object + '''
                                        <systemprofiler_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}" id="oval:mscp:obj:{}" version="1">
                <data_type>SPHardwareDataType</data_type>

                    <xpath>//*[contains(text(), "platform_UUID")]/following-sibling::string[position()=1]/text()</xpath>
                </systemprofiler_object> '''.format("hardware UUID",x+999)

                        oval_variable = oval_variable + '''       
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
                <concat>
                    <literal_component datatype="string">/Library/Preferences/com.apple.PowerManagement.</literal_component>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                    <literal_component datatype="string">.plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+999)

                        oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>'''.format(rule_yaml['id'] + "_standbydelayhigh",x,x)
                
                        oval_object = oval_object + '''
                    <xpath>boolean(plist/dict[key="AC Power"]/dict[key="{}"]/integer/text() = "{}")</xpath>
                </plist511_object>'''.format("High Standby Delay",standbydelayhigh)
                    

                        oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>'''.format(rule_yaml['id'] + "_standbydelaylow",x+877, x)
                
                        oval_object = oval_object + '''
                    <xpath>boolean(plist/dict[key="AC Power"]/dict[key="{}"]/integer/text() = "{}")</xpath>
                </plist511_object>'''.format("Standby Delay",standbydelaylow)

                        oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>'''.format(rule_yaml['id'] + "_highstandbythreshold",x+888, x)
                        
                        oval_object = oval_object + '''
                    <xpath>boolean(plist/dict[key="AC Power"]/dict[key="{}"]/integer/text() = "{}")</xpath>
                </plist511_object>'''.format("Standby Battery Threshold",highstandbythreshold)
                        
                        oval_state = oval_state + '''
                            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="boolean" operation="equals">true</value_of>
                </plist511_state>'''.format(rule_yaml['id'] + "_standbydelayhigh",x)

                        oval_state = oval_state + '''
                            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="boolean" operation="equals">true</value_of>
                </plist511_state>'''.format(rule_yaml['id'] + "_standbydelaylow",x+877)

                        oval_state = oval_state + '''
                            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="boolean" operation="equals">true</value_of>
                </plist511_state>'''.format(rule_yaml['id'] + "_highstandbythreshold",x+888)

                        x += 1
                        continue
                except:
                    pass
                if "sudo -V" in rule_yaml['check']:
                    
                    
                    if "grep" in rule_yaml['check'].split("|")[1]:
                        oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{0}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{1}</title> 
                        <reference source="CCE" ref_id="{2}"/>
                        <reference source="macos_security" ref_id="{3}"/>
                        <description>{4}</description> 
                    </metadata> 
                <criteria operator="OR">
                    <criterion comment="{5}" test_ref="oval:mscp:tst:{6}" />
                    <criterion comment="{7}_sudoers.d" test_ref="oval:mscp:tst:{8}"/>
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label, x+5051)
                    
                        oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                    
                        oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sudoers.d_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x+5051, rule_yaml['id'] + "_" + odv_label, x+5051)

                        check_string = rule_yaml['fix'].split("echo")[1].split('"')[1]
                        
                        oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <behaviors ignore_case="true"/>
                    <filepath>/etc/sudoers</filepath>
                    <pattern operation="pattern match">{}</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>'''.format(x, rule_yaml['id'] + "_" + odv_label, check_string)


                        oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sudoers.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <path>/etc/sudoers.d/</path>
                <filename operation="pattern match">.*</filename>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x+5051, rule_yaml['id'] + "_" + odv_label, check_string)
                    
                
                        x = x + 1
                        continue

                    if "awk" in rule_yaml['check'].split("|")[1]:
                        if "timestamp_type" in rule_yaml['fix'] and rule_yaml['result']['string'] == "tty":
                            oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria operator="AND">
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_sudoers.d" test_ref="oval:mscp:tst:{}"/>
                    <criterion comment="{}_tty_ticket" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_sudoers.d_tty_ticket" test_ref="oval:mscp:tst:{}"/>
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label, x+8000, rule_yaml['id'] + "_" + odv_label,x+8001, rule_yaml['id'] + "_" + odv_label,x+8002,rule_yaml['id'] + "_" + odv_label,x+8003)
                    
                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="none_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                        
                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sudoers.d_test" check_existence="none_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x+8000, rule_yaml['id'] + "_" + odv_label, x+8000)

                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sudoers.d_test" check_existence="none_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x+8001, rule_yaml['id'] + "_" + odv_label, x+8001)

                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sudoers.d_test" check_existence="none_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x+8002, rule_yaml['id'] + "_" + odv_label, x+8002)

                            
                            oval_object = oval_object + '''
                        <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                        <behaviors ignore_case="true"/>
                        <filepath>/etc/sudoers</filepath>
                        <pattern operation="pattern match">timestamp_type</pattern>
                        <instance datatype="int">1</instance>
                    </textfilecontent54_object>'''.format(x, rule_yaml['id'] + "_" + odv_label)


                            oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sudoers.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <behaviors ignore_case="true"/>
                    <path>/etc/sudoers.d/</path>
                    <filename operation="pattern match">.*</filename>
                    <pattern operation="pattern match">timestamp_type</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>'''.format(x+8000, rule_yaml['id'] + "_" + odv_label)

                            oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sudoers.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <behaviors ignore_case="true"/>
                    <path>/etc/sudoers.d/</path>
                    <filename operation="pattern match">.*</filename>
                    <pattern operation="pattern match">!tty_tickets</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>'''.format(x+8001, rule_yaml['id'] + "_" + odv_label)
                            oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sudoers.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <behaviors ignore_case="true"/>
                    <path>/etc/sudoers.d/</path>
                    <filename operation="pattern match">.*</filename>
                    <pattern operation="pattern match">!tty_tickets</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>'''.format(x+8002, rule_yaml['id'] + "_" + odv_label)
                            x = x + 1
                            continue
                        else:
                            check_string = "Defaults.*.timestamp_type={}".format(rule_yaml['result']['string'])
                            
                            oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria operator="OR">
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_sudoers.d" test_ref="oval:mscp:tst:{}"/>
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label, x+8000, rule_yaml['id'] + "_" + odv_label,x+8001, rule_yaml['id'] + "_" + odv_label,x+8002,rule_yaml['id'] + "_" + odv_label,x+8003)
                    
                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="at_least_one_exists" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                        
                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sudoers.d_test" check_existence="at_least_one_exists" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x+5000, rule_yaml['id'] + "_" + odv_label, x+7000)

                            oval_object = oval_object + '''
                        <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                        <behaviors ignore_case="true"/>
                        <filepath>/etc/sudoers</filepath>
                        <pattern operation="pattern match">{}</pattern>
                        <instance datatype="int">1</instance>
                    </textfilecontent54_object>'''.format(x, rule_yaml['id'] + "_" + odv_label, check_string)

                        
                            oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sudoers.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <behaviors ignore_case="true"/>
                    <path>/etc/sudoers.d/</path>
                    <filename operation="pattern match">.*</filename>
                    <pattern operation="pattern match">{}</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>'''.format(x+7000, rule_yaml['id'] + "_" + odv_label, check_string)

                        x = x + 1
                        continue

                if "ssh_config" in rule_yaml['discussion'] and "dscl" in rule_yaml['check']:
                    oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria operator="OR">
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_ssh_config.d" test_ref="oval:mscp:tst:{}"/>
                    <criterion comment="{}_.ssh" test_ref="oval:mscp:tst:{}"/>
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label, x+5010, rule_yaml['id'] + "_" + odv_label,x+5025)
                    
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                    
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_ssh_config.d_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x+5010, rule_yaml['id'] + "_" + odv_label, x+5010)
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_ssh_config.d_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x+5025, rule_yaml['id'] + "_" + odv_label, x+5025)
                    regex = r"(?<=grep).*$"
                    matches = re.finditer(regex, rule_yaml['check'], re.MULTILINE)
                    matchy_match = ""
                    for matchNum, match in enumerate(matches, start=1):
                        matchy_match = match.group()
                                
                    ssh_config_pattern = matchy_match.split('"')[1]
                    

                    oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <filepath>/etc/ssh/ssh_config</filepath>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x, rule_yaml['id'] + "_" + odv_label, ssh_config_pattern)


                    oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__ssh_config.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <path>/etc/ssh/ssh_config.d/</path>
                <filename operation="pattern match">.*</filename>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x+5010, rule_yaml['id'] + "_" + odv_label, ssh_config_pattern)
                    
                    oval_object = oval_object + '''
            <textfilecontent54_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:obj:{}" version="1" comment="{}_.ssh_object" >
            <filepath var_ref="oval:mscp:var:{}"></filepath>
            <pattern operation="pattern match">{}</pattern>
            <instance datatype="int">1</instance>
            
            </textfilecontent54_object>
            

            <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="user home directory" id="oval:mscp:obj:{}" version="1">
                <username operation="pattern match">.*</username>
                <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
            </accountinfo_object>'''.format(x+5025,rule_yaml['id'] + "_" + odv_label,x,ssh_config_pattern,x+999,x+999)
                
                    oval_state = oval_state + '''
                       <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="accountinfo_state" id="oval:mscp:ste:{}" version="1">
                <username operation="pattern match">^[^_\s].*</username>
                <uid datatype="int" operation="not equal">0</uid>
                <gid datatype="int" operation="not equal">0</gid>
                <login_shell operation="not equal">/usr/bin/false</login_shell>
            </accountinfo_state>'''.format(x+999)

                    oval_variable = oval_variable + '''
                    <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="home directory variable">
                <concat>
                <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
                <literal_component datatype="string">/.ssh/config</literal_component>
                </concat>
        </local_variable>'''.format(x,x+999)
                    x = x + 1
                    continue
                if "sshd -T" in rule_yaml['check'] and "fips" in rule_yaml['check'] or "sshd -G" in rule_yaml['check'] and "fips" in rule_yaml['check']:
                    fipslist = rule_yaml['check'].split("\n")[0].split("(")[1].replace(")","").replace('" "',"\n").replace('"',"")
                    
                    
                    oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria operator="OR">
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_sshd_config.d" test_ref="oval:mscp:tst:{}"/>
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label, x+6000, rule_yaml['id'] + "_" + odv_label,x+6001)
                    
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                    
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sshd_config.d_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x+6000, rule_yaml['id'] + "_" + odv_label, x+6000)
                    
                    oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <filepath>/etc/ssh/sshd_config</filepath>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x, rule_yaml['id'] + "_" + odv_label, fipslist)


                    oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sshd_config.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <path>/etc/ssh/sshd_config.d/</path>
                <filename operation="pattern match">.*</filename>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x+6000, rule_yaml['id'] + "_" + odv_label, fipslist)
                    
                    x = x + 1
                    
                    continue
                if "sshd -T" in rule_yaml['check'] or "sshd -G" in rule_yaml['check']:
                    oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria operator="OR">
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_sshd_config.d" test_ref="oval:mscp:tst:{}"/>
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label, x+6000, rule_yaml['id'] + "_" + odv_label,x+6001)
                    
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                    
                    oval_test = oval_test + '''
                <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_sshd_config.d_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <object object_ref="oval:mscp:obj:{}"/>
        </textfilecontent54_test>
        '''.format(x+6000, rule_yaml['id'] + "_" + odv_label, x+6000)
                    sshd_config_pattern = ""
                    if "grep" in rule_yaml['check']:                        
                        regex = r"(?<=grep).*$"
                        matches = re.finditer(regex, rule_yaml['check'], re.MULTILINE)
                        matchy_match = ""
                        for matchNum, match in enumerate(matches, start=1):
                            matchy_match = match.group()
                        sshd_config_pattern = ""
                        if '"' in matchy_match:
                            sshd_config_pattern = matchy_match.split('"')[1]
                        elif "'" in matchy_match:
                            sshd_config_pattern = matchy_match.split("'")[1]
                    
                    if "awk" in rule_yaml['check']:
                        matchy_match = rule_yaml['check'].split("'")[1].split("/")[1]
                        for item in rule_yaml['result']:
                            sshd_config_pattern = matchy_match + " " + str(rule_yaml['result'][item])
                    
                    oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <filepath>/etc/ssh/sshd_config</filepath>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x, rule_yaml['id'] + "_" + odv_label, sshd_config_pattern)


                    oval_object = oval_object + '''
                <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}__sshd_config.d_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <behaviors ignore_case="true"/>
                <path>/etc/ssh/sshd_config.d/</path>
                <filename operation="pattern match">.*</filename>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x+6000, rule_yaml['id'] + "_" + odv_label, sshd_config_pattern)
                    
                
                    x = x + 1
                    continue
                try:
                    if "pmset" in command[3]:
                        oval_definition = oval_definition + '''
                            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />

                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)
                        
                        oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="at_least_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)
                        
                        oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath>/Library/Preferences/com.apple.PowerManagement.plist</filepath>'''.format(rule_yaml['id'] + "_" + odv_label,x)
                        pmset_key = str()
                        if "powernap" in rule_yaml['check']:
                            pmset_key = "DarkWakeBackgroundTasks"
                        if "womp" in rule_yaml['check']:
                            pmset_key = "Wake On LAN"

                        oval_object = oval_object + '''
                    <xpath>boolean(plist/dict[key="AC Power"]/dict[key="{}"]/integer/text() = "{}")</xpath>
                </plist511_object>'''.format(pmset_key,rule_yaml['fix'].split("----")[1].replace("\n","")[-1])

                        oval_state = oval_state + '''
                            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="boolean" operation="equals">true</value_of>
                </plist511_state>'''.format(rule_yaml['id'] + "_" + odv_label,x)
                        x += 1
                        continue
                except:
                    pass
                if "socketfilterfw" in rule_yaml['check']:
                    oval_definition = oval_definition + '''
            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria>
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />

                </criteria>
            </definition>
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)
                    oval_test = oval_test + '''
            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>
            '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                    if rule_yaml['check'].split()[1] == "--getloggingmode":
                        firewall_variable = "loggingenabled"
                    elif rule_yaml['check'].split()[1] == "--getstealthmode":
                        firewall_variable = "stealthenabled"
                    elif rule_yaml['check'].split()[1] == "--getglobalstate":
                        firewall_variable = "globalstate"

                    oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath>/Library/Preferences/com.apple.alf.plist</filepath>
                <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(rule_yaml['id'] + "_" + odv_label,x,firewall_variable)

                    oval_state = oval_state + '''
            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="int" operation="equals">1</value_of>
            </plist511_state>'''.format(rule_yaml['id'] + "_" + odv_label,x)
                    x += 1
                    continue
                try:
                    if "systemsetup" in command[3]:
                        oval_definition = oval_definition + '''
                            <definitions>
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />

                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                        oval_test = oval_test + '''
                        <systemsetup_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </systemsetup_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                        oval_object = oval_object + '''
                    <systemsetup_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                </systemsetup_object>'''.format(rule_yaml['id'] + "_" + odv_label,x)
                        state_test = ""
                        if "-getnetworktimeserver" in rule_yaml['check']:
                            
                                timeservers = rule_yaml['result']['string']
                            
                                state_test = '''
                                <networktimeserver datatype="string" operation="equals">{}</networktimeserver>
                                '''.format(timeservers)
                        oval_state = oval_state + '''
                            <systemsetup_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                {}
                </systemsetup_state>'''.format(rule_yaml['id'] + "_" + odv_label,x,state_test)


                except:
                    pass

                abc = 0
                if "defaults" in rule_yaml['check'] and "grep" in rule_yaml['check'] and "CURRENT_USER" in rule_yaml['check']:
                    
                    regex = r"(?<=\()(.*?)(?=\))"

                    test_str = rule_yaml['check'].split("grep")[1]

                    matches = re.finditer(regex, test_str, re.MULTILINE)
                    matchy_match = ""
                    for matchNum, match in enumerate(matches, start=1):
                        matchy_match = match.group()
                    
                    
                    oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria>
                    '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)
                    
                    for multi_grep in matchy_match.split("|"):
                        
                        oval_definition = oval_definition + '''
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                        '''.format(rule_yaml['id']+"_"+str(abc),x)
                        
                        oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="any_exist" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>'''.format(rule_yaml['id']+"_"+str(abc),x,x,x)

                        key = matchy_match.split("|")[abc].split(" = ")[0].replace("\"","")
                        value = matchy_match.split("|")[abc].split(" = ")[1].replace(";","")
                        if "$CURRENT_USER" in rule_yaml['check']:
                            

                            oval_object = oval_object + '''
                            <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory" id="oval:mscp:obj:{}" version="1">
                <username operation="pattern match">.*</username>
                <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
            </accountinfo_object>
            '''.format(x+1999,x+1999)

                            oval_state = oval_state + '''
                        <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory state" id="oval:mscp:ste:{}" version="1">
                <username operation="pattern match">^[^_\s].*</username>
                <uid datatype="int" operation="not equal">0</uid>
                <gid datatype="int" operation="not equal">0</gid>
                <login_shell operation="not equal">/usr/bin/false</login_shell>
            </accountinfo_state>'''.format(x+1999)
                            plist = rule_yaml['check'].split("read")[1].split()[0].replace(".plist","")

                            

                            oval_variable = oval_variable + '''
        <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
            <concat>
                <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
                <literal_component datatype="string">/Library/Preferences/{}.</literal_component>                    
                <literal_component datatype="string">plist</literal_component>
            </concat>
        </local_variable>'''.format(x,x+1999,plist)

        
                        oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>'''.format(rule_yaml['id']+"_"+str(abc),x,x)

                        oval_datatype = ""
                        try:
                            int(value)
                            
                            oval_datatype = "int"     
                            oval_object = oval_object + '''
                            <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                            </plist511_object>'''.format(key)
                        except:
                            if value.lower() == "true" or value.lower == "false":
                                oval_datatype = "boolean"
                                oval_object = oval_object + '''
                        <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
                    </plist511_object>'''.format(key)
                            else:
                                oval_datatype = "string"
                                oval_object = oval_object + '''
                            <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                            </plist511_object>'''.format(key)
                        oval_state = oval_state + '''
            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="{}" operation="equals">{}</value_of>
            </plist511_state>'''.format(rule_yaml['id']+"_"+str(abc),x,oval_datatype,value)
                        
                        abc =+ 1
                        x = x+1
                    oval_definition = oval_definition + '''</criteria>
            </definition>'''
                    oval_definition = re.sub('(?=\n\[NOTE\])(?s)(.*)\=\n<', '<', oval_definition)
                    
                    x = x+1
                    break

                        
                if "defaults" in rule_yaml['check']:
                    
                    if rule_yaml['id'] == "system_settings_hot_corners_secure" or rule_yaml['id'] == "sysprefs_hot_corners_secure":
                        oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria operator="AND">
                    <criterion comment="{}_1" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_2" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_3" test_ref="oval:mscp:tst:{}" />
                    <criterion comment="{}_4" test_ref="oval:mscp:tst:{}" />
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label,x+5000,rule_yaml['id'] + "_" + odv_label,x+5001,rule_yaml['id'] + "_" + odv_label,x+5002)
                    
                        oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_1_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                        oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_2_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x+5000,x+5000,x+5000)

                        oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_3_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x+5001,x+5001,x+5001)

                        oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_4_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x+5002,x+5002,x+5002)

                        plist = rule_yaml['check'].split("read")[1].split()[0].replace(".plist","")
                        check_length = len(rule_yaml['check'].split())
                        key = rule_yaml['check'].split("\n")[0].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                            
                        oval_object = oval_object + '''
                            <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory" id="oval:mscp:obj:{}" version="1">
                <username operation="pattern match">.*</username>
                <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
            </accountinfo_object>
            
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_1_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
            '''.format(x+1999,x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                        oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
        </plist511_object>'''.format(key)    

                        key = rule_yaml['check'].split("\n")[1].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                        
                        oval_object = oval_object + '''
                        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_2_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
            '''.format(rule_yaml['id'] + "_" + odv_label,x+5000,x)

                        oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
        </plist511_object>'''.format(key)

                        key = rule_yaml['check'].split("\n")[2].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                        
                        oval_object = oval_object + '''
                        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_3_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
            '''.format(rule_yaml['id'] + "_" + odv_label,x+5001,x)

                        oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
        </plist511_object>'''.format(key)

                        key = rule_yaml['check'].split("\n")[3].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                        
                        oval_object = oval_object + '''
                        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_4_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
            '''.format(rule_yaml['id'] + "_" + odv_label,x+5002,x)
                        oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
        </plist511_object>'''.format(key)

                        oval_state = oval_state + '''
                        <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory state" id="oval:mscp:ste:{}" version="1">
                <username operation="pattern match">^[^_\s].*</username>
                <uid datatype="int" operation="not equal">0</uid>
                <gid datatype="int" operation="not equal">0</gid>
                <login_shell operation="not equal">/usr/bin/false</login_shell>
            </accountinfo_state>'''.format(x+1999)
                        
                        
                        after_user = plist.split('"')[2]
                        oval_variable = oval_variable + '''
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
                <concat>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
                    <literal_component datatype="string">{}</literal_component>
                    <literal_component datatype="string">.plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+1999,after_user,x+999)
                        try:
                            check_if = rule_yaml['check'].split("\n")[5]
                        
                            modifier = 0
                            for n in check_if.split():
                                
                                if n.replace('"',"").isdigit():
                                    if modifier >= 4999:
                                        modifier = modifier + 1
                                    oval_state = oval_state + '''<plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_plist_state" id="oval:mscp:ste:{}" version="1">
                        <value_of datatype="int" operation="not equal">{}</value_of>
                    </plist511_state>'''.format(rule_yaml['id'] + "_" + odv_label,x+modifier,n.replace('"',""))
                                    if modifier == 0:
                                        modifier = 4999
                            x = x + 1
                            continue
                        except:      
                            x = x + 1  
                            continue
                    


                    oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria>
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria>
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)
                    
                    oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                <object object_ref="oval:mscp:obj:{}" />
                <state state_ref="oval:mscp:ste:{}" />
            </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                    plist = rule_yaml['check'].split("read")[1].split()[0].replace(".plist","")
                    
                    if "ByHost" in rule_yaml['fix'] or "currentHost" in rule_yaml['fix']:
                        
                        oval_object = oval_object + '''
                                    <systemprofiler_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}" id="oval:mscp:obj:{}" version="1">
            <data_type>SPHardwareDataType</data_type>

                <xpath>//*[contains(text(), "platform_UUID")]/following-sibling::string[position()=1]/text()</xpath>
            </systemprofiler_object> '''.format("hardware UUID",x+999)

                        if "$CURRENT_USER" in rule_yaml['check']:
                            
                            
                            check_length = len(rule_yaml['check'].split())
                            key = rule_yaml['check'].split()[check_length-1]
                            
                            oval_object = oval_object + '''
                            <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory" id="oval:mscp:obj:{}" version="1">
                <username operation="pattern match">.*</username>
                <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
            </accountinfo_object>
            
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
            '''.format(x+1999,x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                            
                            try: 
                                rule_yaml['result']['boolean']
                                oval_object = oval_object + '''
                        <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
    </plist511_object>'''.format(key)
                            except:
                                
                                oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(key)
                            oval_state = oval_state + '''
                        <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory state" id="oval:mscp:ste:{}" version="1">
                <username operation="pattern match">^[^_\s].*</username>
                <uid datatype="int" operation="not equal">0</uid>
                <gid datatype="int" operation="not equal">0</gid>
                <login_shell operation="not equal">/usr/bin/false</login_shell>
            </accountinfo_state>'''.format(x+1999)
                            
                            oval_variable = oval_variable + '''
        <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
            <concat>
                <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
                <literal_component datatype="string">/Library/Preferences/ByHost/{}.</literal_component>
                <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                <literal_component datatype="string">.plist</literal_component>
            </concat>
        </local_variable>'''.format(x,x+1999,plist,x+999)

                        

                        else:
                            
                            check_length = len(rule_yaml['check'].split())
                            key = rule_yaml['check'].replace(" 2>/dev/null","").split()[check_length-1]

                            oval_object = oval_object + '''
            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                '''.format(rule_yaml['id'] + "_" + odv_label,x,x)

                            try:
                                rule_yaml['result']['boolean']
                                oval_object = oval_object + '''
                        <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
            </plist511_object>'''.format(key)
                            except:
                                oval_object = oval_object + '''
                            <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(key)
                            
                            oval_variable = oval_variable + '''       
        <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
            <concat>
                <literal_component datatype="string">{}.</literal_component>
                <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                <literal_component datatype="string">.plist</literal_component>
            </concat>
        </local_variable>'''.format(x,plist,x+999)
                    
                    elif "$CURRENT_USER" in rule_yaml['check']:
                        
                            
                        check_length = len(rule_yaml['check'].split())
                        key = rule_yaml['check'].replace(" 2>/dev/null","").split()[-1]
                        
                        oval_object = oval_object + '''
                        <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory" id="oval:mscp:obj:{}" version="1">
            <username operation="pattern match">.*</username>
            <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
        </accountinfo_object>
        
        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
            <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
        '''.format(x+1999,x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                        
                        try: 
                            rule_yaml['result']['boolean']
                            oval_object = oval_object + '''
                    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
    </plist511_object>'''.format(key)
                        except:
                            
                            oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
        </plist511_object>'''.format(key)
                        oval_state = oval_state + '''
                    <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory state" id="oval:mscp:ste:{}" version="1">
            <username operation="pattern match">^[^_\s].*</username>
            <uid datatype="int" operation="not equal">0</uid>
            <gid datatype="int" operation="not equal">0</gid>
            <login_shell operation="not equal">/usr/bin/false</login_shell>
        </accountinfo_state>'''.format(x+1999)
                        
                        oval_variable = oval_variable + '''
    <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
        <concat>
            <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
            <literal_component datatype="string">/Library/Preferences/{}.</literal_component>
            <literal_component datatype="string">plist</literal_component>
        </concat>
    </local_variable>'''.format(x,x+1999,plist,x+999)

                    else:
                        
                        if plist[-6:] != ".plist":
                            plist = plist + ".plist"
                        
                        plist_key = rule_yaml['check'].replace(" 2>/dev/null","").split(" ")[3].rstrip()
                        oval_object = oval_object + '''
                        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                        <filepath>{}</filepath>'''.format(rule_yaml['id'] + "_" + odv_label,x,plist)
                        
                        try:
                            rule_yaml['result']['boolean']
                            oval_object = oval_object + '''
                        <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
                        </plist511_object>'''.format(plist_key)
                        except:
                            oval_object = oval_object + '''
                            <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                        </plist511_object>'''.format(plist_key)
                        
                        
                    datatype = ""
                    plist_key = rule_yaml['check'].split(" ")[3].rstrip()
                    for key in rule_yaml['result']:
                        datatype = key
                    if datatype == "integer":
                        oval_datatype = "int"

                    else:
                        oval_datatype = datatype

                    if oval_datatype == "boolean" and rule_yaml['result'][datatype] == 0:
                        value = "false"
                    elif oval_datatype == "boolean" and rule_yaml['result'][datatype] == 1:
                        value = "true"
                    else:
                        value = rule_yaml['result'][datatype]
                        
                    oval_state = oval_state + '''
            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
            <value_of datatype="{}" operation="equals">{}</value_of>
            </plist511_state>'''.format(rule_yaml['id'] + "_" + odv_label,x,oval_datatype,value)
                    oval_definition = re.sub('(?=\n\[NOTE\])(?s)(.*)\=\n<', '<', oval_definition)
                    x = x+1
                
                    continue
                try:
                    if "security" in command[3]:
                        if rule_yaml['check'].split()[1] == "authorizationdb":
                            check = rule_yaml['check'].split("|")
                            
                            authdb = rule_yaml['check'].split()[3]
                            if len(check) > 2:

                                matches = re.findall(r'(?<=\>)(.*)(?=\<)',check[1])
                                key = str(matches).replace("[","").replace("]","").replace("'","")

                                length = len(check[2].split())
                                
                                last_string = check[2].split()[length-1].replace('"',"").replace("<","").replace(">","").replace("/","")
                                

                                oval_definition = oval_definition + '''
                                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />

                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                                oval_test = oval_test + '''
                                    <authorizationdb_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </authorizationdb_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)
                                
                                oval_object = oval_object + '''
                                    <authorizationdb_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <right_name>{}</right_name>
                    <xpath>boolean(//key[text()="{}"]/following-sibling::{})</xpath>
                </authorizationdb_object>  '''.format(rule_yaml['id'] + "_" + odv_label,x,authdb,key,last_string)

                                oval_state = oval_state  + '''
                    <authorizationdb_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    
                <value_of datatype="boolean" operation="equals">true</value_of>
                </authorizationdb_state>'''.format(rule_yaml['id'] + "_" + odv_label,x)
                            else:
                                key = (check[1].split()[2].replace("'",""))
                                key = key.split('>')[1].split('<')[0]
                                oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)

                                oval_test = oval_test + '''
                <authorizationdb_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </authorizationdb_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                                oval_object = oval_object + '''
                                <authorizationdb_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <right_name>{}</right_name>
                    <xpath>//*[contains(text(), "{}")]/text()</xpath>
                </authorizationdb_object>  '''.format(rule_yaml['id'] + "_" + odv_label,x,authdb,key)

                                oval_state = oval_state + '''
                                    <authorizationdb_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_test" id="oval:mscp:ste:{}" version="1">
                    <value_of>{}</value_of>
                </authorizationdb_state>'''.format(rule_yaml['id'] + "_" + odv_label,x,key)
                        
                        else:
                            if "authorizationdb" in rule_yaml['check']:
                                regex = r"=\(.*.\)"
                                matchy_match = []
                                matches = re.finditer(regex, rule_yaml['check'], re.MULTILINE)
                                for matchNum, match in enumerate(matches, start=1):
                                    matchy_match = match.group().replace('=(',"").replace(")","").replace('"','').split()
                                
                                oval_definition = oval_definition + '''
                                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria operator="AND">'''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"))

                                for match in matchy_match:
                                    
                                    oval_definition = oval_definition + '''
                                <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                                '''.format(rule_yaml['id'] + "+" + match, x)
                                    oval_test = oval_test + '''
                                    <authorizationdb_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </authorizationdb_test>'''.format(match,x,x,x)
                                    key="shared"
                                    value=""
                                    if "false" in rule_yaml["check"]: 
                                        value="false"
                                    else:
                                        value="true"

                                    oval_object = oval_object + '''
                                    <authorizationdb_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <right_name>{}</right_name>
                    <xpath>boolean(//key[text()="{}"]/following-sibling::{})</xpath>
                </authorizationdb_object>  '''.format(match,x,match,key,value)

                                    oval_state = oval_state  + '''
                    <authorizationdb_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    
                <value_of datatype="boolean" operation="equals">true</value_of>
                </authorizationdb_state>'''.format(match,x)
                                    x += 1
                                
                                oval_definition = oval_definition + "</criteria></definition>"
                        x += 1
                        continue
                except:
                    pass
                if "/bin/rm" in rule_yaml['fix'] and "/bin/ls" in rule_yaml['check']:
                    oval_definition = oval_definition + '''
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata> 
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                
                </criteria> 
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)
                    oval_test = oval_test + '''
                            <file_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="none_exist" check="none satisfy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                <object object_ref="oval:mscp:obj:{}"/>
            </file_test>'''.format(x,rule_yaml['id'] + "_" + odv_label,x)

                    path = rule_yaml['fix'].split("----")[1].split(" ")[-1]
                    
                    oval_object = oval_object + '''
            <file_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                <path>{}</path>
                <filename xsi:nil="true" />            
            </file_object>'''.format(x,rule_yaml['id'] + "_" + odv_label,path.rstrip())
                    x += 1
                    continue

                try:
                    if "ls" in command[2] or "stat" in command[3].split()[0]:
                        if '/Library/Security/PolicyBanner.rtf' in rule_yaml['check']:
                            
                            
                            oval_definition = oval_definition + '''
                        <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria operator="OR"> 
                        <criterion comment="{}_rtf_enforce" test_ref="oval:mscp:tst:{}" />
                        <criterion comment="{}_rtfd_enforce" test_ref="oval:mscp:tst:{}" />
                    </criteria> 
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'],rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label,x+2999)

                            oval_test = oval_test + '''
                                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_rtf_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>
                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_rtfd_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>'''.format(x,rule_yaml['id'] + "_" + odv_label,x,x+2999,rule_yaml['id'] + "_" + odv_label,x+2999)

                            oval_object = oval_object + '''
                <file_object id="oval:mscp:obj:{}" version="1" comment="{}_rtf_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <path>/Library/Security/PolicyBanner.rtf</path>
                    <filename xsi:nil="true" />            
                </file_object>
                <file_object id="oval:mscp:obj:{}" version="1" comment="{}_rtfd_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <path>/Library/Security/PolicyBanner.rtfd</path>
                    <filename xsi:nil="true" />            
                </file_object>'''.format(x,rule_yaml['id'] + "_" + odv_label,x+2999,rule_yaml['id'])
                            x = x + 1
                            continue
                    
                        s = rule_yaml['check']
                        config_file = str()
                        oval_variable_need = bool()
                        if "grep" in s.split()[2]:
                            
                            
                            oval_variable_need = True
                            grep_search = re.search('\((.*?)\)', s).group(1)
                        
                            substring = grep_search.split("|")[0]
                            regex = re.search('\'(.*?)\'', substring).group(1)
                            
                            try:
                                regex = re.search('/(.*?)/', regex).group(1)
                            except:
                                regex = regex

                            config_file = substring = grep_search.split("|")[0].split()[-1]                    

                            oval_object = oval_object + '''
                <textfilecontent54_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" version="1" comment="{}_var_object" id="oval:mscp:obj:{}">
                    <filepath datatype="string" operation="equals">{}</filepath>
                    <pattern datatype="string" operation="pattern match">{}:\s*(.*)$</pattern>
                    <instance datatype="int" operation="greater than or equal">1</instance>
                </textfilecontent54_object>
                '''.format(rule_yaml['id'] + "_" + odv_label, x+999, config_file, regex)

                            oval_variable = oval_variable + '''
                    <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="{}_var">
                    <object_component object_ref="oval:mscp:obj:{}" item_field="subexpression"/>
                    </local_variable>'''.format(x,rule_yaml['id'] + "_" + odv_label,x+999)
                        
                        else:
                            oval_variable_need = False
                            config_file = s.split()[2]

                        s = rule_yaml['fix']

                        fix_command = re.search('-\n(.*?)\n-', s).group(1).split('$')[0]
                    
                        oval_definition = oval_definition + '''
                        
                    <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria> 
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria> 
                </definition> 
            '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;").rstrip(),rule_yaml['id'] + "_" + odv_label,x)

                        oval_test = oval_test + '''
                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                    <state state_ref="oval:mscp:ste:{}"/>
                </file_test>'''.format(x,rule_yaml['id'] + "_" + odv_label,x,x)
                        
                        if "-" in fix_command and "R" in fix_command or rule_yaml['fix'].split("\n")[2][-1] == "*":
                            behavior = '<behaviors recurse="symlinks and directories" recurse_direction="down" max_depth="-1" recurse_file_system="local"></behaviors>'
                            if "audit" in rule_yaml['id']:
                                filename = '<filename datatype="string" operation="not equal">current</filename>'
                        else:
                            behavior = ""
                            filename = '<filename xsi:nil="true"/>'

                        if oval_variable_need == True:
                            oval_object = oval_object + '''
                    <file_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" version="1" comment="{}_object" id="oval:mscp:obj:{}">
                    {}
                    <path datatype="string" operation="equals" var_ref="oval:mscp:var:{}"></path>
                    {}
                    </file_object>'''.format(rule_yaml['id'] + "_" + odv_label,x,behavior,x,filename)
                        else:
                            oval_object = oval_object + '''
                    <file_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" version="1" comment="{}_object" id="oval:mscp:obj:{}">
                    {}
                    <filepath datatype="string" operation="equals">{}</filepath>
                    
                    </file_object>'''.format(rule_yaml['id'] + "_" + odv_label,x,behavior,config_file)
                        state_test = ""
                        if "-" in fix_command and "N" in fix_command and "chmod" in fix_command:
                            state_test = '''
                            <has_extended_acl datatype="boolean">false</has_extended_acl>
                            '''
                        
                        elif "chgrp" in fix_command:
                            state_test = '''
                            <group_id>{}</group_id>
                            '''.format(rule_yaml['result']['integer'])

                        elif "chown" in fix_command:
                    
                            state_test = '''
                            <user_id>{}</user_id>
                            '''.format(rule_yaml['result']['integer'])
                

                        elif "chmod" in fix_command:
                            
                            perms = fix_command.split()[1]
                            
                            if perms[0] == "0":
                                state_test = '''
                <uread datatype="boolean">false</uread>
                <uwrite datatype="boolean">false</uwrite>
                <uexec datatype="boolean">false</uexec>'''
                            if perms[0] == "1":
                                state_test = '''
                <uread datatype="boolean">false</uread>
                <uwrite datatype="boolean">false</uwrite>
                <uexec datatype="boolean">true</uexec>'''
                            elif perms[0] == "2":
                                state_test = '''
                <uread datatype="boolean">false</uread>
                <uwrite datatype="boolean">true</uwrite>
                <uexec datatype="boolean">false</uexec>'''
                            elif perms[0] == "3":
                                state_test = '''
                <uread datatype="boolean">false</uread>
                <uwrite datatype="boolean">true</uwrite>
                <uexec datatype="boolean">true</uexec>'''
                            elif perms[0] == "4":
                                
                                state_test = '''
                <uread datatype="boolean">true</uread>
                <uwrite datatype="boolean">false</uwrite>
                <uexec datatype="boolean">false</uexec>'''
                            elif perms[0] == "5":
                                state_test = '''
                <uread datatype="boolean">true</uread>
                <uwrite datatype="boolean">false</uwrite>
                <uexec datatype="boolean">true</uexec>'''
                            elif perms[0] == "6":
                                state_test = '''
                <uread datatype="boolean">true</uread>
                <uwrite datatype="boolean">true</uwrite>
                <uexec datatype="boolean">false</uexec>'''
                            elif perms[0] == "7":
                                state_test = '''
                <uread datatype="boolean">true</uread>
                <uwrite datatype="boolean">true</uwrite>
                <uexec datatype="boolean">true</uexec>'''
                            
                            if perms[1] == "0":
                                state_test = state_test + '''
                <gread datatype="boolean">false</gread>
                <gwrite datatype="boolean">false</gwrite>
                <gexec datatype="boolean">false</gexec>'''
                            elif perms[1] == "1":
                                state_test = state_test + '''
                <gread datatype="boolean">false</gread>
                <gwrite datatype="boolean">false</gwrite>
                <gexec datatype="boolean">true</gexec>'''
                            elif perms[1] == "2":
                                state_test = state_test + '''
                <gread datatype="boolean">false</gread>
                <gwrite datatype="boolean">true</gwrite>
                <gexec datatype="boolean">false</gexec>'''
                            elif perms[1] == "3":
                                state_test = state_test + '''
                <gread datatype="boolean">false</gread>
                <gwrite datatype="boolean">true</gwrite>
                <gexec datatype="boolean">true</gexec>'''
                            elif perms[1] == "4":
                                
                                state_test = state_test + '''
                <gread datatype="boolean">true</gread>
                <gwrite datatype="boolean">false</gwrite>
                <gexec datatype="boolean">false</gexec>'''
                            elif perms[1] == "5":
                                state_test = state_test + '''
                <gread datatype="boolean">true</gread>
                <gwrite datatype="boolean">false</gwrite>
                <gexec datatype="boolean">true</gexec>'''
                            elif perms[1] == "6":
                                state_test = state_test + '''
                <gread datatype="boolean">true</gread>
                <gwrite datatype="boolean">true</gwrite>
                <gexec datatype="boolean">false</gexec>'''
                            elif perms[1] == "7":
                                state_test = state_test + '''
                <gread datatype="boolean">true</gread>
                <gwrite datatype="boolean">true</gwrite>
                <gexec datatype="boolean">true</gexec>'''

                            if perms[2] == "0":
                                
                                state_test = state_test + '''
                <oread datatype="boolean">false</oread>
                <owrite datatype="boolean">false</owrite>
                <oexec datatype="boolean">false</oexec>'''        
                            if perms[2] == "1":
                                state_test = state_test + '''
                <oread datatype="boolean">false</oread>
                <owrite datatype="boolean">false</owrite>
                <oexec datatype="boolean">true</oexec>'''
                            elif perms[2] == "1":
                                state_test = state_test + '''
                <oread datatype="boolean">false</oread>
                <owrite datatype="boolean">false</owrite>
                <oexec datatype="boolean">true</oexec>'''
                            elif perms[2] == "2":
                                state_test = state_test + '''
                <oread datatype="boolean">false</oread>
                <owrite datatype="boolean">true</owrite>
                <oexec datatype="boolean">false</oexec>'''
                            elif perms[2] == "3":
                                state_test = state_test + '''
                <oread datatype="boolean">false</oread>
                <owrite datatype="boolean">true</owrite>
                <oexec datatype="boolean">true</oexec>'''
                            elif perms[2] == "4":
                                state_test = state_test + '''
                <oread datatype="boolean">true</oread>
                <owrite datatype="boolean">false</owrite>
                <oexec datatype="boolean">false</oexec>'''
                            elif perms[2] == "5":
                                state_test = state_test + '''
                <oread datatype="boolean">true</oread>
                <owrite datatype="boolean">false</owrite>
                <oexec datatype="boolean">true</oexec>'''
                            elif perms[2] == "6":
                                state_test = state_test + '''
                <oread datatype="boolean">true</oread>
                <owrite datatype="boolean">true</owrite>
                <oexec datatype="boolean">false</oexec>'''
                            elif perms[2] == "7":
                                state_test = state_test + '''
                <oread datatype="boolean">true</oread>
                <owrite datatype="boolean">true</owrite>
                <oexec datatype="boolean">true</oexec>'''

                        oval_state = oval_state + '''
                <file_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" version="1" comment="{}_state" id="oval:mscp:ste:{}">'''.format(rule_yaml['id'] + "_" + odv_label,x) + state_test + '''
                </file_state>
                        '''
                    
                        x += 1
                        continue
                except:
                    pass
                try:
                    if "dscl" in command[3]:
                            if "UserShell" in rule_yaml['check']:
                                shell = rule_yaml['check'].split()[9].replace('"','')
                                oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria>
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria>
                </definition> 
                '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].replace("&","&amp;"),rule_yaml['id'] + "_" + odv_label,x)
                                
                                oval_test = oval_test + '''
                <accountinfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </accountinfo_test>
                '''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)

                                oval_object = oval_object + '''
                    <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <username>{}</username>
                </accountinfo_object>
                '''.format(rule_yaml['id'] + "_" + odv_label,x,command[5].split()[0])
                                
                                oval_state = oval_state + '''
                                <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <login_shell>{}</login_shell>
                </accountinfo_state>
                '''.format(rule_yaml['id'] + "_" + odv_label,x,shell)
                                x += 1
                                continue
                except:
                    pass
                try:
                    if "awk" in command[3]:
                        awk_file = ""
                        awk_search = ""
                        field_sep = ""
                        
                        if "grep -qE" in rule_yaml['fix']:
                            awk_file = rule_yaml['fix'].split(" ")[3].strip(" ")
                            awk_search = rule_yaml['fix'].split(" ")[2].strip("\"")
                            
                        elif "grep" in rule_yaml['check']:

                            awk_file = rule_yaml['check'].split("|")[0].split(" ")[-2]
                            awk_search = rule_yaml['check'].split("|")[-1].split(" ")[-2].strip("\'")
                            
                        else:
                            awk_file = rule_yaml['check'].split("'")[2].strip(" ")
                            awk_search = rule_yaml['check'].split("'")[1].split("/")[1]
                            
                            try: 
                                field_sep = rule_yaml['check'].split("-F")[1].split(" ")[0].replace('\"',"")

                            except:
                                field_sep = " "

                            try: 
                        
                                awk_result = rule_yaml['result']['string']

                            except: 
                                
                                awk_result = str(rule_yaml['result']['integer'])
                            
                            if awk_search[0] != "^":
                                awk_search = "^" + awk_search + field_sep + awk_result
                            else:
                                awk_search = awk_search + field_sep + awk_result

                        
                        oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria> 
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria> 
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x)
                        oval_test = oval_test + '''
                        <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <object object_ref="oval:mscp:obj:{}"/>
                </textfilecontent54_test>
                '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                        oval_object = oval_object + '''
                        <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <filepath>{}</filepath>
                    <pattern operation="pattern match">{}</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>
                '''.format(x,rule_yaml['id'] + "_" + odv_label,awk_file.rstrip(), awk_search)
                        x += 1
                        continue
                except:
                    pass
                try:
                    if "grep" in command[3] and not "pgrep" in command[3]:
                        
                        if "bannerText" in rule_yaml['check'] or "fips_" in rule_yaml['check']:
                            
                            text_to_find = rule_yaml['check'].split("=")[1].split('"')[1]

                            matches = text_to_find.replace(".","\.").replace(")","\)").replace("(","\(").replace("*","\*")
                            
                            oval_definition = oval_definition + '''
            <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                        <title>{}</title> 
                        <reference source="CCE" ref_id="{}"/>
                        <reference source="macos_security" ref_id="{}"/>
                        <description>{}</description> 
                    </metadata>
                <criteria> 
                    <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                </criteria> 
            </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x)
                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                            
                            file_path = rule_yaml["check"].split(" ")[-1].rstrip()
                            
                            oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <filepath>{}</filepath>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x,rule_yaml['id'] + "_" + odv_label,file_path,matches)

                            x += 1
                            continue
                        else:
                            
                            s = rule_yaml['check']
                            
                            try: 
                                
                                grep_search = re.search('"(.*?)"', s).group(1)
                                
                            except: 
                                
                                grep_search = re.search('\'(.*?)\'', s).group(1)
                                
                            
                            grep_file = rule_yaml['check'].split(grep_search,1)[1].split(" ")[1]
                            
                            
                            oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria> 
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria> 
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x)
                            oval_test = oval_test + '''
                        <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <object object_ref="oval:mscp:obj:{}"/>
                </textfilecontent54_test>
                '''.format(x, rule_yaml['id'] + "_" + odv_label, x)
                            oval_object = oval_object + '''
                        <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <filepath>{}</filepath>
                    <pattern operation="pattern match">{}</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>
                '''.format(x,rule_yaml['id'] + "_" + odv_label,grep_file.rstrip(),grep_search)
                            x += 1
                            continue
                except:
                    pass
                try:
                    if "launchctl" in command[2] or "launchctl" in rule_yaml['fix']:
                        if ("disable" in command[2] and "=> true" in rule_yaml['check'] or "unload -w" in rule_yaml['fix'] or "disable" in command[2] and "=> disabled" in rule_yaml['check']) or ("disable" in rule_yaml['fix']):
                            oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                    </metadata> 
                    <criteria operator="AND">
                        <criterion comment="{}_plist" test_ref="oval:mscp:tst:{}" />
                        <criterion comment="{}_launchctl" test_ref="oval:mscp:tst:{}" />
                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label,x+999)                            
                            oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_plist_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
                <launchd_test id="oval:mscp:tst:{}" version="1" comment="{}_launchctl_test" check_existence="none_exist" check="none satisfy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <object object_ref="oval:mscp:obj:{}"/>
                
                </launchd_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x,x+999,rule_yaml['id'] + "_" + odv_label,x+999)
                            
                            domain = str()
                            if "launchctl" not in rule_yaml['check']:
                                if "launchctl disable system/" in rule_yaml["fix"]:
                                    domain = rule_yaml['fix'].split()[4].split('/')[1]
                                else:
                                    domain = rule_yaml['fix'].split()[4].split('/')[4].replace(".plist","")
                            else:                                
                                s = command[5].split()[2]
                                domain = re.search('"(.*?)"', s).group(1)
                            
                            oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_plist_object" id="oval:mscp:obj:{}" version="1">
                    <filepath>/var/db/com.apple.xpc.launchd/disabled.plist</filepath>
                    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
                </plist511_object>
                <launchd_object id="oval:mscp:obj:{}" version="1" comment="{}_launchctl_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <label>{}</label>
                </launchd_object>'''.format(rule_yaml['id'] + "_" + odv_label,x,domain,x+999,rule_yaml['id'] + "_" + odv_label,domain.replace('(','').replace(')',''))
                            
                            status = ""
                            if "enable" in rule_yaml["fix"]:
                                status = "false"
                            else:
                                status = "true"
                            oval_state = oval_state + '''
                <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_plist_state" id="oval:mscp:ste:{}" version="1">
                    <value_of datatype="boolean" operation="equals">{}</value_of>
                </plist511_state>'''.format(rule_yaml['id'] + "_" + odv_label,x,status)
                        
                        elif "launchctl unload" in rule_yaml['fix'] or "launchctl disable" in rule_yaml['fix']:
                            oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                    <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                    </metadata> 
                    <criteria>
                        <criterion comment="{}_launchctl" test_ref="oval:mscp:tst:{}" />
                    </criteria>
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x,rule_yaml['id'] + "_" + odv_label,x+999)

                            oval_test = oval_test + '''
                <launchd_test id="oval:mscp:tst:{}" version="1" comment="{}_launchctl_test" check_existence="none_exist" check="none satisfy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <object object_ref="oval:mscp:obj:{}"/>
                </launchd_test>'''.format(x,rule_yaml['id'] + "_" + odv_label,x)
                            
                            domain = str()
                            
                            if "launchctl" not in rule_yaml['check']:
                                domain = rule_yaml['fix'].split()[4].split('/')[4].replace(".plist","")
                                
                            else:
                                s = command[5].split()[2]
                                domain = re.search('"(.*?)"', s).group(1)
                            
                            oval_object = oval_object + '''
                <launchd_object id="oval:mscp:obj:{}" version="1" comment="{}_launchctl_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <label>{}</label>
                </launchd_object>'''.format(x, rule_yaml['id'] + "_" + odv_label,domain.replace('(','').replace(')',''))
                        



                        elif "defaults write" in rule_yaml['fix']:
                            oval_definition = oval_definition + '''
                                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                            <metadata> 
                                <title>{}</title> 
                                <reference source="CCE" ref_id="{}"/>
                                <reference source="macos_security" ref_id="{}"/>
                                <description>{}</description> 
                            </metadata> 
                        <criteria>
                            <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                        </criteria>
                    </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'],rule_yaml['id'] + "_" + odv_label,x)
                            
                            oval_test = oval_test + '''
                                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                        <object object_ref="oval:mscp:obj:{}" />
                        <state state_ref="oval:mscp:ste:{}" />
                    </plist511_test>'''.format(rule_yaml['id'] + "_" + odv_label,x,x,x)
                            plist = rule_yaml['fix'].split(" ")[2].replace(".plist","")
                            
                            if "ByHost" in rule_yaml['fix'] or "currentHost" in rule_yaml['fix']:
                                
                                oval_object = oval_object + '''
                                            <systemprofiler_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}" id="oval:mscp:obj:{}" version="1">
                    <data_type>SPHardwareDataType</data_type>

                        <xpath>//*[contains(text(), "platform_UUID")]/following-sibling::string[position()=1]/text()</xpath>
                    </systemprofiler_object> '''.format("hardware UUID",x+999)

                                if "$CURRENT_USER" in rule_yaml['check']:
                                    
                                    
                                    
                                    key = rule_yaml['fix'].split("defaults")[1].split(" ")[3]
                                    
                                    oval_object = oval_object + '''
                                    <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory" id="oval:mscp:obj:{}" version="1">
                        <username operation="pattern match">.*</username>
                        <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
                    </accountinfo_object>
                    
                    <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                        <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
                    '''.format(x+1999,x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                                    
                                    if rule_yaml['fix'].split("defaults")[1].split(" ")[4] == "-bool":
                                        rule_yaml['result']['boolean']
                                        oval_object = oval_object + '''
                                <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
            </plist511_object>'''.format(key)
                                    else:
                                        
                                        oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                    </plist511_object>'''.format(key)
                                    oval_state = oval_state + '''
                                <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory state" id="oval:mscp:ste:{}" version="1">
                        <username operation="pattern match">^[^_\s].*</username>
                        <uid datatype="int" operation="not equal">0</uid>
                        <gid datatype="int" operation="not equal">0</gid>
                        <login_shell operation="not equal">/usr/bin/false</login_shell>
                    </accountinfo_state>'''.format(x+1999)
                                    
                                    oval_variable = oval_variable + '''
                <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
                    <concat>
                        <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
                        <literal_component datatype="string">/Library/Preferences/ByHost/{}.</literal_component>
                        <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                        <literal_component datatype="string">.plist</literal_component>
                    </concat>
                </local_variable>'''.format(x,x+1999,plist,x+999)

                                

                                else:
                                    
                                    
                                    key = rule_yaml['fix'].split("defaults")[1].split(" ")[3]

                                    oval_object = oval_object + '''
                    <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                        <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                        '''.format(rule_yaml['id'] + "_" + odv_label,x,x)

                                    
                                    if rule_yaml['fix'].split("defaults")[1].split(" ")[4] == "-bool":
                                        
                                        oval_object = oval_object + '''
                                <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
                    </plist511_object>'''.format(key)
                                    else:
                                        oval_object = oval_object + '''
                                    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                    </plist511_object>'''.format(key)
                                    
                                    oval_variable = oval_variable + '''       
                <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
                    <concat>
                        <literal_component datatype="string">{}.</literal_component>
                        <object_component object_ref="oval:mscp:obj:{}" item_field="value_of"/>
                        <literal_component datatype="string">.plist</literal_component>
                    </concat>
                </local_variable>'''.format(x,plist,x+999)
                            
                            elif "$CURRENT_USER" in rule_yaml['check']:
                                
                                    
                                check_length = len(rule_yaml['check'].split())
                                key = rule_yaml['fix'].split("defaults")[1].split(" ")[3]
                                
                                oval_object = oval_object + '''
                                <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory" id="oval:mscp:obj:{}" version="1">
                    <username operation="pattern match">.*</username>
                    <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
                </accountinfo_object>
                
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
                '''.format(x+1999,x+1999,rule_yaml['id'] + "_" + odv_label,x,x)
                                
                                if rule_yaml['fix'].split("defaults")[1].split(" ")[4] == "-bool":
                                    
                                    oval_object = oval_object + '''
                            <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
            </plist511_object>'''.format(key)
                                else:
                                    
                                    oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                </plist511_object>'''.format(key)
                                oval_state = oval_state + '''
                            <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="home directory state" id="oval:mscp:ste:{}" version="1">
                    <username operation="pattern match">^[^_\s].*</username>
                    <uid datatype="int" operation="not equal">0</uid>
                    <gid datatype="int" operation="not equal">0</gid>
                    <login_shell operation="not equal">/usr/bin/false</login_shell>
                </accountinfo_state>'''.format(x+1999)
                                
                                oval_variable = oval_variable + '''
            <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="uuid variable">
                <concat>
                    <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
                    <literal_component datatype="string">/Library/Preferences/{}.</literal_component>
                    <literal_component datatype="string">plist</literal_component>
                </concat>
            </local_variable>'''.format(x,x+1999,plist,x+999)

                            else:
                                
                                if plist[-6:] != ".plist":
                                    plist = plist + ".plist"
                                plist_key = rule_yaml['fix'].split("defaults")[1].split(" ")[3]
                                
                                oval_object = oval_object + '''
                                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                                <filepath>{}</filepath>'''.format(rule_yaml['id'] + "_" + odv_label,x,plist)
                                
                                try:
                                    rule_yaml['result']['boolean']
                                    oval_object = oval_object + '''
                                <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
                                </plist511_object>'''.format(plist_key)
                                except:
                                    oval_object = oval_object + '''
                                    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                                </plist511_object>'''.format(plist_key)
                                
                                
                            datatype = ""
                            plist_key = rule_yaml['fix'].split("defaults")[1].split(" ")[3]
                            
                            oval_datatype = rule_yaml['fix'].split("defaults")[1].split(" ")[4].replace("-","")

                            if oval_datatype == "integer":
                                oval_datatype = "int"
                            
                            if oval_datatype == "bool":
                                oval_datatype = "boolean"

                            value = rule_yaml['fix'].split("defaults")[1].split(" ")[5].replace(";","")
                                
                            oval_state = oval_state + '''
                    <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    <value_of datatype="{}" operation="equals">{}</value_of>
                    </plist511_state>'''.format(rule_yaml['id'] + "_" + odv_label,x,oval_datatype,value)
                            oval_definition = re.sub('(?=\n\[NOTE\])(?s)(.*)\=\n<', '<', oval_definition)


                            x = x+1
                    
                            continue                        
                        else:
                            oval_definition = oval_definition + '''
                <definition id="oval:mscp:def:{}" version="1" class="compliance"> 
                        <metadata> 
                            <title>{}</title> 
                            <reference source="CCE" ref_id="{}"/>
                            <reference source="macos_security" ref_id="{}"/>
                            <description>{}</description> 
                        </metadata> 
                    <criteria> 
                        <criterion comment="{}" test_ref="oval:mscp:tst:{}" />
                    </criteria> 
                </definition> '''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,rule_yaml['discussion'].rstrip(),rule_yaml['id'] + "_" + odv_label,x)

                            oval_test = oval_test + '''
                <launchd_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <object object_ref="oval:mscp:obj:{}"/>
                </launchd_test>'''.format(x,rule_yaml['id'] + "_" + odv_label,x)
                            
                            domain = command[5].split()[2]
                            domain = domain.replace('"','').replace("'",'')
                            ###########
                            label_obj = '<label>'
                            if 'E' in command[5].split()[1]:
                                label_obj = '<label operation="pattern match">'
                            else:
                                domain = domain.replace('(','').replace(')','')
                            oval_object = oval_object + '''
                <launchd_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    {}{}</label>
                </launchd_object>'''.format(x,rule_yaml['id'] + "_" + odv_label,label_obj,domain)
                        x += 1
                        continue    
                except:
                    pass
        
    for k in generated_baselines.keys():
        xccdf_profiles = xccdf_profiles + '''
        <Profile id="xccdf_gov.nist.mscp.content_profile_{1}">
                <title>{0}</title>
                <description>This profile selects all rules tagged as {0}.</description>'''.format(k, k.replace(" ","_"))
        for v in generated_baselines[k]:
            xccdf_profiles = xccdf_profiles + '''
                <select idref="xccdf_gov.nist.mscp.content_rule_{0}" selected="true"/>'''.format(v)
        xccdf_profiles = xccdf_profiles + '''
        </Profile>'''
    

    total_xccdf = xccdfPrefix + xccdf_profiles + '''
    <Group id="xccdf_gov.nist.mscp.content_group_all_rules">
        <title>All rules</title>
        <description>
         All the rules
        </description>
        <warning category="general">
          The check/fix commands outlined in this section must be run with elevated privileges.
        </warning>''' + xccdf_rules + '''      
        </Group>  </Benchmark>'''

    total_scap = scapPrefix + xccdf_profiles + '''
    <Group id="xccdf_gov.nist.mscp.content_group_all_rules">
        <title>All rules</title>
        <description>
         All the rules
        </description>
        <warning category="general">
          The check/fix commands outlined in this section must be run with elevated privileges.
        </warning>''' + xccdf_rules + '''      
        </Group>  </Benchmark>
  </component>  
  <component id="scap_gov.nist.mscp.content_comp_macOS_{1}_check_1" timestamp="{0}">
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="   http://oval.mitre.org/XMLSchema/oval-definitions-5             https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/oval-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/independent-definitions-schema.xsd    http://oval.mitre.org/XMLSchema/oval-definitions-5#macos       https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/macos-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#unix        https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/unix-definitions-schema.xsd">
      <generator>
        <oval:schema_version xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">5.11.2</oval:schema_version>
        <oval:timestamp xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">{0}</oval:timestamp>
        <terms_of_use>Copyright (c) 2020, NIST.</terms_of_use>
        <oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">macOS Security Compliance Project</oval:product_name>
      </generator>
'''.format(date_time_string,version_yaml['os'])
    total_oval = "\n<definitions>\n" + oval_definition + "\n</definitions>\n<tests>\n" + oval_test + "\n</tests>\n<objects>\n" + oval_object + "\n</objects>\n"
    if oval_state != "":
        total_oval = total_oval + "<states>\n" + oval_state + "\n</states>\n"
    if oval_variable != "":
        total_oval = total_oval + "\n<variables>\n" + oval_variable + "\n</variables>\n"
    
    total_oval = total_oval + "\n</oval_definitions>"
    
    final_oval = re.sub('(?=\n\[NOTE\])(?s)(.*)\=\n$.*', '<', total_oval)
    
    total_scap = total_scap + final_oval + '''
      </component>
      <component id="scap_gov.nist.mscp.content_comp_macOS_{2}_check_2" timestamp="{0}">
    <ocil xmlns="http://scap.nist.gov/schema/ocil/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://scap.nist.gov/schema/ocil/2.0 ocil-2.0.xsd">
      <generator>
        <product_name>Manual Labor</product_name>
        <product_version>1</product_version>
        <schema_version>2.0</schema_version>
        <timestamp>{0}</timestamp>
      </generator>
      <questionnaires>
        <questionnaire id="ocil:gov.nist.mscp.content:questionnaire:1">
          <title>Obtain a pass or a fail</title>
          <actions>
            <test_action_ref>ocil:gov.nist.mscp.content:testaction:1</test_action_ref>
          </actions>
        </questionnaire>
      </questionnaires>
      <test_actions>
        <boolean_question_test_action id="ocil:gov.nist.mscp.content:testaction:1" question_ref="ocil:gov.nist.mscp.content:question:1">
          <when_true>
            <result>PASS</result>
          </when_true>
          <when_false>
            <result>FAIL</result>
          </when_false>
        </boolean_question_test_action>
      </test_actions>
      <questions>
        <boolean_question id="ocil:gov.nist.mscp.content:question:1">
          <question_text>Do you wish this checklist item to be considered to have passed?</question_text>
        </boolean_question>
      </questions>
    </ocil>
  </component>
       <component id="scap_gov.nist.mscp.content_comp_macOS_{2}_macOS-cpe-dictionary.xml" timestamp="{0}">
    <?xml-model href="https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd" schematypens="http://www.w3.org/2001/XMLSchema" title="CPE XML schema"?>
    <cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:cpe-23="http://scap.nist.gov/schema/cpe-extension/2.3">
      <generator>
        <product_name>macOS Security Compliance Project</product_name>
        <schema_version>2.3</schema_version>
        <timestamp>{0}</timestamp>
      </generator>
      <cpe-item name="cpe:/{1}">
        <title xml:lang="en-US">Apple macOS {2}</title>
        <notes xml:lang="en-US">
          <note>This CPE Name represents macOS {2}</note>
        </notes>
        <check href="macOS-cpe-oval.xml" system="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:gov.nist.mscp.content.cpe.oval:def:1</check>
        <cpe-23:cpe23-item name="cpe:2.3:{1}:*:*:*:*:*:*:*"/>
      </cpe-item>
    </cpe-list>
  </component>
  <component id="scap_gov.nist.mscp.content_comp_macOS_{2}_macOS-cpe-oval.xml" timestamp="{0}">
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation=" http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/unix-definitions-schema.xsd">
      <generator>
        <oval:product_name>macOS Security Compliance Project</oval:product_name>
        <oval:schema_version>5.11.2</oval:schema_version>
        <oval:timestamp>{0}</oval:timestamp>
      </generator>
      <definitions>
        <definition id="oval:gov.nist.mscp.content.cpe.oval:def:1" version="1" class="inventory">
          <metadata>
            <title>Apple macOS {2} is installed</title>
            <affected family="macos">
              <platform>macOS</platform>
            </affected>
            <reference source="CPE" ref_id="cpe:/{1}"/>
            <description>The operating system installed on the system is Apple macOS ({2}).</description>
          </metadata>
          <criteria operator="AND">
            <criterion comment="The Installed Operating System is Part of the Mac OS Family" test_ref="oval:gov.nist.mscp.content.cpe:tst:1"/>
            <criterion comment="Apple macOS version is greater than or equal to {2}" test_ref="oval:gov.nist.mscp.content.cpe:tst:2"/>
          </criteria>
        </definition>
      </definitions>
      <tests>
        <family_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" check="all" check_existence="only_one_exists" comment="The Installed Operating System is Part of the macOS Family" id="oval:gov.nist.mscp.content.cpe:tst:1" version="1">
          <object object_ref="oval:gov.nist.mscp.content.cpe:obj:1"/>
          <state state_ref="oval:gov.nist.mscp.content.cpe:ste:1"/>
        </family_test>
        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="Apple macOS version is greater than {2}" id="oval:gov.nist.mscp.content.cpe:tst:2" version="2">
          <object object_ref="oval:gov.nist.mscp.content.cpe:obj:2"/>
          <state state_ref="oval:gov.nist.mscp.content.cpe:ste:2"/>
        </plist511_test>
      </tests>
      <objects>
        <family_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:gov.nist.mscp.content.cpe:obj:1" version="1" comment="This variable_object represents the family that the operating system belongs to."/>
        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="The macOS product version plist object." id="oval:gov.nist.mscp.content.cpe:obj:2" version="1">
          <filepath>/System/Library/CoreServices/SystemVersion.plist</filepath>
          <xpath>//*[contains(text(), "ProductVersion")]/following-sibling::*[1]/text()</xpath>
        </plist511_object>
      </objects>
      <states>
        <family_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:gov.nist.mscp.content.cpe:ste:1" version="1" comment="The OS is part of the macOS Family.">
          <family>macos</family>
        </family_state>
        <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="Is the value is greater than or equal to {2}" id="oval:gov.nist.mscp.content.cpe:ste:2" version="1">
          <value_of datatype="version" operation="greater than or equal">{2}</value_of>
        </plist511_state>
      </states>
    </oval_definitions>
  </component>
</data-stream-collection>'''.format(date_time_string,version_yaml['cpe'],version_yaml['os'])
    # total_scap = total_scap.replace("&", "&amp;")
    # total_scap = total_scap.replace("<", "&lt;")
    # total_scap = total_scap.replace(">", "&gt;")
    # total_scap = total_scap.replace("\"", "&quot;")
    # total_scap = total_scap.replace("'", "&apos;")
    scap_file = output
    with open(scap_file + "temp",'w') as rite:
        if export_as == "scap":
            rite.write(total_scap)
        elif export_as == "xccdf":
            rite.write(total_xccdf)
        elif export_as == "oval":
            total_oval = ovalPrefix + total_oval
            rite.write(total_oval)

        cmd = shutil.which('xmllint')
        rite.close()
        if cmd == None:
            try:
                os.rename(scap_file + "temp", scap_file)
            except:
                print("Error writing Oval file.")
        else:
            cmd = cmd + " " + scap_file + "temp --format --output " + scap_file
            
            os.popen(cmd).read()
            if os.path.exists(scap_file):
                os.remove(scap_file + "temp")    

def get_rule_yaml(rule_file, custom=False, baseline_name=""):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
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
        og_rule_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        resulting_yaml['customized'] = ["customized rule"]
    
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)

    for yaml_field in og_rule_yaml:
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
                    resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
                else:
                    resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                    if 'customized' in resulting_yaml:
                        resulting_yaml['customized'].append("customized {}".format(yaml_field))
                    else:
                        resulting_yaml['customized'] = ["customized {}".format(yaml_field)]
            except KeyError:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
        
    return resulting_yaml
     
                
class MacSecurityRule():
    def __init__(self, title, rule_id, severity, discussion, check, fix, cci, cce, nist_controls, disa_stig, srg, odv, tags, result_value, mobileconfig, mobileconfig_info):
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r4 = nist_controls
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_odv = odv
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info

    def create_asciidoc(self, adoc_rule_template):
        """Pass an AsciiDoc template as file object to return formatted AsciiDOC"""
        rule_adoc = ""
        rule_adoc = adoc_rule_template.substitute(
            rule_title=self.rule_title,
            rule_id=self.rule_id,
            rule_severity=self.rule_severity,
            rule_discussion=self.rule_discussion,
            rule_check=self.rule_check,
            rule_fix=self.rule_fix,
            rule_cci=self.rule_cci,
            rule_80053r4=self.rule_80053r4,
            rule_disa_stig=self.rule_disa_stig,
            rule_srg=self.rule_srg,
            rule_result=self.rule_result_value
        )
        return rule_adoc

def collect_rules():
    """Takes a baseline yaml file and parses the rules, returns a list of containing rules
    """
    all_rules = []
    keys = ['mobileconfig',
            'macOS',
            'severity',
            'title',
            'check',
            'fix',
            'odv',
            'tags',
            'id',
            'references',
            'result',
            'discussion']
    references = ['disa_stig',
                  'cci',
                  'cce',
                  '800-53r4',
                  'srg']


    for rule in glob.glob('../rules/**/*.yaml',recursive=True) + glob.glob('../custom/rules/**/*.yaml',recursive=True):
        if "supplemental" in rule:
            continue
        rule_yaml = get_rule_yaml(rule, custom=False)
        for key in keys:
            try:
                rule_yaml[key]
            except:
                rule_yaml.update({key: "missing"})
            if key == "references":
                for reference in references:
                    try:
                        rule_yaml[key][reference]
                    except:
                        rule_yaml[key].update({reference: ["None"]})

        if "n_a" in rule_yaml['tags']:
            rule_yaml['tags'].remove("n_a")
        if "inherent" in rule_yaml['tags']:
            rule_yaml['tags'].remove("inherent")
        if "manual" in rule_yaml['tags']:
            rule_yaml['tags'].remove("manual")
        if "none" in rule_yaml['tags']:
            rule_yaml['tags'].remove("none")
        if "permanent" in rule_yaml['tags']:
            rule_yaml['tags'].remove("permanent")
        if "supplemental" in rule_yaml['tags']:
            rule_yaml['tags'].remove("supplemental")
        if "i386" in rule_yaml['tags']:
            rule_yaml['tags'].remove("i386")
        if "arm64" in rule_yaml['tags']:
            rule_yaml['tags'].remove("arm64")

        all_rules.append(MacSecurityRule(rule_yaml['title'].replace('|', '\|'),
                                    rule_yaml['id'].replace('|', '\|'),
                                    rule_yaml['severity'],
                                    rule_yaml['discussion'].replace('|', '\|'),
                                    rule_yaml['check'].replace('|', '\|'),
                                    rule_yaml['fix'].replace('|', '\|'),
                                    rule_yaml['references']['cci'],
                                    rule_yaml['references']['cce'],
                                    rule_yaml['references']['800-53r4'],
                                    rule_yaml['references']['disa_stig'],
                                    rule_yaml['references']['srg'],
                                    rule_yaml['odv'],
                                    rule_yaml['tags'],
                                    rule_yaml['result'],
                                    rule_yaml['mobileconfig'],
                                    rule_yaml['mobileconfig_info']
                                    ))
    return all_rules

def available_tags(all_rules):
    all_tags = []
    for rule in all_rules:
        for tag in rule.rule_tags:
            all_tags.append(tag)

    available_tags = []
    for tag in all_tags:
        if tag not in available_tags:
            available_tags.append(tag)
    available_tags.sort()

    return available_tags
    
def get_controls(all_rules):
    all_controls = []
    for rule in all_rules:
        for control in rule.rule_80053r4:
            if control not in all_controls:
                all_controls.append(control)
    
    all_controls.sort()
    
    return all_controls

def main():

    args = create_args()

    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    original_working_directory = os.getcwd()

    os.chdir(file_dir)
    stig = ''
    all_rules = collect_rules()
    if args.disastig:
        file = open(args.disastig, "r")
        stig = file.read()

    all_rules_pruned = []

    # for rule in all_rules:
    #     if rule.rule_id not in all_rules_pruned:
    #         all_rules_pruned.append(rule.rule_id)

    if args.list_tags:
        for tag in available_tags(all_rules):
            print(tag)
        exit(0)
    all_baselines = []

    if args.baseline:
        all_baselines = [args.baseline]
        for rule in all_rules:
            if rule.rule_id not in all_rules_pruned and args.baseline in rule.rule_tags:
            # if args.baseline in rule.rule_tags:
                all_rules_pruned.append(rule.rule_id)

    if all_baselines == ['None']:
        all_baselines = available_tags(all_rules)
        for rule in all_rules:
            if rule.rule_id not in all_rules_pruned:
                all_rules_pruned.append(rule.rule_id)
    
    generate_scap(all_rules_pruned, all_baselines, args, stig)

    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()