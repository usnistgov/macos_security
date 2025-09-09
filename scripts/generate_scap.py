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
    year = now.year

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
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/unix-definitions-schema.xsd">
      <generator>
        <oval:schema_version>5.12.1</oval:schema_version>
        <oval:timestamp xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">{0}</oval:timestamp>
        <terms_of_use>Copyright (c) {1}, NIST.</terms_of_use>
        <oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">macOS Security Compliance Project</oval:product_name>
      </generator>'''.format(date_time_string, year)

    ostype = "macOS"
    if "ios" in version_yaml['cpe'] or "visionos" in version_yaml['cpe']:
        ostype = "iOS/iPadOS"
        if "visionos" in version_yaml['cpe']:
            ostype = "visionOS"

    xccdfPrefix = '''<?xml version="1.0" encoding="UTF-8"?>
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_gov.nist.mscp.content_benchmark_macOS_{1}" style="SCAP_1.4" resolved="true" xml:lang="en">
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
<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" id="scap_gov.nist.mscp.content_collection_macOS_{1}" schematron-version="1.4">
  <data-stream timestamp="{0}" id="scap_gov.nist.mscp.content_datastream_macOS_{1}" scap-version="1.4" use-case="CONFIGURATION">
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
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_gov.nist.mscp.content_benchmark_macOS_{1}" style="SCAP_1.4" resolved="true" xml:lang="en">
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
                odv_keys = list(rule_yaml['odv'].keys())
                
                if args.baseline != "None":
                    if args.baseline in odv_keys:
                        odv_label = args.baseline
                    else:
                        odv_label = "recommended"
                else:
                    odv_label = odv_keys[a]
                    

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
            '''.format(rule_yaml['id'] + "_" + odv_label, severity, rule_yaml['title'], escape(rule_yaml['discussion']).rstrip(), escape(rule_yaml['check']).rstrip(), result, cce,escape(rule_yaml['fix'])  + "\n" + mobileconfig_info, check_rule, references)

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
            '''.format(rule_yaml['id'] + "_" + odv_label, severity, rule_yaml['title'], escape(rule_yaml['discussion']).rstrip(), escape(rule_yaml['check']).rstrip(), result, cce,escape(rule_yaml['fix']) + "\n" + mobileconfig_info, references)
                continue
                

            
            if "inherent" in rule_yaml['tags'] or "n_a" in rule_yaml['tags'] or "permanent" in rule_yaml['tags']:
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue            
            if "manual" in rule_yaml['tags']:
                print(rule_yaml['id'] + " - Manual Check")
                xccdf_rules = replace_ocil(xccdf_rules,x)
                x += 1
                continue
            
            else:
                check_result = str()
                for k,v in rule_yaml['result'].items():
                    check_result = v
                count_found = False

                if " 2> /dev/null" in rule_yaml['check']:
                    rule_yaml['check'] = rule_yaml['check'].replace(" 2> /dev/null","")

                check_existance = "all_exist"


                if "/usr/bin/grep -c" in rule_yaml['check']:
                    if "echo \"1\"" not in rule_yaml['check'] or "echo \"0\"" not in rule_yaml['check']:
                        if "/usr/bin/ssh -G ." not in rule_yaml['check']:
                            if "auditd_enabled" not in rule_yaml['id']:
                                if "/usr/sbin/sshd -G" not in rule_yaml['check']:
                                
                                    rule_yaml['check'] = rule_yaml['check'].replace("/usr/bin/grep -c ", "/usr/bin/grep ")
                                    count_found = True
                                    if check_result == 0:                        
                                        check_existance = "none_exist"
                    
                                    
                                        
                if "launchctl list" in rule_yaml['check']:
                    rule_yaml['check'] = rule_yaml['check'].replace("launchctl list", "launchctl print system")
                    if "auditd_enabled" in rule_yaml['id']:
                        rule_yaml['check'] = rule_yaml['check'].replace("/usr/bin/grep -c com.apple.auditd", "/usr/bin/grep -c '\"com.apple.auditd\" => enabled'")
                        
                            
                if "/usr/bin/wc -l" in rule_yaml['check']:
                    new_test = []
                    for command in rule_yaml['check'].split("|"):
                        if "/usr/bin/wc -l" in command:
                            break
                        new_test.append(command.strip())
                    count_found = True
                    
                    rule_yaml['check'] = "|".join(new_test)
                    if check_result == 0:
                        check_existance = "none_exist"
                

                oval_definition = oval_definition + '''
    <definition id="oval:mscp:def:{0}" version="1" class="compliance">
      <metadata>
        <title>{1}</title>        
        <reference source="CCE" ref_id="{2}"/>
        <reference source="macos_security" ref_id="{3}"/>
        <description>{4}</description>
      </metadata>
      <criteria>
        <criterion comment="{3}" test_ref="oval:mscp:tst:{5}"/>
      </criteria>
    </definition>'''.format(x,rule_yaml['title'],cce,rule_yaml['id'] + "_" + odv_label,escape(rule_yaml['discussion']).rstrip(),x)


                if "$CURRENT_USER" in rule_yaml['check']:
                    rule_yaml['check'] = '''CURRENT_USER=$(/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow.plist lastUserName)
{}'''.format(rule_yaml['check'])   

                
                oval_test = oval_test + '''
    <shellcommand_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:tst:{0}" version="1" comment="{1}_test" check_existence="all_exist" check="all">
      <object object_ref="oval:mscp:obj:{0}"/>
      <state state_ref="oval:mscp:ste:{0}"/>
    </shellcommand_test>'''.format(x,rule_yaml['id'] + "_" + odv_label)
                oval_object = oval_object + '''
  
    <shellcommand_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:obj:{0}" version="1" comment="{1}_object">
     <shell>zsh</shell>
     <command>{2}</command>
    </shellcommand_object>'''.format(x,rule_yaml['id'] + "_" + odv_label,escape(rule_yaml['check']).rstrip())

                

                
                if count_found:
                    if check_existance != "none_exist":
                        oval_state = oval_state + '''
    <shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_state">
      <stdout_line operation="pattern match">.*</stdout_line>
    </shellcommand_state>'''.format(x,rule_yaml['id'] + "_" + odv_label)
                    else:
                        oval_state = oval_state + '''
    <shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_state">
      <stdout_line check_existence="none_exist" />
    </shellcommand_state>'''.format(x,rule_yaml['id'] + "_" + odv_label)
                    
                else:
                    oval_state = oval_state + '''
    <shellcommand_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:mscp:ste:{0}" version="1" comment="{1}_state">
      <stdout_line operation="equals">{2}</stdout_line>
    </shellcommand_state>'''.format(x,rule_yaml['id'] + "_" + odv_label,check_result)
                x += 1
                check_existance = "all_exist"
                continue
            x += 1
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
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/unix-definitions-schema.xsd">
      <generator>
        <oval:schema_version>5.12.1</oval:schema_version>
        <oval:timestamp xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">{0}</oval:timestamp>
        <terms_of_use>Copyright (c) {2}, NIST.</terms_of_use>
        <oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">macOS Security Compliance Project</oval:product_name>
      </generator>
'''.format(date_time_string,version_yaml['os'],year)
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
    <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVAL-Community/OVAL/master/oval-schemas/unix-definitions-schema.xsd">
      <generator>
        <oval:product_name>macOS Security Compliance Project</oval:product_name>
        <oval:schema_version>5.12.1</oval:schema_version>
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
            cmd = cmd + " " + scap_file + "temp --huge --format --output " + scap_file
            
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
        if "srg" in rule_yaml['tags']:
            rule_yaml['tags'].remove("srg")

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