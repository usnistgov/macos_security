#!/usr/bin/env python3
import argparse
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

warnings.filterwarnings("ignore", category=DeprecationWarning) 


def main():
    now = datetime.now()
    date_time_string = now.strftime("%Y-%m-%dT%H:%M:%S")
    output = ""
    parser = argparse.ArgumentParser(description='Given a profile, create oval checks.')
    parser.add_argument("baseline", default=None, help="Baseline YAML file used to create the oval.", type=argparse.FileType('rt'))

    results = parser.parse_args()
    try:
        
        output_basename = os.path.basename(results.baseline.name)
        output_filename = os.path.splitext(output_basename)[0]
        baseline_name = os.path.splitext(output_basename)[0]
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)
        
        build_path = os.path.join(parent_dir, 'build', f'{baseline_name}')
        output = build_path + "/" + baseline_name + ".xml"

        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")
        print('Profile YAML:', results.baseline.name)
        print('Output path:', output)
        
       
        
    except IOError as msg:
        parser.error(str(msg))

    profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)
    
    x = 1

    ovalPrefix = '''<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions 
 xsi:schemaLocation=" 
 http://oval.mitre.org/XMLSchema/oval-definitions-5             https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/oval-definitions-schema.xsd
 http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/independent-definitions-schema.xsd  
 http://oval.mitre.org/XMLSchema/oval-definitions-5#macos       https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/macos-definitions-schema.xsd
 http://oval.mitre.org/XMLSchema/oval-definitions-5#unix        https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/unix-definitions-schema.xsd"
 xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" 
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" 
 xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" 
 xmlns:macos-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos"
 xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"> 
        <generator>
            <oval:schema_version>5.11.2</oval:schema_version>
             <oval:timestamp>{}</oval:timestamp>
             <terms_of_use>Copyright (c) 2020, NIST.</terms_of_use>
             <oval:product_name>macOS Security Compliance Project</oval:product_name>
        </generator>
    '''.format(date_time_string)
    oval_definition = str()
    oval_test = str()
    oval_object = str()
    oval_state = str()
    oval_variable = str()
    print()
    for sections in profile_yaml['profile']:
        for profile_rule in sections['rules']:
            for rule_file in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                
                if "srg" in rule_file or "supplemental" in rule_file:
                    continue
                with open(rule_file) as r:
                    rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
                if "inherent" in rule_yaml['tags'] or "n_a" in rule_yaml['tags'] or "permanent" in rule_yaml['tags']:
                    continue
                if "time_machine" in rule_yaml['id'] and "encrypted" in rule_yaml['id']:
                    print(rule_yaml['id'] + " - Manual Check Required")
                    continue
                if "bluetooth" in rule_yaml['id'] and "unpaired" in rule_yaml['id']:
                    print(rule_yaml['id'] + " - Manual Check Required")
                    continue
                if rule_yaml['check'][0] != "/" and "[source,bash]" not in rule_yaml['fix']:
                    print(rule_yaml['id'] + " - Manual Check")
                    continue
                if "hint" in rule_yaml['check'] and "dscl" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - no relevant oval")
                    continue
                if "manual" in rule_yaml['tags']:
                    print(rule_yaml['id'] + " - Manual Check")
                    continue
                if "eficheck" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - eficheck - no relevant oval")
                    continue
                if "newsyslog.conf" in rule_yaml['check'] or "asl.conf" in rule_yaml['check'] or "aslmanager" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - Manual Check Required")
                    continue
                if "/usr/bin/pwpolicy getaccountpolicies" in rule_yaml['check']:
                    print(rule_yaml['id'] + " - pwpolicy getaccountpolicies - no relevant oval")
                    continue
                if "find" in rule_yaml['check'].split(" ")[0]:
                    print(rule_yaml['id'] + " - no relevant oval")
                    continue
                if "os_home_folders_secure" in rule_file:
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'], rule_yaml['discussion'],rule_yaml['id'],x)

                    oval_test = oval_test + '''
                        <file_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" check="all" check_existence="all_exist" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </file_test>'''.format(rule_yaml['id'],x,x,x)

                    oval_object = oval_object + '''
                <file_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <path datatype="string" operation="equals" var_ref="oval:mscp:var:{}"></path>
                <filename xsi:nil="true"/>
                
                </file_object>

                <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="user home directory" id="oval:mscp:obj:{}" version="1">
                    <username operation="pattern match">.*</username>
                    <filter action="include" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:mscp:ste:{}</filter>
                </accountinfo_object>'''.format(rule_yaml['id'],x,x,x+999,x+999)

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
                </accountinfo_state>'''.format(rule_yaml['id'],x,x+999)

                    oval_variable = oval_variable + '''
                        <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="home directory variable">
                    <object_component object_ref="oval:mscp:obj:{}" item_field="home_dir"/>
            </local_variable>'''.format(x,x+999)
                    x = x + 1
                    continue
                
                if rule_yaml['mobileconfig']:
                    if "spctl" in rule_yaml['check']:
                        
                        if "verbose" in rule_yaml['check']:
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
                </definition>'''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                            oval_test = oval_test + '''
                <gatekeeper_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}"/>
                    <state state_ref="oval:mscp:ste:{}" />
                </gatekeeper_test>'''.format(rule_yaml['id'],x,x,x)

                            oval_object = oval_object + '''
                <gatekeeper_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                </gatekeeper_object>'''.format(x,rule_yaml['id'])

                            oval_state = oval_state + '''
                <gatekeeper_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    <enabled datatype="boolean" operation="equals">true</enabled>
                </gatekeeper_state>'''.format(rule_yaml['id'],x)

                        
                        x += 1
                        continue
                    
                    for payload_type, info in rule_yaml['mobileconfig_info'].items():
                        if payload_type == "com.apple.systempolicy.control":
                            continue
                        if payload_type == "com.apple.ManagedClient.preferences":
                            for payload_domain, settings in info.items():
                                
                                for key, value in settings.items():
                                    state_kind = ""
                                    if type(value) == bool:
                                        state_kind = "boolean"
                                    elif type(value) == int:
                                        state_kind = "int"
                                    elif type(value) == str:
                                        state_kind = "string"

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
                        '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                    oval_test = oval_test + '''
                        <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                            <object object_ref="oval:mscp:obj:{}" />
                            <state state_ref="oval:mscp:ste:{}" />
                        </plist511_test>
                    
                    
                    '''.format(rule_yaml['id'],x,x,x)
                                    if payload_domain == "com.apple.dock":
                                        
                                        oval_object = oval_object + '''
                    <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                        <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                        <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
                    </plist511_object>
                        <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                    <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                </plist511_object>'''.format(x+1999,key,x,x,key)

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
                            '''.format(rule_yaml['id'],x,payload_domain,key)
                                        
                                    
                                    oval_state = oval_state + '''
                                        <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                            <value_of datatype="{}" operation="equals">{}</value_of>
                            </plist511_state>
                            '''.format(rule_yaml['id'],x,state_kind,value)
                                    x += 1

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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                    oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                                    oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                        <filepath>/Library/Managed Preferences/com.apple.applicationaccess.new.plist</filepath>
                        <xpath>boolean(plist/dict/array/string/text() = "{}")</xpath>
                </plist511_object>
                '''.format(rule_yaml['id'],x,str(xpath_search).replace('[',"").replace(']',"").replace("'",""))
                                
                                    oval_state = oval_state + '''
                            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="boolean" operation="equals">true</value_of>
                </plist511_state>
                '''.format(rule_yaml['id'],x)
                                    
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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                    oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                                    oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath>/Library/Managed Preferences/{}.plist</filepath>'''.format(rule_yaml['id'],x,payload_type)
                        
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
                '''.format(rule_yaml['id'],x,state_kind,value)

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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                                oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                    <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                    <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
                </plist511_object>
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                '''.format(x+1999,rule_yaml['id'],x,x)
                                                        
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
            '''.format(rule_yaml['id'],x,state_kind,value)


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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                                oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                    <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                    <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
                </plist511_object>
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                '''.format(x+1999,rule_yaml['id'],x,x)
                                
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
            '''.format(rule_yaml['id'],x,state_kind,value)


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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                                oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                    <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                    <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
                </plist511_object>
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                '''.format(x+1999,rule_yaml['id'],x,x)
                                
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
            '''.format(rule_yaml['id'],x,state_kind,value)


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
                            if payload_type == "com.apple.systempreferences" and key == "DisabledPreferencePanes" or payload_type == "com.apple.systempreferences" and key == "HiddenPreferencePanes": 
                                
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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                                oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                                oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" version="1" comment="find a username" id="oval:mscp:obj:{}">
                    <filepath>/Library/Preferences/com.apple.loginwindow.plist</filepath>
                    <xpath>/plist/dict/key[string()="lastUserName"]/following-sibling::*[1]/text()</xpath>
                </plist511_object>
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>
                    <xpath>/plist/dict/key[string()="{}"]/following-sibling::*[1]/string[string()="{}"]/text()</xpath>
                </plist511_object>  
                '''.format(x+1999,rule_yaml['id'],x,x,key,str(value).strip('[]').strip("'"))
                                
                        
                                oval_state = oval_state + '''
            
                <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="string" operation="equals">{}</value_of>
                </plist511_state>
            
                '''.format(rule_yaml['id'],x,str(value).strip('[]').strip("'"))

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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                            oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
            '''.format(rule_yaml['id'],x,x,x)

                            
                            oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath>/Library/Managed Preferences/{}.plist</filepath>'''.format(rule_yaml['id'],x,payload_type)
                    
                            if state_kind == "boolean":
                                oval_object = oval_object + '''
                    <xpath>name(//*[contains(text(), "{}")]/following-sibling::*[1])</xpath>
                </plist511_object>'''.format(key)
                            else:
                                oval_object = oval_object + '''
                                <xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
                </plist511_object>'''.format(key)
                        
                            oval_state = oval_state + '''
                            <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="{}" operation="equals">{}</value_of>
                </plist511_state>
                '''.format(rule_yaml['id'],x,state_kind,value)
                            x += 1
                            continue
                else:
                    command = rule_yaml['check'].split("/")
                    if "sntp" in rule_yaml['check']:
                        x += 1
                        print(rule_yaml['id'] + " - No relevant oval test")
                        continue

                    if "SPStorageDataType" in rule_yaml['check']:
                        x += 1
                        print(rule_yaml['id'] + " - No relevant oval test")
                        continue

                    if "fdesetup" in command[3]:
                        x += 1
                        print(rule_yaml['id'] + " - No relevant oval test")
                        continue
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
                </definition>'''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],x,x+899,x+799)

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
                    if "csrutil" in command[3]:
                        if "authenticated-root" in command[3]:
                            print(rule_yaml['id'] + " - No relevant oval test")
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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)

                        oval_test = oval_test + '''
                            <systemprofiler_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </systemprofiler_test>
                '''.format(rule_yaml['id'],x,x,x)

                        oval_object = oval_object + '''
                    <systemprofiler_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <data_type>SPSoftwareDataType</data_type>

        <xpath>//*[contains(text(), "system_integrity")]/following-sibling::string[position()=1]/text()</xpath>
                </systemprofiler_object>
                '''.format(rule_yaml['id'],x)

                        oval_state = oval_state + '''
                                <systemprofiler_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    <data_type>SPSoftwareDataType</data_type>

        <xpath>//*[contains(text(), "system_integrity")]/following-sibling::string[position()=1]/text()</xpath>
        <value_of>integrity_enabled</value_of>
                </systemprofiler_state>
                '''.format(rule_yaml['id'],x)
                        x += 1
                        continue
                    if "pfctl" in rule_yaml['check']:
                        print(rule_yaml['id'] + " - No relevant oval test")
                        x += 1
                        continue
                    if "dump-keychain" in rule_yaml['check']:
                        print(rule_yaml['id'] + " - No relevant oval test")
                        x += 1
                        continue
                    if "mdmclient" in command[3]:
                        print(rule_yaml['id'] + " - No relevant oval test")
                        x += 1
                        continue
                    if "nvram" in command[3]:
                        print(rule_yaml['id'] + " - No relevant oval test")
                        x += 1
                        continue

                    
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'] +"_standbydelayhigh",x, rule_yaml['id'] +"_standbydelaylow",x+877, rule_yaml['id'] +"_highstandbythreshold",x+888)
                        
                        
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)
                        
                        oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="at_least_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'],x,x,x)
                        
                        oval_object = oval_object + '''
                <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <filepath>/Library/Preferences/com.apple.PowerManagement.plist</filepath>'''.format(rule_yaml['id'],x)
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
                </plist511_state>'''.format(rule_yaml['id'],x)
                        x += 1
                        continue
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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)
                        oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
                '''.format(rule_yaml['id'],x,x,x)

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
                </plist511_object>'''.format(rule_yaml['id'],x,firewall_variable)

                        oval_state = oval_state + '''
                <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <value_of datatype="int" operation="equals">1</value_of>
                </plist511_state>'''.format(rule_yaml['id'],x)
                        x += 1
                        continue
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)

                        oval_test = oval_test + '''
                        <systemsetup_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </systemsetup_test>'''.format(rule_yaml['id'],x,x,x)

                        oval_object = oval_object + '''
                    <systemsetup_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                </systemsetup_object>'''.format(rule_yaml['id'],x)
                        state_test = ""
                        if "-getnetworktimeserver" in rule_yaml['check']:
                            
                                timeservers = rule_yaml['result']['string']
                            
                                state_test = '''
                                <networktimeserver datatype="string" operation="equals">{}</networktimeserver>
                                '''.format(timeservers)
                        oval_state = oval_state + '''
                            <systemsetup_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                {}
                </systemsetup_state>'''.format(rule_yaml['id'],x,state_test)




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
                        '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)
                        
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
                        
                        if rule_yaml['id'] == "sysprefs_hot_corners_secure":
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x,rule_yaml['id'],x+5000,rule_yaml['id'],x+5001,rule_yaml['id'],x+5002)
                        
                            oval_test = oval_test + '''
                            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_1_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'],x,x,x)

                            oval_test = oval_test + '''
                            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_2_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'],x+5000,x+5000,x+5000)

                            oval_test = oval_test + '''
                            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_3_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'],x+5001,x+5001,x+5001)

                            oval_test = oval_test + '''
                            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_4_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'],x+5002,x+5002,x+5002)

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
                '''.format(x+1999,x+1999,rule_yaml['id'],x,x)
                            oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(key)    

                            key = rule_yaml['check'].split("\n")[1].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                            
                            oval_object = oval_object + '''
                            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_2_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
                '''.format(rule_yaml['id'],x+5000,x)

                            oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(key)

                            key = rule_yaml['check'].split("\n")[2].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                            
                            oval_object = oval_object + '''
                            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_3_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
                '''.format(rule_yaml['id'],x+5001,x)

                            oval_object = oval_object + '''<xpath>//*[contains(text(), "{}")]/following-sibling::*[1]/text()</xpath>
            </plist511_object>'''.format(key)

                            key = rule_yaml['check'].split("\n")[3].replace(" 2>/dev/null","").split()[-1].replace('"','').replace(")",'')
                            
                            oval_object = oval_object + '''
                            <plist511_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_4_object" id="oval:mscp:obj:{}" version="1">
                    <filepath datatype="string" operation="equals" var_check="at least one" var_ref="oval:mscp:var:{}"/>    
                '''.format(rule_yaml['id'],x+5002,x)
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
                        </plist511_state>'''.format(rule_yaml['id'],x+modifier,n.replace('"',""))
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)
                        
                        oval_test = oval_test + '''
                            <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="all_exist" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>'''.format(rule_yaml['id'],x,x,x)

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
                '''.format(x+1999,x+1999,rule_yaml['id'],x,x)
                                
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
                    '''.format(rule_yaml['id'],x,x)

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
            '''.format(x+1999,x+1999,rule_yaml['id'],x,x)
                            
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
                            <filepath>{}</filepath>'''.format(rule_yaml['id'],x,plist)
                            
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
                </plist511_state>'''.format(rule_yaml['id'],x,oval_datatype,value)
                        oval_definition = re.sub('(?=\n\[NOTE\])(?s)(.*)\=\n<', '<', oval_definition)
                        x = x+1
                    
                        continue
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)

                                oval_test = oval_test + '''
                                    <authorizationdb_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </authorizationdb_test>'''.format(rule_yaml['id'],x,x,x)
                                
                                oval_object = oval_object + '''
                                    <authorizationdb_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <right_name>{}</right_name>
                    <xpath>boolean(//key[text()="{}"]/following-sibling::{})</xpath>
                </authorizationdb_object>  '''.format(rule_yaml['id'],x,authdb,key,last_string)

                                oval_state = oval_state  + '''
                    <authorizationdb_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                    
                <value_of datatype="boolean" operation="equals">true</value_of>
                </authorizationdb_state>'''.format(rule_yaml['id'],x)
                            else:
                                key = (check[1].split()[2].replace("'",""))

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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)

                                oval_test = oval_test + '''
                <authorizationdb_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </authorizationdb_test>'''.format(rule_yaml['id'],x,x,x)

                                oval_object = oval_object + '''
                                <authorizationdb_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                    <right_name>{}</right_name>
                    <xpath>//*[contains(text(), "{}")]/text()</xpath>
                </authorizationdb_object>  '''.format(rule_yaml['id'],x,authdb,key)

                                oval_state = oval_state + '''
                                    <authorizationdb_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_test" id="oval:mscp:ste:{}" version="1">
                    <value_of>{}</value_of>
                </authorizationdb_state>'''.format(rule_yaml['id'],x,key)
                        x += 1
                        continue
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)
                        oval_test = oval_test + '''
                                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="none_exist" check="none satisfy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>'''.format(x,rule_yaml['id'],x)

                        path = rule_yaml['fix'].split("----")[1].split(" ")[-1]
                        
                        oval_object = oval_object + '''
                <file_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <path>{}</path>
                    <filename xsi:nil="true" />            
                </file_object>'''.format(x,rule_yaml['id'],path.rstrip())
                        x += 1
                        continue

                    
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x,rule_yaml['id'],x+2999)

                            oval_test = oval_test + '''
                                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_rtf_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>
                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_rtfd_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                </file_test>'''.format(x,rule_yaml['id'],x,x+2999,rule_yaml['id'],x+2999)

                            oval_object = oval_object + '''
                <file_object id="oval:mscp:obj:{}" version="1" comment="{}_rtf_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <path>/Library/Security/PolicyBanner.rtf</path>
                    <filename xsi:nil="true" />            
                </file_object>
                <file_object id="oval:mscp:obj:{}" version="1" comment="{}_rtfd_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <path>/Library/Security/PolicyBanner.rtfd</path>
                    <filename xsi:nil="true" />            
                </file_object>'''.format(x,rule_yaml['id'],x+2999,rule_yaml['id'])
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
                '''.format(rule_yaml['id'], x+999, config_file, regex)

                            oval_variable = oval_variable + '''
                    <local_variable id="oval:mscp:var:{}" version="1" datatype="string" comment="{}_var">
                    <object_component object_ref="oval:mscp:obj:{}" item_field="subexpression"/>
                    </local_variable>'''.format(x,rule_yaml['id'],x+999)
                        
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
            '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                        oval_test = oval_test + '''
                <file_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix">
                    <object object_ref="oval:mscp:obj:{}"/>
                    <state state_ref="oval:mscp:ste:{}"/>
                </file_test>'''.format(x,rule_yaml['id'],x,x)
                        
                        if "-" in fix_command and "R" in fix_command or rule_yaml['fix'].split("\n")[2][-1] == "*":
                            behavior = '<behaviors recurse="symlinks and directories" recurse_direction="down" max_depth="-1" recurse_file_system="local"></behaviors>'
                            if "audit" in rule_file:
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
                    </file_object>'''.format(rule_yaml['id'],x,behavior,x,filename)
                        else:
                            oval_object = oval_object + '''
                    <file_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" version="1" comment="{}_object" id="oval:mscp:obj:{}">
                    {}
                    <filepath datatype="string" operation="equals">{}</filepath>
                    
                    </file_object>'''.format(rule_yaml['id'],x,behavior,config_file)
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
                <file_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" version="1" comment="{}_state" id="oval:mscp:ste:{}">'''.format(rule_yaml['id'],x) + state_test + '''
                </file_state>
                        '''
                    
                        x += 1
                        continue
            
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
                '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'],rule_yaml['id'],x)
                                
                                oval_test = oval_test + '''
                <accountinfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </accountinfo_test>
                '''.format(rule_yaml['id'],x,x,x)

                                oval_object = oval_object + '''
                    <accountinfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_object" id="oval:mscp:obj:{}" version="1">
                <username>{}</username>
                </accountinfo_object>
                '''.format(rule_yaml['id'],x,command[5].split()[0])
                                
                                oval_state = oval_state + '''
                                <accountinfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_state" id="oval:mscp:ste:{}" version="1">
                <login_shell>{}</login_shell>
                </accountinfo_state>
                '''.format(rule_yaml['id'],x,shell)
                                x += 1
                                continue
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
                            field_sep = rule_yaml['check'].split("-F")[1].split(" ")[0].replace('\"',"")
               
                            try: 
                        
                                awk_result = rule_yaml['result']['string']
                            
                            except: 
                            
                                awk_result = str(rule_yaml['result']['integer'])
                            
                            awk_search = "^" + awk_search + field_sep + awk_result
 

                        
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)
                        oval_test = oval_test + '''
                        <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <object object_ref="oval:mscp:obj:{}"/>
                </textfilecontent54_test>
                '''.format(x, rule_yaml['id'], x)
                        oval_object = oval_object + '''
                        <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <filepath>{}</filepath>
                    <pattern operation="pattern match">{}</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>
                '''.format(x,rule_yaml['id'],awk_file.rstrip(), awk_search)
                        x += 1
                        continue
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
            </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)
                            oval_test = oval_test + '''
                    <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <object object_ref="oval:mscp:obj:{}"/>
            </textfilecontent54_test>
            '''.format(x, rule_yaml['id'], x)
                            
                            file_path = rule_yaml["check"].split(" ")[-1].rstrip()
                            
                            oval_object = oval_object + '''
                    <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                <filepath>{}</filepath>
                <pattern operation="pattern match">{}</pattern>
                <instance datatype="int">1</instance>
            </textfilecontent54_object>'''.format(x,rule_yaml['id'],file_path,matches)

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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)
                            oval_test = oval_test + '''
                        <textfilecontent54_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <object object_ref="oval:mscp:obj:{}"/>
                </textfilecontent54_test>
                '''.format(x, rule_yaml['id'], x)
                            oval_object = oval_object + '''
                        <textfilecontent54_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
                    <filepath>{}</filepath>
                    <pattern operation="pattern match">{}</pattern>
                    <instance datatype="int">1</instance>
                </textfilecontent54_object>
                '''.format(x,rule_yaml['id'],grep_file.rstrip(),grep_search)
                            x += 1
                            continue
                    
                    if "launchctl" in command[2] or "launchctl" in rule_yaml['fix']:
                        
                        if "disable" in command[2] and "=> true" in rule_yaml['check'] or "unload -w" in rule_yaml['fix']:
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x,rule_yaml['id'],x+999)

                            oval_test = oval_test + '''
                <plist511_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="{}_plist_test" id="oval:mscp:tst:{}" version="2">
                    <object object_ref="oval:mscp:obj:{}" />
                    <state state_ref="oval:mscp:ste:{}" />
                </plist511_test>
                <launchd_test id="oval:mscp:tst:{}" version="1" comment="{}_launchctl_test" check_existence="none_exist" check="none satisfy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <object object_ref="oval:mscp:obj:{}"/>
                
                </launchd_test>'''.format(rule_yaml['id'],x,x,x,x+999,rule_yaml['id'],x+999)
                            
                            domain = str()
                            if "launchctl" not in rule_yaml['check']:
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
                </launchd_object>'''.format(rule_yaml['id'],x,domain,x+999,rule_yaml['id'],domain)
                            
                            status = ""
                            if "enable" in rule_yaml["fix"]:
                                status = "false"
                            else:
                                status = "true"
                            oval_state = oval_state + '''
                <plist511_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="{}_plist_state" id="oval:mscp:ste:{}" version="1">
                    <value_of datatype="boolean" operation="equals">{}</value_of>
                </plist511_state>'''.format(rule_yaml['id'],x,status)
                        
                        elif "launchctl unload" in rule_yaml['fix']:
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x,rule_yaml['id'],x+999)

                            oval_test = oval_test + '''
                <launchd_test id="oval:mscp:tst:{}" version="1" comment="{}_launchctl_test" check_existence="none_exist" check="none satisfy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <object object_ref="oval:mscp:obj:{}"/>
                </launchd_test>'''.format(x,rule_yaml['id'],x)
                            
                            domain = str()
                            
                            if "launchctl" not in rule_yaml['check']:
                                domain = rule_yaml['fix'].split()[4].split('/')[4].replace(".plist","")
                                
                            else:
                                s = command[5].split()[2]
                                domain = re.search('"(.*?)"', s).group(1)
                            
                            oval_object = oval_object + '''
                <launchd_object id="oval:mscp:obj:{}" version="1" comment="{}_launchctl_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <label>{}</label>
                </launchd_object>'''.format(x, rule_yaml['id'],domain)
                        
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
                </definition> '''.format(x,rule_yaml['title'],rule_yaml['references']['cce'][0],rule_yaml['id'],rule_yaml['discussion'].rstrip(),rule_yaml['id'],x)

                            oval_test = oval_test + '''
                <launchd_test id="oval:mscp:tst:{}" version="1" comment="{}_test" check_existence="all_exist" check="all" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <object object_ref="oval:mscp:obj:{}"/>
                </launchd_test>'''.format(x,rule_yaml['id'],x)

                            domain = command[5].split()[2]
                            domain = domain.replace('"','').replace("'",'')

                            oval_object = oval_object + '''
                <launchd_object id="oval:mscp:obj:{}" version="1" comment="{}_object" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos">
                    <label>{}</label>
                </launchd_object>'''.format(x,rule_yaml['id'],domain)
                        x += 1
                        continue    
            
        total_oval = ovalPrefix + "\n<definitions>\n" + oval_definition + "\n</definitions>\n<tests>\n" + oval_test + "\n</tests>\n<objects>\n" + oval_object + "\n</objects>\n"
        if oval_state != "":
            total_oval = total_oval + "<states>\n" + oval_state + "\n</states>\n"
        if oval_variable != "":
            total_oval = total_oval + "\n<variables>\n" + oval_variable + "\n</variables>\n"
        
        total_oval = total_oval + "\n</oval_definitions>"
        
        final_oval = re.sub('(?=\n\[NOTE\])(?s)(.*)\=\n$.*', '<', total_oval)
        
        oval_file = output

        with open(oval_file + "temp",'w') as rite:
            rite.write(final_oval)
            cmd = shutil.which('xmllint')
            rite.close()
            if cmd == None:
                try:
                    os.rename(oval_file + "temp", oval_file)
                except:
                    print("Error writing Oval file.")
            else:
                cmd = cmd + " " + oval_file + "temp --format --output " + oval_file
                
                os.popen(cmd).read()
                if os.path.exists(oval_file):
                    os.remove(oval_file + "temp")
    
if __name__ == "__main__":
    main()