#!/bin/bash

OS=$(/usr/bin/awk -F ": " '/os: /{print $2}' ../VERSION.yaml | /usr/bin/tr -d '"')
CPE=$(/usr/bin/awk '/cpe/{print $2}'  ../VERSION.yaml )
CREATIONDATE=$(date -j -f "%a %b %d %T %Z %Y" "$(date)" "+%Y-%m-%dT%TZ")

/bin/cat > macos-cpe-oval.xml << EOO
<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
    xsi:schemaLocation=" http://oval.mitre.org/XMLSchema/oval-definitions-5 https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#macos https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/macos-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix https://raw.githubusercontent.com/OVALProject/Language/5.11.2/schemas/unix-definitions-schema.xsd">
    <generator>
        <oval:product_name>macOS Security Compliance Project</oval:product_name>
        <oval:schema_version>5.11.2</oval:schema_version>
        <oval:timestamp>$CREATIONDATE</oval:timestamp>
    </generator>
    <definitions>
        <definition id="oval:gov.nist.mscp.content.cpe.oval:def:1" version="1" class="inventory">
            <metadata>
                <title>Apple macOS $OS is installed</title>
                <affected family="macos">
                    <platform>macOS</platform>
                </affected>
                <reference source="CPE" ref_id="cpe:/$CPE"/>
                <description>The operating system installed on the system is Apple macOS ($OS).</description>
            </metadata>
            <criteria operator="AND">
                <criterion comment="The Installed Operating System is Part of the Mac OS Family" test_ref="oval:gov.nist.mscp.content.cpe:tst:1"/>
                <criterion comment="Apple macOS version is greater than or equal to $OS" test_ref="oval:gov.nist.mscp.content.cpe:tst:2"/>
            </criteria>
        </definition>
    </definitions>
    <tests>
        <family_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" check="all" check_existence="only_one_exists"
            comment="The Installed Operating System is Part of the macOS Family" id="oval:gov.nist.mscp.content.cpe:tst:1" version="1">
            <object object_ref="oval:gov.nist.mscp.content.cpe:obj:1"/>
            <state state_ref="oval:gov.nist.mscp.content.cpe:ste:1"/>
        </family_test>
        <plist510_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" check="all" check_existence="only_one_exists" comment="Apple macOS version is greater than $OS"
            id="oval:gov.nist.mscp.content.cpe:tst:2" version="2">
            <object object_ref="oval:gov.nist.mscp.content.cpe:obj:2"/>
            <state state_ref="oval:gov.nist.mscp.content.cpe:ste:2"/>
        </plist510_test>
    </tests>
    <objects>
        <family_object id="oval:gov.nist.mscp.content.cpe:obj:1" version="1" comment="This variable_object represents the family that the operating system belongs to."
            xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"/>
        <plist510_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="The macOS product version plist object." id="oval:gov.nist.mscp.content.cpe:obj:2" version="1">
            <key>ProductVersion</key>
            <filepath>/System/Library/CoreServices/SystemVersion.plist</filepath>
            <instance datatype="int" operation="equals">1</instance>
        </plist510_object>
    </objects>
    <states>
        <family_state id="oval:gov.nist.mscp.content.cpe:ste:1" version="1" comment="The OS is part of the macOS Family." xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
            <family>macos</family>
        </family_state>
        <plist510_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#macos" comment="Is the value is greater than or equal to $OS" id="oval:gov.nist.mscp.content.cpe:ste:2" version="1">
            <value datatype="version" operation="greater than or equal">$OS</value>
        </plist510_state>
    </states>
</oval_definitions>

EOO

/bin/cat > macos-cpe-dictionary.xml << EOCPE
<?xml version="1.0" encoding="UTF-8"?>

<!-- This is a Common Platform Enumeration (CPE) 2.3 document -->
<!-- See https://doi.org/10.6028/NIST.IR.7697 -->

<!-- See https://www.w3.org/TR/xml-model/ -->
<?xml-model href="https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd" schematypens="http://www.w3.org/2001/XMLSchema" title="CPE XML schema"?>
<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:cpe-23="http://scap.nist.gov/schema/cpe-extension/2.3">
    <generator>
        <product_name>macOS Security Compliance Project</product_name>
        <schema_version>2.3</schema_version>
        <timestamp>$CREATIONDATE</timestamp>
    </generator>
    <cpe-item name="cpe:/$CPE">
        <title xml:lang="en-US">Apple macOS $OS</title>
        <notes xml:lang="en-US">
            <note>This CPE Name represents macOS $OS</note>
        </notes>
        <check href="macos-cpe-oval.xml" system="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:gov.nist.mscp.content.cpe.oval:def:1</check>
        <cpe-23:cpe23-item name="cpe:2.3:$CPE:*:*:*:*:*:*:*"/>
    </cpe-item>
</cpe-list>

EOCPE