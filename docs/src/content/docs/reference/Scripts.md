---
title: Scripts
description: A scripts reference.
---

## generate_guidance.py script

The generate_guidance script is used to generate the following:

* AsciiDoc document
* HTML guide from asciidoc
* PDF guide from asciidoc
* Configuration Profiles
* Compliance Script
* Excel Document

When running generate guidance, the first argument given must be the baseline desired to create the asciidoc, PDF, and HTML files.

```bash
python3 ./scripts/generate_guidance.py -h
usage: generate_guidance.py [-h] [-l LOGO] [-p] [-r REFERENCE] [-s] [-x] [-H HASH] baseline

Given a baseline, create guidance documents and files.

positional arguments:
  baseline              Baseline YAML file used to create the guide.

optional arguments:
  -h, --help            show this help message and exit
  -l LOGO, --logo LOGO  Full path to logo file to be included in the guide.
  -p, --profiles        Generate configuration profiles for the rules.
  -r REFERENCE, --reference REFERENCE
                        Use the reference ID instead of rule ID for identification.
  -s, --script          Generate the compliance script for the rules.
  -x, --xls             Generate the excel (xls) document for the rules.
  -H HASH, --hash HASH  sign the configuration profiles with subject key ID (hash value without spaces)
```

**Example:**
```
python3 scripts/generate_guidance.py baselines/800-53r5_moderate.yaml
Profile YAML: baselines/800-53r5_moderate.yaml
Output path: /Users/mscp/src/macos_security/build/800-53r5_moderate/800-53r5_moderate.adoc
Generating HTML file from AsciiDoc...
Generating PDF file from AsciiDoc...
```

## generate_baseline.py

The generate baseline script creates a baseline.yaml which can be used for content generation. The output file can be found under `build/baselines`

```bash
python3 scripts/generate_baseline.py -h
usage: generate_baseline.py [-h] [-c] [-k KEYWORD] [-l] [-t]

Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.

optional arguments:
  -h, --help            show this help message and exit
  -c, --controls        Output the 800-53 controls covered by the rules.
  -k KEYWORD, --keyword KEYWORD
                        Keyword tag to collect rules containing the tag.
  -l, --list_tags       List the available keyword tags to search for.
  -t, --tailor          Customize the baseline to your organizations values.
```

**📌 NOTE**\
If the script is called without any flags it will provide a list of all possible keywords.

**Example:**
```
python3 scripts/generate_baseline.py -k all_rules
```

## generate_scap.py

The generate oval script creates the OVAL checks required for SCAP generation.

```bash
usage: generate_scap.py [-h] [-x] [-o] [-l] [-b BASELINE]

Easily generate xccdf, oval, or scap datastream. If no option is defined, it will generate an scap datastream file.

optional arguments:
  -h, --help            show this help message and exit
  -x, --xccdf           Generate an xccdf file.
  -o, --oval            Generate an oval file of the checks.
  -l, --list_tags       List the available keyword tags to search for.
  -b BASELINE, --baseline BASELINE
                        Choose a baseline to generate an xml file for, if none is specified it will generate for every rule found.
```

**Example:**
```
git checkout monterey
python3 scripts/generate_scap.py
builds an SCAP 1.3 document in build/macOS_12.0_Security_Compliance_Benchmark-Revision_3.xml 
```
