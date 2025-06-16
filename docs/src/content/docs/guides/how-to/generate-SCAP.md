---
title: Generate SCAP
description: A generate-scap reference.
---

To generate SCAP, OVAL, or XCCDF run the `generate_scap.py` script.

**❗ IMPORTANT**\
Never work off the `main` branch, always `git checkout` one of the OS branches.

When running the `generate_scap.py` with no arguments, it will generate an SCAP 1.3 document with an XCCDF profile for every baseline available as a tag in the `rules` and `custom` folder.

Running `generate_scap.py` with the `-x` argument it will generate an XCCDF document and running `generate_scap.py` with the `-o` argument will generate an OVAL document.

Documents can be generated for just a specific baseline using the `-b` argument. The baselines that the `generate_scap.py` scripts sees are tags that are listed on rule files in `rules` and in `custom`. The baselines can be listed with the `-l` argument.

**Built-in Baseline**

```bash
➜  macos_security git:(sequoia) ./scripts/generate_scap.py
./scripts/generate_scap.py -l 
800-171
800-53r4_high
800-53r4_low
800-53r4_moderate
800-53r5_high
800-53r5_low
800-53r5_moderate
800-53r5_privacy
cis_lvl1
cis_lvl2
cisv8
cnssi-1253
stig
➜  macos_security git:(ventura) ./scripts/generate_scap.py -b stig -x
```
This would generate an XCCDF document in the `build` folder for just the stig baseline.

## SCAP References

[Security Content Automation Protocol (SCAP) 1.3](https://csrc.nist.gov/projects/security-content-automation-protocol/scap-releases/scap-1-3)

That page has links to most of the SCAP-related normative documents.

An SCAP data stream (typically) consists of several XML documents knit together in a containing XML document.
The component documents are
- An XCCDF document
- An OVAL document referenced by the XCCDF document
- An OCIL document referenced by the XCCDF document
- A CPE dictionary document referenced by the XCCDF document
- An OVAL document referenced by the CPE dictionary document

[National Checklist Program for IT Products Guidelines for Checklist Users and Developers](https://csrc.nist.gov/publications/detail/sp/800-70/rev-4/final)

[National Checklist Program Repository](https://nvd.nist.gov/ncp/repository)
