---
title: Customization
description: A customization reference.
---

The project supports modifying existing rules and adding new rules to a baseline, to meet an organizations requirements. For existing rules, only the fields that are being customized need to remain — this ensures that your custom rules will continue working as the project is updated (including updates to meet the needs of future OS releases). Where [tailoring](https://github.com/usnistgov/macos_security/wiki/Tailoring) is used to select which rules to include in a benchmark, customizing is modifying the rules themselves.

To modify an existing rule do the following:

1. Copy the existing rule file to the `custom` folder. The name must rename the same.
2. Remove any fields that don’t need to be modified.
3. Modify the fields that meet your organizational defined values.
4. Run `generate_guidance.py`, the custom version of the rule will be added to the output.

**Example (Configure macOS to Use an Authorized Time Server)**

```YAML
references:
 custom:
   MSCP:
     - MSCP-OS-001
   URL:
     - https://developer.apple.com/documentation/devicemanagement/timeserver
   Remediation Tool:
     - MDM
```

To add an new rule, follow these steps:

1. Create a new rules.yaml file in the `custom` folder.
   1. If the rule contains a configuration profile payload not in the project, add the new payload to `supported_payloads.yaml` in the `includes` folder.
2. Run `generate_baseline.py` to add the new rule to your baseline.
3. Run `generate_guidance.py` against the customized baseline.

**Use Case:**

If you want to include a custom version of rule that still explains the control, but do not want to include a check, result, or fix see below. By adding the `manual` tag to the custom rule will also ensure it does not show up in the compliance script.

**Example Rule (No Check/Result/Fix)**

```YAML
check: |
result: |
fix: | 
tag:
    - manual
