---
title: Rules
description: A rules reference.
---

# Rules YAML Format

**id**
The id should match the file name, without the yaml file extension.

**title**
The title is a human-readable title of the rule.

**discussion**
The discussion should provide a concise description of the intended use of the rule.

**check**
Every rule will have a check. Most rules should be able to be validated and checked with a shell based check.

**result**
Expected results from the check.

**fix**
The fix will appear in a document when generated. If a fix includes `[source,bash]` the fix will be used for generating the script to enforce the rule.

**references**
The references include a CCE and a mapping of the security frameworks, guidance, and individual controls, which have been mapped to the rule.

**macos**
The version of macOS for which this rule is validated.

**odv**
Sets Organization Defined Values. If a rule falls under this designation, the odv section will/should be added. At a minimum this field should contain a hint (provides a description when tailoring a baseline) and a default value which replaces the $ODV variable.

**tags**
Tags are keywords used to categorize and identify related rules and can be added to or modified as needed. Tags can also be used to make index-based searching of the rules faster and easier.

**mobileconfig**
The `mobileconfig` and `mobileconfig_info` are related. If `mobileconfig` is set to "true", the information required for creating the mobileconfig configuration profile is required in the `mobileconfig_info` area. 

## Example:

```
id: system_settings_screensaver_timeout_enforce
title: Enforce Screen Saver Timeout
discussion: |
  The screen saver timeout _MUST_ be set to $ODV seconds or a shorter length of time.

  This rule ensures that a full session lock is triggered within no more than $ODV seconds of inactivity.
check: |
  /usr/bin/osascript -l JavaScript << EOS
  function run() {
    let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
  .objectForKey('idleTime'))
    if ( timeout <= $ODV ) {
      return("true")
    } else {
      return("false")
    }
  }
  EOS
result:
  string: 'true'
fix: |
  This is implemented by a Configuration Profile.
references:
  cce:
    - CCE-94390-2
  cci:
    - CCI-000057
  800-53r5:
    - AC-11
    - IA-11
  800-53r4:
    - AC-11
  srg:
    - SRG-OS-000029-GPOS-00010
  disa_stig:
    - N/A
  800-171r3:
    - 03.01.10
    - 03.05.01
  cis:
    benchmark:
      - 2.10.1 (level 1)
    controls v8:
      - 4.3
  cmmc:
    - AC.L2-3.1.10
macOS:
  - '15.0'
odv:
  hint: Number of seconds.
  recommended: 1200
  cis_lvl1: 1200
  cis_lvl2: 1200
  stig: 900
tags:
  - 800-53r5_moderate
  - 800-53r5_high
  - 800-53r5_low
  - 800-53r4_moderate
  - 800-53r4_high
  - 800-171
  - cis_lvl1
  - cis_lvl2
  - cisv8
  - cnssi-1253_moderate
  - cnssi-1253_low
  - cnssi-1253_high
  - cmmc_lvl2
  - stig
severity: medium
mobileconfig: true
mobileconfig_info:
  com.apple.screensaver:
    idleTime: $ODV
```
