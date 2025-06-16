---
title: Generate Mapping
description: A generate-mapping reference.
---

The generate mapping script allows you to quickly create custom rules and baselines for a compliance framework not published by the project. This is achieved by creating a CSV that contains controls from one framework (Column 1) to one supported by the project (Column 2). 

**CSV Format**
```csv
800-171r2,800-53r5
3.1.1,"AC-2, AC-3, AC-17"
3.1.2,"AC-2, AC-3, AC-17"
3.1.3,AC-4
3.1.4,AC-5
```

By default, the script is designed to map a framework to NIST SP 800-53r5. Adding `-f` allows you to map to another supported framework.

**Generate custom rule files**
```
➜  macos_security git:(sequoia) ./scripts/generate_mapping.py ~/Desktop/171-to-53.csv
Mapping CSV: /Users/mscp/Desktop/171-to-53.csv
Source compliance framework: 800-53r5
auth_pam_login_smartcard_enforce - 800-53r5 IA-2(1) maps to 800-171r2 3.5.3
auth_pam_login_smartcard_enforce - 800-53r5 IA-2(8) maps to 800-171r2 3.5.4
auth_smartcard_allow - 800-53r5 IA-2(1) maps to 800-171r2 3.5.3
auth_pam_sudo_smartcard_enforce - 800-53r5 IA-2(1) maps to 800-171r2 3.5.3
auth_pam_sudo_smartcard_enforce - 800-53r5 IA-2(8) maps to 800-171r2 3.5.4
auth_smartcard_enforce - 800-53r5 IA-2 maps to 800-171r2 3.5.1
....
sysprefs_improve_siri_dictation_disable - 800-53r5 AC-20 maps to 800-171r2 3.1.20
sysprefs_improve_siri_dictation_disable - 800-53r5 CM-7 maps to 800-171r2 3.4.6
sysprefs_improve_siri_dictation_disable - 800-53r5 CM-7(1) maps to 800-171r2 3.4.7
800-171r2.yaml baseline file created in build/800-171r2/baseline/
Move all of the folders in rules into the custom folder.
```

For a compliance framework such as the CIS Controls v8. Column 2 header would be `cis/controls v8` and the same would be used for the `-f` option.
