---
title: Baselines
description: A baselines reference.
---

# Baselines

Baseline files are used for the creation of the guide, scripts, and mobileconfig files. Each baseline defines the associated controls which are used to meet a given security profile. 

**title**

A human-readable title for the baseline (e.g., "macOS 13 Security Configuration:NIST SP 800-53 Rev 5 High Impact Security Baseline"). 

**description**

A description of the baseline.

**authors**

A list of authors of the baseline file.

**profile**

* section - this relates to a section (as defined in the `sections` directory) to be used in generating a baseline guide.
* rules - the list of rules applied in the baseline which match the file name and ID of a corresponding rule.

**Example**

```
title: "Apple macOS 13 (Ventura) Test Baseline"
description: |
  This guide describes the prudent actions to take when securing a macOS 12 system against the Test Baseline.   
authors: |
  |===
  |John Smith|NIST
  |Jack Doe|NIST
  |===
profile:
  - section: "Authentication"
    rules:
      - auth_pam_login_smartcard_enforce
      - auth_pam_su_smartcard_enforce
      - auth_pam_sudo_smartcard_enforce
      - auth_smartcard_allow
  - section: "Auditing"
    rules:
      - audit_acls_files_configure
      - audit_acls_files_mode_configure
      - audit_acls_folder_wheel_configure
```
