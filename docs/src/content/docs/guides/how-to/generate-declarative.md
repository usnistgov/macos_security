---
title: Generate Declarative Device Management Components
description: A generate-declarative-components reference.
---

Adding the `-D` flag to the `generate_guidance.py` script will generate all the necessary components for the rules that support declarative device management (DDM). Depending on the configurations chosen, the output might differ.

**Generate DDM content**

`➜  macos_security git:(sequoia) ./scripts/generate_guidance.py -D baselines/all_rules.yaml -p -s`

**Example Output (all_rules)**

```
├── activations
│   ├── org.mscp.all_rules.activation.diskmanagement.settings.json
│   ├── org.mscp.all_rules.activation.pam.json
│   ├── org.mscp.all_rules.activation.passcode.settings.json
│   ├── org.mscp.all_rules.activation.sshd.json
│   └── org.mscp.all_rules.activation.sudo.json
├── assets
│   ├── com.apple.pam.zip
│   ├── com.apple.sshd.zip
│   ├── com.apple.sudo.zip
│   ├── org.mscp.all_rules.asset.pam.json
│   ├── org.mscp.all_rules.asset.sshd.json
│   └── org.mscp.all_rules.asset.sudo.json
└── configurations
    ├── org.mscp.all_rules.config.diskmanagement.settings.json
    ├── org.mscp.all_rules.config.pam.json
    ├── org.mscp.all_rules.config.passcode.settings.json
    ├── org.mscp.all_rules.config.sshd.json
    └── org.mscp.all_rules.config.sudo.json
```