---
title: Getting Started
description: A getting-started reference.
---

## Prerequisites
```
. Git
. Python3
  . Python3 Modules
    . pyyaml
    . xlwt
. Ruby
  . Gemfiles
    . asciidoctor
    . asciidoctor-pdf
    . rouge
```

## Getting Started

To work locally, first clone into the repository and install the required Python3 modules and Ruby gems:

```bash
git clone https://github.com/usnistgov/macos_security.git

cd macos_security

# always git checkout one of the OS branches
git checkout sequoia

pip3 install -r requirements.txt --user

bundle install --binstubs --path mscp_gems
```

**❗ IMPORTANT**\
Never work off the `main` branch, always `git checkout` one of the OS branches.
