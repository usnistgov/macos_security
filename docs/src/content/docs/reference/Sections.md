---
title: Sections
description: A sections reference.
---

# Sections

The `sections` directory contains YAML files that are used to define different sections of your guide.

**name**

This is the name of the section as it would appear in the guide.

**description**

The description of each section as it would appear in the guide.

## Sections Included
```
. auditing
. authentication
. icloud
. inherent
. macos
. not_applicable
. passwordpolicy
. permanent
. srg
. supplemental
. system_settings
. systempreferences
```

## Example:

```
  name: "iCloud"
  description: |
    This section contains the configuration and enforcement of iCloud and the Apple ID service settings.

    NOTE: The check/fix commands outlined in this section _MUST_ be run by a user with with elevated privileges. 
```
