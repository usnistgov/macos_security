# MSCP v1 to v2.0 Migration Guide

This guide provides complete instructions for migrating your MSCP v1.x projects and customizations to MSCP v2.0 format.

## Table of Contents

- [Overview](#overview)
- [What Gets Migrated](#what-gets-migrated)
- [What You Need](#what-you-need)
- [Migration Process](#migration-process)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## Overview

The macOS Security Compliance Project (MSCP) v2.0 introduces significant improvements and reorganization. To make transitioning easier, this migration tool automatically converts your v1.x projects to the v2.0 format while preserving all your customizations.

**Key Benefits:**

- Automated, zero-manual-labor migration
- Preserves all customizations and settings
- Validates compatibility with v2.0 rules
- Generates detailed migration report
- Low risk - changes are documented and reversible

## What Gets Migrated

The migration tool automatically transfers:

### 1. Custom Rules

All custom rule files in your `custom/rules/` directory are preserved exactly as-is, enabling you to maintain your organization's specific configurations and requirements.

**Example:** If you have customized `audit_acls_files_configure.yaml`, it will be copied to the new v2.0 project structure.

### 2. Custom Baselines

Your custom baseline definitions in the `baselines/` directory are migrated with full validation to ensure all referenced rules exist in v2.0.

**Example:** A file `baselines/my_organization_baseline.yaml` will be validated and migrated.

### 3. Custom Sections

Any custom section definitions in `custom/sections/` are preserved and migrated to the v2.0 format.

### 4. Project Configuration

- Organization-specific settings
- Custom metadata
- Baseline mappings and references

## What You Need

### Prerequisites

1. **Python 3.6+** - The migration script requires Python 3.6 or later
2. **PyYAML** - Already included in MSCP requirements
3. **Your v1.x project directory** - The directory containing your custom rules, baselines, and sections
4. **MSCP v2.0 repository** - For validation against v2.0 rule base

### Check Your Environment

```bash
# Verify Python version
python3 --version  # Should be 3.6 or higher

# Verify PyYAML is installed
python3 -c "import yaml; print('PyYAML is installed')"
```

## Migration Process

### Step 1: Prepare Your v1 Project

Ensure your v1 project has the proper structure:

```
my_project_v1/
├── custom/
│   ├── rules/
│   │   ├── custom_rule_1.yaml
│   │   └── custom_rule_2.yaml
│   └── sections/
│       └── custom_section.yaml
├── baselines/
│   ├── my_baseline_1.yaml
│   └── my_baseline_2.yaml
└── ... (other files)
```

### Step 2: Review Migration (Dry Run)

Always preview the migration before committing changes:

```bash
cd scripts
python3 migrate_v1_to_v2.py /path/to/v1_project --dry-run
```

This will:

- Validate the v1 project structure
- Scan for all customizations
- Validate compatibility with v2.0
- Show what will be migrated
- NOT write any files

**Example Output:**

```
🔄 Starting MSCP v1 to v2.0 migration...
Source project: /path/to/v1_project
Target directory: ./mscp_v2_migration

1️⃣  Validating source project...
✓ Project structure valid

2️⃣  Scanning for customizations...
✓ Found 5 custom rules, 2 custom sections, 3 custom baselines

🏁 DRY RUN - No changes will be written

==============================================================================
MIGRATION REPORT
==============================================================================

Timestamp: 2025-12-18T14:23:45.123456
Duration: 0.45 seconds

Customizations Found:
  - Custom Rules: 5
  - Custom Baselines: 3
  - Custom Sections: 2

Customized Rules (5):
  - custom_audit_rule (custom_audit_rule.yaml)
  - custom_auth_rule (custom_auth_rule.yaml)
  - ...
```

### Step 3: Execute Migration

Once you've reviewed the dry run output, execute the actual migration:

```bash
python3 migrate_v1_to_v2.py /path/to/v1_project --output /path/to/v2_project
```

**Parameters:**

- `v1_project` (required): Path to your MSCP v1 project
- `--output, -o` (optional): Where to save migrated project (default: `./mscp_v2_migration`)
- `--base, -b` (optional): Path to MSCP v2 repo for validation (default: current MSCP repo)
- `--dry-run` (optional): Preview without writing files
- `--verbose, -v` (optional): Show detailed logging

**Example with custom paths:**

```bash
python3 migrate_v1_to_v2.py ~/projects/my_org_v1 \
  --output ~/projects/my_org_v2 \
  --base ~/Git/macos_security
```

### Step 4: Review Migration Report

After migration completes, review the detailed report:

```bash
cat /path/to/v2_project/custom/MIGRATION_REPORT.json
```

The report includes:

- Migration timestamp and duration
- Count of migrated items
- List of all custom rules, baselines, and sections
- Any warnings or errors that occurred
- Skipped items (if any)

**Example Report:**

```json
{
  "timestamp": "2025-12-18T14:23:45.123456",
  "duration_seconds": 0.45,
  "custom_rules_count": 5,
  "custom_baselines_count": 3,
  "custom_sections_count": 2,
  "warnings_count": 2,
  "errors_count": 0,
  "warnings": [
    "Custom rule 'legacy_audit_rule' not found in v2 base rules",
    "Baseline 'old_baseline' references unknown rule 'removed_rule_id'"
  ]
}
```

## Verification

### Verify All Custom Files Were Migrated

```bash
# Check custom rules
ls -la /path/to/v2_project/custom/rules/

# Check custom sections
ls -la /path/to/v2_project/custom/sections/

# Check custom baselines
ls -la /path/to/v2_project/baselines/
```

### Validate YAML Structure

```bash
# Use the existing v2.0 generation scripts to ensure your migrated project still generates properly
python3 generate_baseline.py

# Generate guidance with your custom baseline
python3 generate_guidance.py --baseline my_baseline_1
```

### Compare Custom Rules

To ensure customizations were preserved:

```bash
# Compare rule structure before and after
diff /path/to/v1_project/custom/rules/my_rule.yaml \
     /path/to/v2_project/custom/rules/my_rule.yaml
```

They should be identical.

## Troubleshooting

### Issue: "Missing required directory: custom/rules"

**Cause:** Your v1 project doesn't have the expected directory structure.

**Solution:** Ensure your v1 project has these directories:

```
custom/
├── rules/
└── sections/
```

Even if they're empty, they should exist.

### Issue: "Custom rule 'xxx' not found in v2 base rules"

**Cause:** A custom rule references a rule ID that doesn't exist in v2.0.

**Possible Solutions:**

1. The rule was renamed in v2.0 - check the migration mappings
2. The rule was removed - review the v2.0 CHANGELOG
3. The rule was completely custom (not from base) - this is normal and safe

**Action:** Check `MIGRATION_REPORT.json` for the full list of warnings.

### Issue: Script fails with "Python 3.6+ required"

**Cause:** Python 3.x is not installed or not in PATH.

**Solution:** Install Python 3.6 or later from python.org

### Issue: "No module named yaml"

**Cause:** PyYAML is not installed in your Python environment.

**Solution:**

```bash
pip3 install pyyaml
```

Or use the MSCP requirements file:

```bash
pip3 install -r requirements.txt
```

### Issue: Migration script is slow

**Cause:** Large v1 project with many rules.

**Solution:** This is normal for large projects. The migration validates every rule and baseline against v2.0, which may take several seconds.

### Issue: Permission denied when writing output

**Cause:** Output directory doesn't have write permissions.

**Solution:**

```bash
# Ensure you have write permissions
chmod 755 /path/to/output/directory

# Or use a different output location
python3 migrate_v1_to_v2.py /path/to/v1_project --output ~/my_migrated_project
```

## FAQ

### Q: Will my customizations be preserved exactly as-is?

**A:** Yes! All custom rules, sections, and baselines are copied verbatim to the v2.0 project. No modifications are made to your custom content.

### Q: What if a custom rule uses a v1-only feature?

**A:** This is unlikely, but if it occurs, you'll see a warning in the migration report. You can review and manually adjust the rule if needed.

### Q: Can I migrate multiple projects?

**A:** Yes! Run the migration script for each v1 project separately:

```bash
python3 migrate_v1_to_v2.py /path/to/project1 --output /path/to/project1_v2
python3 migrate_v1_to_v2.py /path/to/project2 --output /path/to/project2_v2
```

### Q: Can I rollback if something goes wrong?

**A:** Yes! The migration writes to a new output directory, so your original v1 project is untouched. Simply keep your v1 project as-is and re-run migration if needed.

### Q: How do I know if there are compatibility issues?

**A:** The migration report will list any:

- Custom rules that don't exist in v2.0
- Baselines referencing unknown rules
- Skipped items (if any)

These are typically informational warnings, not errors.

### Q: Will the migration tool update my baseline definitions?

**A:** No. The migration preserves your baseline files as-is. However, if you want to take advantage of new v2.0 rules, you can manually add them to your `profile` sections.

### Q: What's the performance impact?

**A:** The migration is lightweight and fast:

- Small projects (< 50 rules): < 1 second
- Medium projects (50-200 rules): 1-5 seconds
- Large projects (200+ rules): 5-30 seconds

### Q: Can I automate the migration in a script?

**A:** Yes! The tool supports programmatic usage:

```bash
#!/bin/bash
# Migrate multiple projects automatically

for project in ~/projects/mscp_v1_*; do
    project_name=$(basename "$project")
    output="~/projects/${project_name/v1_/v2_}"

    echo "Migrating $project_name..."
    python3 migrate_v1_to_v2.py "$project" --output "$output"

    if [ $? -eq 0 ]; then
        echo "✓ $project_name migrated successfully"
    else
        echo "✗ $project_name migration failed"
    fi
done
```

### Q: Where can I get help?

**A:**

- Check the [CHANGELOG.md](../CHANGELOG.md) for v2.0 changes
- Review the [migration report](#step-4-review-migration-report) for specific issues
- Open an issue on [GitHub](https://github.com/usnistgov/macos_security/issues)
- Refer to the main [README.md](../README.md)

## Success Criteria

Migration is successful when:

✅ Script completes without errors  
✅ All custom rules are present in output  
✅ All custom baselines are present in output  
✅ All custom sections are present in output  
✅ Migration report shows 0 errors  
✅ Warnings are reviewed and understood  
✅ Generated guidance uses your custom settings

## Next Steps

After successful migration:

1. **Copy to your v2.0 working directory** (the main MSCP v2.0 repo)
2. **Merge custom directory** with your v2.0 checkout
3. **Run baseline generation** to create updated guidance
4. **Generate reports** for your migrated baselines
5. **Deploy to your environment**

Example:

```bash
# Copy custom directory to MSCP v2.0
cp -r /path/to/v2_project/custom/* ~/Git/macos_security/custom/

# Generate updated guidance
cd ~/Git/macos_security/scripts
python3 generate_guidance.py --baseline my_organization_baseline

# Verify output
ls -la ../build/
```

---

**Version:** 1.0  
**Last Updated:** 2025-12-18  
**Applies to:** MSCP v2.0 and later
