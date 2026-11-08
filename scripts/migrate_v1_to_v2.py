#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
migrate_v1_to_v2.py

Migration tool to automatically convert MSCP 1.x projects to MSCP 2.0 format.

This script:
1. Validates the source v1 project structure
2. Identifies customized rules and baselines
3. Maps old rule/baseline IDs to new ones (if changes occurred)
4. Preserves customizations in v2 format
5. Generates a detailed migration report

Usage:
    python3 migrate_v1_to_v2.py <path_to_v1_project> [--output <output_path>] [--dry-run]

Example:
    python3 migrate_v1_to_v2.py /path/to/old_project --output /path/to/new_project
    python3 migrate_v1_to_v2.py /path/to/old_project --dry-run  # Preview changes
"""

import os
import sys
import argparse
import yaml
import json
import glob
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional


class MigrationReport:
    """Tracks migration statistics and issues"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.custom_rules = []
        self.custom_baselines = []
        self.custom_sections = []
        self.rule_mappings = {}
        self.baseline_mappings = {}
        self.warnings = []
        self.errors = []
        self.skipped_items = []
        
    def add_custom_rule(self, rule_id: str, source: str):
        self.custom_rules.append({"id": rule_id, "source": source})
    
    def add_custom_baseline(self, baseline_name: str, source: str):
        self.custom_baselines.append({"name": baseline_name, "source": source})
    
    def add_custom_section(self, section_name: str, source: str):
        self.custom_sections.append({"name": section_name, "source": source})
    
    def add_warning(self, message: str):
        self.warnings.append(message)
    
    def add_error(self, message: str):
        self.errors.append(message)
    
    def add_skipped(self, item_type: str, item_id: str, reason: str):
        self.skipped_items.append({
            "type": item_type,
            "id": item_id,
            "reason": reason
        })
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.start_time.isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            "custom_rules_count": len(self.custom_rules),
            "custom_baselines_count": len(self.custom_baselines),
            "custom_sections_count": len(self.custom_sections),
            "custom_rules": self.custom_rules,
            "custom_baselines": self.custom_baselines,
            "custom_sections": self.custom_sections,
            "warnings_count": len(self.warnings),
            "errors_count": len(self.errors),
            "skipped_count": len(self.skipped_items),
            "warnings": self.warnings,
            "errors": self.errors,
            "skipped_items": self.skipped_items
        }
    
    def print_summary(self):
        """Print human-readable summary"""
        print("\n" + "=" * 70)
        print("MIGRATION REPORT")
        print("=" * 70)
        print(f"\nTimestamp: {self.start_time.isoformat()}")
        print(f"Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds")
        print(f"\nCustomizations Found:")
        print(f"  - Custom Rules: {len(self.custom_rules)}")
        print(f"  - Custom Baselines: {len(self.custom_baselines)}")
        print(f"  - Custom Sections: {len(self.custom_sections)}")
        
        if self.custom_rules:
            print(f"\nCustomized Rules ({len(self.custom_rules)}):")
            for rule in self.custom_rules[:10]:  # Show first 10
                print(f"  - {rule['id']} ({rule['source']})")
            if len(self.custom_rules) > 10:
                print(f"  ... and {len(self.custom_rules) - 10} more")
        
        if self.warnings:
            print(f"\nWarnings ({len(self.warnings)}):")
            for warning in self.warnings[:5]:
                print(f"  [WARNING] {warning}")
            if len(self.warnings) > 5:
                print(f"  ... and {len(self.warnings) - 5} more")
        
        if self.errors:
            print(f"\nErrors ({len(self.errors)}):")
            for error in self.errors[:5]:
                print(f"  [ERROR] {error}")
            if len(self.errors) > 5:
                print(f"  ... and {len(self.errors) - 5} more")
        
        if self.skipped_items:
            print(f"\nSkipped Items ({len(self.skipped_items)}):")
            for item in self.skipped_items[:5]:
                print(f"  - {item['type']}: {item['id']} ({item['reason']})")
            if len(self.skipped_items) > 5:
                print(f"  ... and {len(self.skipped_items) - 5} more")
        
        print("\n" + "=" * 70 + "\n")


class MSCPMigrator:
    """Handles migration from MSCP v1 to v2.0"""
    
    def __init__(self, v1_project_path: str, v2_base_path: str, output_path: str):
        """
        Initialize migrator
        
        Args:
            v1_project_path: Path to MSCP v1 project
            v2_base_path: Path to MSCP v2 repository (for validation)
            output_path: Where to write migrated project
        """
        self.v1_path = Path(v1_project_path)
        self.v2_base_path = Path(v2_base_path)
        self.output_path = Path(output_path)
        self.report = MigrationReport()
        
        # Rule ID mappings for cases where rules were renamed/consolidated
        # Format: {"old_v1_id": "new_v2_id"}
        self.rule_mappings = self._load_rule_mappings()
        
        # Available rules in v2 (loaded from v2 base)
        self.v2_rules = self._load_v2_rules()
    
    def _load_rule_mappings(self) -> Dict[str, str]:
        """Load any rule ID mappings between v1 and v2"""
        # This can be extended to load from a mappings file if needed
        # For now, we assume rule IDs remain consistent between v1 and v2
        return {}
    
    def _load_v2_rules(self) -> Dict[str, str]:
        """Load all available v2 rule IDs for validation"""
        rules = {}
        rules_dir = self.v2_base_path / "rules"
        
        if not rules_dir.exists():
            return rules
        
        for rule_file in rules_dir.rglob("*.yaml"):
            try:
                with open(rule_file, 'r') as f:
                    yaml_data = yaml.safe_load(f)
                    if yaml_data and 'id' in yaml_data:
                        rules[yaml_data['id']] = str(rule_file)
            except Exception as e:
                self.report.add_error(f"Failed to load v2 rule {rule_file}: {str(e)}")
        
        return rules
    
    def validate_v1_project(self) -> bool:
        """
        Validate that v1 project has required structure
        
        Returns:
            True if valid, False otherwise
        """
        required_dirs = ["custom/rules", "custom/sections"]
        
        for req_dir in required_dirs:
            path = self.v1_path / req_dir
            if not path.exists():
                self.report.add_error(f"Missing required directory: {req_dir}")
                return False
        
        # Check for custom files
        custom_rules = list((self.v1_path / "custom/rules").rglob("*.yaml"))
        custom_sections = list((self.v1_path / "custom/sections").rglob("*.yaml"))
        
        if not custom_rules and not custom_sections:
            self.report.add_warning("No custom rules or sections found - migration will be minimal")
        
        return True
    
    def scan_custom_rules(self) -> List[Path]:
        """Find all custom rules in v1 project"""
        custom_rules_dir = self.v1_path / "custom/rules"
        rules = []
        
        if custom_rules_dir.exists():
            rules = list(custom_rules_dir.rglob("*.yaml"))
            for rule in rules:
                try:
                    with open(rule, 'r') as f:
                        yaml_data = yaml.safe_load(f)
                        if yaml_data and 'id' in yaml_data:
                            rule_id = yaml_data['id']
                            self.report.add_custom_rule(rule_id, rule.name)
                            
                            # Check if rule exists in v2
                            mapped_id = self.rule_mappings.get(rule_id, rule_id)
                            if mapped_id not in self.v2_rules:
                                self.report.add_warning(
                                    f"Custom rule '{rule_id}' not found in v2 base rules"
                                )
                except Exception as e:
                    self.report.add_error(f"Failed to parse custom rule {rule}: {str(e)}")
        
        return rules
    
    def scan_custom_baselines(self) -> Dict[str, Path]:
        """Find all custom baseline definitions"""
        baselines = {}
        baselines_dir = self.v1_path / "baselines"
        
        if baselines_dir.exists():
            for baseline_file in baselines_dir.glob("*.yaml"):
                try:
                    with open(baseline_file, 'r') as f:
                        yaml_data = yaml.safe_load(f)
                        if yaml_data:
                            baseline_name = baseline_file.stem
                            baselines[baseline_name] = baseline_file
                            self.report.add_custom_baseline(baseline_name, baseline_file.name)
                except Exception as e:
                    self.report.add_error(f"Failed to parse baseline {baseline_file}: {str(e)}")
        
        return baselines
    
    def scan_custom_sections(self) -> List[Path]:
        """Find all custom sections in v1 project"""
        sections = []
        custom_sections_dir = self.v1_path / "custom/sections"
        
        if custom_sections_dir.exists():
            sections = list(custom_sections_dir.rglob("*.yaml"))
            for section in sections:
                try:
                    with open(section, 'r') as f:
                        yaml_data = yaml.safe_load(f)
                        section_name = section.stem
                        self.report.add_custom_section(section_name, section.name)
                except Exception as e:
                    self.report.add_error(f"Failed to parse custom section {section}: {str(e)}")
        
        return sections
    
    def migrate_custom_rules(self, rules: List[Path]) -> bool:
        """Copy and validate custom rules to v2 output location"""
        output_rules_dir = self.output_path / "custom/rules"
        output_rules_dir.mkdir(parents=True, exist_ok=True)
        
        for rule_file in rules:
            try:
                output_file = output_rules_dir / rule_file.name
                shutil.copy2(rule_file, output_file)
            except Exception as e:
                self.report.add_error(f"Failed to copy rule {rule_file.name}: {str(e)}")
                return False
        
        return True
    
    def migrate_custom_sections(self, sections: List[Path]) -> bool:
        """Copy and validate custom sections to v2 output location"""
        output_sections_dir = self.output_path / "custom/sections"
        output_sections_dir.mkdir(parents=True, exist_ok=True)
        
        for section_file in sections:
            try:
                output_file = output_sections_dir / section_file.name
                shutil.copy2(section_file, output_file)
            except Exception as e:
                self.report.add_error(f"Failed to copy section {section_file.name}: {str(e)}")
                return False
        
        return True
    
    def migrate_baselines(self, baselines: Dict[str, Path]) -> bool:
        """Copy custom baseline definitions"""
        output_baselines_dir = self.output_path / "baselines"
        output_baselines_dir.mkdir(parents=True, exist_ok=True)
        
        for baseline_name, baseline_file in baselines.items():
            try:
                output_file = output_baselines_dir / baseline_file.name
                
                # Read and validate baseline
                with open(baseline_file, 'r') as f:
                    baseline_data = yaml.safe_load(f)
                
                # Validate baseline references rules that exist
                if baseline_data and 'profile' in baseline_data:
                    for section in baseline_data['profile']:
                        if 'rules' in section:
                            for rule_id in section['rules']:
                                mapped_id = self.rule_mappings.get(rule_id, rule_id)
                                if mapped_id not in self.v2_rules:
                                    self.report.add_warning(
                                        f"Baseline '{baseline_name}' references unknown rule '{rule_id}'"
                                    )
                
                shutil.copy2(baseline_file, output_file)
            except Exception as e:
                self.report.add_error(f"Failed to copy baseline {baseline_name}: {str(e)}")
                return False
        
        return True
    
    def create_gitignore(self):
        """Create .gitignore for custom directory if it doesn't exist"""
        gitignore_path = self.output_path / "custom" / ".gitignore"
        gitignore_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Only create if doesn't exist
        if not gitignore_path.exists():
            content = """# MSCP Custom Project Files
# This directory contains your customizations to the MSCP v2.0 baseline

# Ignore common OS files
.DS_Store
Thumbs.db

# Ignore generated output
*.pdf
*.html
*.docx

# Keep custom rules and sections
!rules/
!sections/
!.gitignore
"""
            with open(gitignore_path, 'w') as f:
                f.write(content)
    
    def create_migration_metadata(self):
        """Create metadata documenting the migration"""
        metadata = {
            "migration_version": "1.0",
            "source_version": "v1.x",
            "target_version": "v2.0",
            "migration_date": datetime.now().isoformat(),
            "report": self.report.to_dict()
        }
        
        metadata_path = self.output_path / "custom" / ".migration_metadata.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def migrate(self, dry_run: bool = False) -> bool:
        """
        Execute the full migration process
        
        Args:
            dry_run: If True, validate but don't write files
        
        Returns:
            True if migration successful, False otherwise
        """
        print(f"\n[*] Starting MSCP v1 to v2.0 migration...")
        print(f"Source project: {self.v1_path}")
        print(f"Target directory: {self.output_path}")
        
        # Step 1: Validate v1 project
        print("\n[1] Validating source project...")
        if not self.validate_v1_project():
            print("[!] Validation failed")
            self.report.print_summary()
            return False
        print("[+] Project structure valid")
        
        # Step 2: Scan for customizations
        print("\n[2] Scanning for customizations...")
        custom_rules = self.scan_custom_rules()
        custom_sections = self.scan_custom_sections()
        custom_baselines = self.scan_custom_baselines()
        print(f"[+] Found {len(custom_rules)} custom rules, {len(custom_sections)} custom sections, {len(custom_baselines)} custom baselines")
        
        if dry_run:
            print("\n[*] DRY RUN - No changes will be written")
            self.report.print_summary()
            return True
        
        # Step 3: Create output directory structure
        print("\n[3] Creating output directory structure...")
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Step 4: Migrate custom rules
        if custom_rules:
            print("\n[4] Migrating custom rules...")
            if not self.migrate_custom_rules(custom_rules):
                print("[!] Failed to migrate custom rules")
                self.report.print_summary()
                return False
            print(f"[+] Migrated {len(custom_rules)} custom rules")
        
        # Step 5: Migrate custom sections
        if custom_sections:
            print("\n[5] Migrating custom sections...")
            if not self.migrate_custom_sections(custom_sections):
                print("[!] Failed to migrate custom sections")
                self.report.print_summary()
                return False
            print(f"[+] Migrated {len(custom_sections)} custom sections")
        
        # Step 6: Migrate baselines
        if custom_baselines:
            print("\n[6] Migrating baseline definitions...")
            if not self.migrate_baselines(custom_baselines):
                print("[!] Failed to migrate baselines")
                self.report.print_summary()
                return False
            print(f"[+] Migrated {len(custom_baselines)} baseline definitions")
        
        # Step 7: Create Git ignore and metadata
        print("\n[7] Finalizing migration...")
        self.create_gitignore()
        self.create_migration_metadata()
        print("[+] Created .gitignore and migration metadata")
        
        print("\n[SUCCESS] Migration completed successfully!")
        self.report.print_summary()
        
        # Save detailed report
        report_path = self.output_path / "custom" / "MIGRATION_REPORT.json"
        with open(report_path, 'w') as f:
            json.dump(self.report.to_dict(), f, indent=2)
        print(f"\n[*] Detailed report saved to: {report_path}")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Migrate MSCP v1.x project to v2.0 format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Migrate a v1 project to v2 format
  python3 migrate_v1_to_v2.py /path/to/v1_project --output /path/to/v2_project

  # Preview migration without making changes
  python3 migrate_v1_to_v2.py /path/to/v1_project --dry-run

  # Use custom v2 base repo (default uses current directory)
  python3 migrate_v1_to_v2.py /path/to/v1_project --base /path/to/mscp_v2 --output /path/to/v2_project
        """
    )
    
    parser.add_argument(
        "v1_project",
        help="Path to MSCP v1 project directory"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for migrated v2 project (default: ./mscp_v2_migration)"
    )
    parser.add_argument(
        "--base", "-b",
        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        help="Path to MSCP v2 repository base (default: current MSCP repo)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview migration without writing files"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Validate input path
    if not os.path.exists(args.v1_project):
        print(f"❌ Error: v1 project path does not exist: {args.v1_project}")
        sys.exit(1)
    
    # Set output path
    output_path = args.output or "./mscp_v2_migration"
    
    # Create migrator and run
    migrator = MSCPMigrator(args.v1_project, args.base, output_path)
    success = migrator.migrate(dry_run=args.dry_run)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
