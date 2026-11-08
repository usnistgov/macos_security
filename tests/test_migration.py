#!/usr/bin/env python3
"""
test_migration.py

Unit tests for the MSCP v1 to v2.0 migration tool.

Run tests with:
    python3 -m pytest test_migration.py -v
    
Or without pytest:
    python3 test_migration.py
"""

import unittest
import tempfile
import shutil
import json
import yaml
from pathlib import Path
import sys
import os

# Add scripts directory to path so we can import the migration module
scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts')
sys.path.insert(0, scripts_dir)

# Import after path is set
try:
    from migrate_v1_to_v2 import MSCPMigrator, MigrationReport
except ImportError as e:
    print(f"Error: Could not import migration module. Make sure migrate_v1_to_v2.py is in the scripts directory.")
    print(f"Import error: {e}")
    sys.exit(1)


class TestMigrationReport(unittest.TestCase):
    """Tests for MigrationReport class"""
    
    def setUp(self):
        self.report = MigrationReport()
    
    def test_initialization(self):
        """Test report initializes with empty data"""
        self.assertEqual(len(self.report.custom_rules), 0)
        self.assertEqual(len(self.report.custom_baselines), 0)
        self.assertEqual(len(self.report.custom_sections), 0)
        self.assertEqual(len(self.report.warnings), 0)
        self.assertEqual(len(self.report.errors), 0)
    
    def test_add_custom_rule(self):
        """Test adding custom rule to report"""
        self.report.add_custom_rule("test_rule_1", "test_rule_1.yaml")
        self.assertEqual(len(self.report.custom_rules), 1)
        self.assertEqual(self.report.custom_rules[0]["id"], "test_rule_1")
    
    def test_add_custom_baseline(self):
        """Test adding custom baseline to report"""
        self.report.add_custom_baseline("my_baseline", "my_baseline.yaml")
        self.assertEqual(len(self.report.custom_baselines), 1)
        self.assertEqual(self.report.custom_baselines[0]["name"], "my_baseline")
    
    def test_add_warning(self):
        """Test adding warning to report"""
        self.report.add_warning("Test warning")
        self.assertEqual(len(self.report.warnings), 1)
        self.assertIn("Test warning", self.report.warnings)
    
    def test_add_error(self):
        """Test adding error to report"""
        self.report.add_error("Test error")
        self.assertEqual(len(self.report.errors), 1)
        self.assertIn("Test error", self.report.errors)
    
    def test_to_dict(self):
        """Test converting report to dictionary"""
        self.report.add_custom_rule("test_rule", "test_rule.yaml")
        self.report.add_warning("Test warning")
        
        report_dict = self.report.to_dict()
        
        self.assertIn("timestamp", report_dict)
        self.assertIn("custom_rules_count", report_dict)
        self.assertIn("warnings_count", report_dict)
        self.assertEqual(report_dict["custom_rules_count"], 1)
        self.assertEqual(report_dict["warnings_count"], 1)


class TestMSCPMigrator(unittest.TestCase):
    """Tests for MSCPMigrator class"""
    
    def setUp(self):
        """Create temporary directories for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.v1_project = os.path.join(self.temp_dir, "v1_project")
        self.v2_base = os.path.join(self.temp_dir, "v2_base")
        self.output_dir = os.path.join(self.temp_dir, "output")
        
        # Create basic directory structures
        os.makedirs(os.path.join(self.v1_project, "custom/rules"), exist_ok=True)
        os.makedirs(os.path.join(self.v1_project, "custom/sections"), exist_ok=True)
        os.makedirs(os.path.join(self.v1_project, "baselines"), exist_ok=True)
        
        os.makedirs(os.path.join(self.v2_base, "rules"), exist_ok=True)
        
        self.migrator = MSCPMigrator(self.v1_project, self.v2_base, self.output_dir)
    
    def tearDown(self):
        """Clean up temporary directories"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test migrator initializes correctly"""
        self.assertEqual(str(self.migrator.v1_path), self.v1_project)
        self.assertEqual(str(self.migrator.output_path), self.output_dir)
        self.assertIsNotNone(self.migrator.report)
    
    def test_validate_v1_project_valid(self):
        """Test validation succeeds with proper structure"""
        result = self.migrator.validate_v1_project()
        self.assertTrue(result)
    
    def test_validate_v1_project_missing_dir(self):
        """Test validation fails with missing directory"""
        # Remove custom/rules directory
        shutil.rmtree(os.path.join(self.v1_project, "custom/rules"))
        
        result = self.migrator.validate_v1_project()
        self.assertFalse(result)
        self.assertTrue(len(self.migrator.report.errors) > 0)
    
    def test_scan_custom_rules_empty(self):
        """Test scanning empty custom rules directory"""
        rules = self.migrator.scan_custom_rules()
        self.assertEqual(len(rules), 0)
    
    def test_scan_custom_rules_with_files(self):
        """Test scanning custom rules with files"""
        # Create a test rule file
        rule_content = {
            "id": "test_rule_1",
            "title": "Test Rule",
            "discussion": "Test discussion"
        }
        
        rule_file = os.path.join(self.v1_project, "custom/rules/test_rule_1.yaml")
        with open(rule_file, 'w') as f:
            yaml.dump(rule_content, f)
        
        rules = self.migrator.scan_custom_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(self.migrator.report.custom_rules), 1)
    
    def test_scan_custom_baselines(self):
        """Test scanning custom baselines"""
        # Create a test baseline file
        baseline_content = {
            "title": "Test Baseline",
            "profile": [
                {
                    "section": "audit",
                    "rules": ["test_rule_1"]
                }
            ]
        }
        
        baseline_file = os.path.join(self.v1_project, "baselines/test_baseline.yaml")
        with open(baseline_file, 'w') as f:
            yaml.dump(baseline_content, f)
        
        baselines = self.migrator.scan_custom_baselines()
        self.assertEqual(len(baselines), 1)
        self.assertEqual(len(self.migrator.report.custom_baselines), 1)
    
    def test_scan_custom_sections(self):
        """Test scanning custom sections"""
        # Create a test section file
        section_content = {
            "name": "custom_audit",
            "title": "Custom Audit"
        }
        
        section_file = os.path.join(self.v1_project, "custom/sections/custom_audit.yaml")
        with open(section_file, 'w') as f:
            yaml.dump(section_content, f)
        
        sections = self.migrator.scan_custom_sections()
        self.assertEqual(len(sections), 1)
        self.assertEqual(len(self.migrator.report.custom_sections), 1)
    
    def test_migrate_custom_rules(self):
        """Test migrating custom rules"""
        # Create test rule files
        rule_files = []
        for i in range(2):
            rule_content = {"id": f"test_rule_{i}", "title": f"Test Rule {i}"}
            rule_file = os.path.join(self.v1_project, f"custom/rules/test_rule_{i}.yaml")
            with open(rule_file, 'w') as f:
                yaml.dump(rule_content, f)
            rule_files.append(Path(rule_file))
        
        # Migrate rules
        result = self.migrator.migrate_custom_rules(rule_files)
        self.assertTrue(result)
        
        # Verify files were copied
        output_rules_dir = os.path.join(self.output_dir, "custom/rules")
        self.assertTrue(os.path.exists(output_rules_dir))
        self.assertEqual(len(os.listdir(output_rules_dir)), 2)
    
    def test_migrate_custom_sections(self):
        """Test migrating custom sections"""
        # Create test section file
        section_content = {"name": "custom", "title": "Custom"}
        section_file = os.path.join(self.v1_project, "custom/sections/custom.yaml")
        with open(section_file, 'w') as f:
            yaml.dump(section_content, f)
        
        # Migrate sections
        result = self.migrator.migrate_custom_sections([Path(section_file)])
        self.assertTrue(result)
        
        # Verify file was copied
        output_sections_dir = os.path.join(self.output_dir, "custom/sections")
        self.assertTrue(os.path.exists(output_sections_dir))
        self.assertEqual(len(os.listdir(output_sections_dir)), 1)
    
    def test_migrate_baselines(self):
        """Test migrating baselines"""
        # Create test baseline file
        baseline_content = {
            "title": "Test Baseline",
            "profile": [{"section": "audit", "rules": []}]
        }
        baseline_file = Path(os.path.join(self.v1_project, "baselines/test.yaml"))
        with open(baseline_file, 'w') as f:
            yaml.dump(baseline_content, f)
        
        # Migrate baselines
        result = self.migrator.migrate_baselines({"test": baseline_file})
        self.assertTrue(result)
        
        # Verify file was copied
        output_baselines_dir = os.path.join(self.output_dir, "baselines")
        self.assertTrue(os.path.exists(output_baselines_dir))
        self.assertEqual(len(os.listdir(output_baselines_dir)), 1)
    
    def test_create_gitignore(self):
        """Test creating .gitignore file"""
        self.migrator.create_gitignore()
        
        gitignore_path = os.path.join(self.output_dir, "custom/.gitignore")
        self.assertTrue(os.path.exists(gitignore_path))
        
        with open(gitignore_path, 'r') as f:
            content = f.read()
            self.assertIn("*.pdf", content)
            self.assertIn("*.html", content)
    
    def test_create_migration_metadata(self):
        """Test creating migration metadata"""
        self.migrator.create_migration_metadata()
        
        metadata_path = os.path.join(self.output_dir, "custom/.migration_metadata.json")
        self.assertTrue(os.path.exists(metadata_path))
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            self.assertIn("migration_version", metadata)
            self.assertEqual(metadata["source_version"], "v1.x")
            self.assertEqual(metadata["target_version"], "v2.0")
    
    def test_dry_run_mode(self):
        """Test dry run mode doesn't write files"""
        # Create test rule
        rule_content = {"id": "test_rule", "title": "Test"}
        rule_file = os.path.join(self.v1_project, "custom/rules/test_rule.yaml")
        with open(rule_file, 'w') as f:
            yaml.dump(rule_content, f)
        
        # Run migration in dry-run mode
        result = self.migrator.migrate(dry_run=True)
        self.assertTrue(result)
        
        # Verify output directory was NOT created
        self.assertFalse(os.path.exists(self.output_dir))


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for complete migration scenarios"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.v1_project = os.path.join(self.temp_dir, "v1_project")
        self.v2_base = os.path.join(self.temp_dir, "v2_base")
        self.output_dir = os.path.join(self.temp_dir, "output")
        
        os.makedirs(os.path.join(self.v1_project, "custom/rules"), exist_ok=True)
        os.makedirs(os.path.join(self.v1_project, "custom/sections"), exist_ok=True)
        os.makedirs(os.path.join(self.v1_project, "baselines"), exist_ok=True)
        os.makedirs(os.path.join(self.v2_base, "rules"), exist_ok=True)
    
    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_full_migration_with_all_components(self):
        """Test migration with rules, sections, and baselines"""
        # Create custom rule
        rule_content = {
            "id": "custom_audit_rule",
            "title": "Custom Audit Rule"
        }
        rule_file = os.path.join(self.v1_project, "custom/rules/custom_audit_rule.yaml")
        with open(rule_file, 'w') as f:
            yaml.dump(rule_content, f)
        
        # Create custom section
        section_content = {"name": "custom", "title": "Custom"}
        section_file = os.path.join(self.v1_project, "custom/sections/custom.yaml")
        with open(section_file, 'w') as f:
            yaml.dump(section_content, f)
        
        # Create custom baseline
        baseline_content = {
            "title": "My Baseline",
            "profile": [{
                "section": "audit",
                "rules": ["custom_audit_rule"]
            }]
        }
        baseline_file = os.path.join(self.v1_project, "baselines/my_baseline.yaml")
        with open(baseline_file, 'w') as f:
            yaml.dump(baseline_content, f)
        
        # Run migration
        migrator = MSCPMigrator(self.v1_project, self.v2_base, self.output_dir)
        result = migrator.migrate(dry_run=False)
        
        self.assertTrue(result)
        
        # Verify all components were migrated
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/rules/custom_audit_rule.yaml")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/sections/custom.yaml")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "baselines/my_baseline.yaml")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/.migration_metadata.json")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/.gitignore")))
    
    def test_migration_with_nested_rule_structure(self):
        """Test migration with nested rule directories"""
        # Create nested rule structure
        os.makedirs(os.path.join(self.v1_project, "custom/rules/audit"), exist_ok=True)
        
        rule_content = {"id": "nested_rule", "title": "Nested"}
        rule_file = os.path.join(self.v1_project, "custom/rules/audit/nested_rule.yaml")
        with open(rule_file, 'w') as f:
            yaml.dump(rule_content, f)
        
        # Run migration
        migrator = MSCPMigrator(self.v1_project, self.v2_base, self.output_dir)
        result = migrator.migrate(dry_run=False)
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/rules/audit/nested_rule.yaml")))
    
    def test_empty_project_migration(self):
        """Test migrating empty project (no customizations)"""
        migrator = MSCPMigrator(self.v1_project, self.v2_base, self.output_dir)
        result = migrator.migrate(dry_run=False)
        
        self.assertTrue(result)
        # .gitignore and metadata should still be created
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/.gitignore")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "custom/.migration_metadata.json")))


class TestErrorHandling(unittest.TestCase):
    """Tests for error handling and edge cases"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_invalid_yaml_handling(self):
        """Test handling of invalid YAML files"""
        v1_project = os.path.join(self.temp_dir, "v1")
        v2_base = os.path.join(self.temp_dir, "v2")
        output_dir = os.path.join(self.temp_dir, "out")
        
        os.makedirs(os.path.join(v1_project, "custom/rules"), exist_ok=True)
        os.makedirs(os.path.join(v2_base, "rules"), exist_ok=True)
        
        # Create invalid YAML file
        rule_file = os.path.join(v1_project, "custom/rules/bad.yaml")
        with open(rule_file, 'w') as f:
            f.write("invalid: yaml: content [")
        
        # Migration should handle gracefully
        migrator = MSCPMigrator(v1_project, v2_base, output_dir)
        result = migrator.migrate(dry_run=False)
        
        # Should have error but still complete
        self.assertTrue(len(migrator.report.errors) > 0)
    
    def test_nonexistent_v1_path(self):
        """Test handling of nonexistent v1 project path"""
        v1_project = os.path.join(self.temp_dir, "nonexistent")
        v2_base = os.path.join(self.temp_dir, "v2")
        output_dir = os.path.join(self.temp_dir, "out")
        
        os.makedirs(v2_base, exist_ok=True)
        
        migrator = MSCPMigrator(v1_project, v2_base, output_dir)
        result = migrator.validate_v1_project()
        
        self.assertFalse(result)
        self.assertTrue(len(migrator.report.errors) > 0)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestMigrationReport))
    suite.addTests(loader.loadTestsFromTestCase(TestMSCPMigrator))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegrationScenarios))
    suite.addTests(loader.loadTestsFromTestCase(TestErrorHandling))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    # Try to run with pytest if available, otherwise use unittest
    try:
        import pytest
        exit_code = pytest.main([__file__, "-v"])
    except ImportError:
        print("pytest not found, running with unittest...\n")
        exit_code = run_tests()
    
    sys.exit(exit_code)
