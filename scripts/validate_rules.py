import os
import yaml
import json
import glob
import argparse
from jsonschema import validate, ValidationError, Draft202012Validator

# Load JSON Schema
SCHEMA_PATH = "schema/mscp_rule.json"
RULES_DIR = "rules"

# Load the schema
with open(SCHEMA_PATH, "r") as f:
    schema = json.load(f)

validator = Draft202012Validator(schema)

def validate_yaml_file(file_path, show_only_invalid=False):
    with open(file_path, "r") as f:
        try:
            data = yaml.safe_load(f)
            validator.validate(data)
            if not show_only_invalid:
                print(f"✅ VALID:   {file_path}")
        except ValidationError as e:
            print(f"❌ INVALID: {file_path}")
            print(f"   → {e.message}")
        except Exception as e:
            print(f"⚠️ ERROR:   {file_path}")
            print(f"   → {e}")

def main():
    parser = argparse.ArgumentParser(description="Validate YAML rule files against a JSON Schema.")
    parser.add_argument("--only-invalid", action="store_true", help="Show only invalid YAML files")
    args = parser.parse_args()

    yaml_files = glob.glob(os.path.join(RULES_DIR, "**", "*.y*ml"), recursive=True)
    if not yaml_files:
        print("No YAML files found in rules directory.")
        return

    print(f"Validating {len(yaml_files)} YAML files in '{RULES_DIR}'...\n")
    for file_path in yaml_files:
        validate_yaml_file(file_path, show_only_invalid=args.only_invalid)

if __name__ == "__main__":
    main()
