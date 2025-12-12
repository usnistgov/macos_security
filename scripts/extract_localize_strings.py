#!/usr/bin/env python3
"""
Extract localize strings from YAML files for gettext translation.

This script scans YAML files for !localize tags and extracts the strings
to create a .pot template file that can be used to update .po translation files.
"""

import argparse
import re
import yaml
from pathlib import Path
from typing import Set, List, Tuple
from datetime import datetime


class LocalizeExtractor:
    """Extract localize strings from YAML files."""

    def __init__(self):
        self.localize_strings: Set[str] = set()
        self.string_locations: List[Tuple[str, int, str]] = []

    def _localize_constructor(self, loader, node):
        """Custom YAML constructor to capture !localize strings."""
        value = loader.construct_scalar(node)

        # Store the string and its location
        self.localize_strings.add(value)

        # Get line number if available
        line_num = getattr(node, "start_mark", None)
        line_num = line_num.line + 1 if line_num else 0

        # Store location info
        current_file = getattr(loader, "current_file", "unknown")
        self.string_locations.append((current_file, line_num, value))

        return value

    def extract_from_file(self, file_path: Path) -> None:
        """Extract localize strings from a single YAML file."""
        try:
            # Create a custom loader with our constructor
            loader = yaml.SafeLoader
            loader.add_constructor("!localize", self._localize_constructor)

            with file_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Set current file for location tracking
            yaml_loader = yaml.SafeLoader(content)
            yaml_loader.current_file = str(file_path)

            # Load the YAML (this will trigger our constructor)
            yaml.load(
                content,
                Loader=type(
                    "CustomLoader",
                    (yaml.SafeLoader,),
                    {
                        "__init__": lambda self, stream: (
                            super(type(self), self).__init__(stream),
                            setattr(self, "current_file", str(file_path)),
                        )[1]
                    },
                ),
            )

            print(f"Processed: {file_path}")

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    def scan_directory(self, directory: Path, pattern: str = "**/*.yaml") -> None:
        """Scan directory for YAML files and extract strings."""
        yaml_files = list(directory.glob(pattern))
        yaml_files.extend(directory.glob(pattern.replace("yaml", "yml")))

        print(f"Found {len(yaml_files)} YAML files to process...")

        # Register the constructor globally
        yaml.add_constructor("!localize", self._localize_constructor)
        yaml.SafeLoader.add_constructor("!localize", self._localize_constructor)

        for yaml_file in yaml_files:
            self.extract_from_file(yaml_file)

    def generate_pot_file(self, output_path: Path) -> None:
        """Generate a .pot template file with extracted strings."""
        if not self.localize_strings:
            print("No localize strings found!")
            return

        pot_content = self._generate_pot_header()

        # Sort strings for consistent output
        for string in sorted(self.localize_strings):
            # Find locations for this string
            locations = [
                f"{loc[0]}:{loc[1]}"
                for loc in self.string_locations
                if loc[2] == string
            ]

            pot_content += "\n"

            # Add location comments
            for location in locations:
                pot_content += f"#: {location}\n"

            # Add the msgid and empty msgstr
            pot_content += f'msgid ""\n'

            # Handle multi-line strings
            lines = string.split("\n")
            if len(lines) == 1:
                pot_content += f'"{self._escape_string(string)}"\n'
            else:
                for line in lines:
                    pot_content += f'"{self._escape_string(line)}\\n"\n'

            pot_content += 'msgstr ""\n'

        # Write the file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(pot_content, encoding="utf-8")

        print(
            f"Generated {output_path} with {len(self.localize_strings)} localize strings"
        )

    def _generate_pot_header(self) -> str:
        """Generate the standard .pot file header."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""# YAML localize Strings Template
# Generated automatically from YAML files
#
msgid ""
msgstr ""
"Project-Id-Version: PACKAGE VERSION\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: {now}\\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n"
"Language-Team: LANGUAGE <LL@li.org>\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"""

    def _escape_string(self, s: str) -> str:
        """Escape string for .pot file format."""
        return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    parser = argparse.ArgumentParser(
        description="Extract localize strings from YAML files"
    )
    parser.add_argument("directory", type=Path, help="Directory to scan for YAML files")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("config/locales/messages.pot"),
        help="Output .pot file path (default: config/locales/messages.pot)",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        default="**/*.yaml",
        help="File pattern to match (default: **/*.yaml)",
    )

    args = parser.parse_args()

    if not args.directory.exists():
        print(f"Error: Directory {args.directory} does not exist")
        return 1

    extractor = LocalizeExtractor()
    extractor.scan_directory(args.directory, args.pattern)
    extractor.generate_pot_file(args.output)

    return 0


if __name__ == "__main__":
    exit(main())
