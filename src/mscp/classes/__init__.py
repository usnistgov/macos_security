# classes/__init__.py
"""Domain models for mSCP.

Re-exports the public model classes used throughout mSCP:

- `Baseline`, `Profile`, `Author` — baseline document and its sections.
- `Macsecurityrule`, `Sectionmap` — security rule model and its section
  enumeration.
- `Payload` — configuration profile payload model.
- `RuleLibrary` — ordered, indexed collection of `Macsecurityrule` objects.
"""

from .baseline import Author, Baseline, Profile
from .legacy_baseline import LegacyBaseline, LegacyProfile

# from .filehandler import FileHandler
from .macsecurityrule import Macsecurityrule, Sectionmap
from .payload import Payload
from .rule_library import RuleLibrary

__all__ = [
    "Baseline",
    "LegacyBaseline",
    "LegacyProfile",
    "Macsecurityrule",
    "Payload",
    "Author",
    "Profile",
    "RuleLibrary",
    "Sectionmap",
]
