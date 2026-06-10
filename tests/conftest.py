import sys
from pathlib import Path

# Ensure the worktree's src/ is first on sys.path so 'mscp' resolves to the
# package, not the legacy mscp.py script in the repo root.
src = str(Path(__file__).parent.parent / "src")
if src not in sys.path:
    sys.path.insert(0, src)
