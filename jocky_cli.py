"""Thin CLI shim installed by pip as the `jocky` entry point."""
import sys
import os

# Ensure the jocky repo root is on the path
_repo = os.path.dirname(os.path.abspath(__file__))
if _repo not in sys.path:
    sys.path.insert(0, _repo)

from main import cli  # noqa: E402

def main():
    cli()

if __name__ == "__main__":
    main()
