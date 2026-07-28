"""Entry point for `python3 -m fieldkit`."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
