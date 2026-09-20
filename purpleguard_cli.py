"""Console entry point for PurpleGuardAI.

Delegates to the repository's main.py so the packaged CLI and the
developer workflow (`python3 main.py ...`) share one implementation.
"""

import runpy
from pathlib import Path


def main():
    runpy.run_path(
        str(Path(__file__).resolve().parent / "main.py"),
        run_name="__main__",
    )


if __name__ == "__main__":
    main()
