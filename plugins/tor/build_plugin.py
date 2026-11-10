#!/usr/bin/env python3
# Copyright (C) 2026 barrier-x contributors. GPL; see ../../LICENSE.
"""Build the optional transport as a standalone Python archive."""
import argparse
from pathlib import Path
import zipfile


def build(output):
    source = Path(__file__).resolve().parent
    # Explicit inputs keep caches, test keys and local Tor profiles out of the package.
    with open(output, "xb") as file:
        file.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ("bridge.py", "plugin.json", "README.md"):
                archive.write(source / name, name)
            archive.write(source.parent.parent / "LICENSE", "LICENSE")
            archive.writestr("__main__.py", "from bridge import main\nraise SystemExit(main())\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    build(args.output)
