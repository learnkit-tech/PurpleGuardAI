"""Build-time sanity check for PurpleGuardAI packaging.

Two layers:

1. Structural validation of pyproject.toml (runs everywhere):
   project metadata, console scripts, declared modules, and
   package directories must all exist and agree.

2. A real metadata build through setuptools' PEP 517 backend.
   That needs PEP 621 support plus SPDX license strings, i.e.
   setuptools >= 77, matching build-system.requires. On older
   toolchains this layer is skipped with a notice instead of
   failing spuriously; CI runs a modern toolchain, so the full
   check executes there.
"""

import glob
import os
import re
import shutil
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

REQUIRED_SETUPTOOLS_MAJOR = 77

EXPECTED_NAME = "purpleguard-ai"
EXPECTED_SCRIPT = "purpleguard"


def load_pyproject():
    """Parse pyproject.toml, preferring the stdlib parser."""

    path = os.path.join(PROJECT_ROOT, "pyproject.toml")

    if not os.path.exists(path):
        raise SystemExit("pyproject.toml not found")

    with open(path, "r", encoding="utf-8") as file:
        text = file.read()

    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            # pip always vendors a TOML parser.
            from pip._vendor import tomli as tomllib
        except ImportError:
            return None

    return tomllib.loads(text)


def check_structure(data):
    """Validate pyproject.toml against the repository contents."""

    project = data.get("project")

    if not project:
        raise SystemExit("[project] table missing")

    name = project.get("name")

    if name != EXPECTED_NAME:
        raise SystemExit(
            f"Unexpected project name: {name}"
        )

    if not project.get("version"):
        raise SystemExit("project.version missing")

    if not project.get("description"):
        raise SystemExit("project.description missing")

    requires_python = project.get(
        "requires-python",
        "",
    )

    match = re.search(
        r">=\s*3\.(\d+)",
        requires_python,
    )

    if match and sys.version_info[:2] < (
        3,
        int(match.group(1)),
    ):
        raise SystemExit(
            f"Running Python "
            f"{sys.version_info[0]}.{sys.version_info[1]} does "
            f"not satisfy requires-python '{requires_python}'"
        )

    dependencies = project.get("dependencies", [])

    if (
        not isinstance(dependencies, list)
        or not dependencies
    ):
        raise SystemExit(
            "project.dependencies must be a non-empty list"
        )

    scripts = project.get("scripts", {})

    if EXPECTED_SCRIPT not in scripts:
        raise SystemExit(
            "purpleguard console script missing"
        )

    for script_name, target in scripts.items():

        module = target.partition(":")[0]

        module_path = os.path.join(
            PROJECT_ROOT,
            module.replace(".", os.sep) + ".py",
        )

        if not os.path.exists(module_path):
            raise SystemExit(
                f"Console script '{script_name}' targets "
                f"missing module: {module}"
            )

    setuptools_config = (
        data.get("tool", {})
        .get("setuptools", {})
    )

    for module in setuptools_config.get(
        "py-modules",
        [],
    ):

        if not os.path.exists(
            os.path.join(
                PROJECT_ROOT,
                module + ".py",
            )
        ):
            raise SystemExit(
                f"Declared py-module missing: {module}"
            )

    include_patterns = (
        setuptools_config
        .get("packages", {})
        .get("find", {})
        .get("include", [])
    )

    for pattern in include_patterns:

        package = pattern.split("*")[0].rstrip(".")

        init_path = os.path.join(
            PROJECT_ROOT,
            package.replace(".", os.sep),
            "__init__.py",
        )

        if not os.path.exists(init_path):
            raise SystemExit(
                f"Declared package missing: {package}"
            )

    print(
        "Structure:",
        f"{len(dependencies)} dependencies, "
        f"{len(scripts)} console script(s), "
        f"{len(include_patterns)} package(s)",
    )


def installed_setuptools_major():
    """Return the installed setuptools major version (0 if absent)."""

    from importlib.metadata import (
        PackageNotFoundError,
        version,
    )

    try:
        found = version("setuptools")
    except PackageNotFoundError:
        return 0

    try:
        return int(found.split(".")[0])
    except ValueError:
        return 0


def check_metadata_build():
    """
    Run a real PEP 517 metadata build.

    Skipped on toolchains older than build-system.requires asks for,
    so the check stays green on legacy environments and still does
    the full job on CI.
    """

    installed = installed_setuptools_major()

    if installed < REQUIRED_SETUPTOOLS_MAJOR:

        print(
            f"SKIP: metadata build needs setuptools>="
            f"{REQUIRED_SETUPTOOLS_MAJOR} "
            f"(installed: {installed}); "
            "structural checks still ran"
        )

        return

    original_cwd = os.getcwd()

    metadata_dir = tempfile.mkdtemp(
        prefix="purpleguard-meta-"
    )

    try:

        # The PEP 517 backend resolves pyproject.toml relative to
        # the process working directory.
        os.chdir(PROJECT_ROOT)

        from setuptools import build_meta

        build_meta.prepare_metadata_for_build_wheel(
            metadata_dir
        )

        dist_info_dirs = glob.glob(
            os.path.join(metadata_dir, "*.dist-info")
        )

        if len(dist_info_dirs) != 1:
            raise SystemExit(
                "Expected exactly one dist-info directory, "
                f"found: {dist_info_dirs}"
            )

        dist_info = dist_info_dirs[0]

        with open(
            os.path.join(dist_info, "METADATA")
        ) as file:
            metadata = file.read()

        if f"Name: {EXPECTED_NAME}" not in metadata:
            raise SystemExit(
                "Built metadata does not carry the "
                f"project name {EXPECTED_NAME}"
            )

        with open(
            os.path.join(dist_info, "entry_points.txt")
        ) as file:
            entry_points = file.read()

        if "purpleguard_cli:main" not in entry_points:
            raise SystemExit(
                "purpleguard console script missing "
                "from entry_points.txt"
            )

        print(
            "Metadata build:",
            os.path.basename(dist_info),
        )

    finally:
        os.chdir(original_cwd)
        shutil.rmtree(
            metadata_dir,
            ignore_errors=True,
        )


def main():
    data = load_pyproject()

    if data is None:
        print(
            "SKIP: no TOML parser available "
            "(install Python >= 3.11 or pip)"
        )
        return

    check_structure(data)
    check_metadata_build()

    print("PACKAGING OK")


if __name__ == "__main__":
    main()
