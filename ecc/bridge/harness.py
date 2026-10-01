"""Describe the ECC harness contract that wires ECC -> PurpleGuard.

The curated snapshot ships ``ecc/ecc2.toml`` whose ``[harness_runners.purpleguard]``
section is the real, documented ECC -> PurpleGuard invocation contract (ECC 2.0
calls ``purpleguard_runner.py`` with ``--cwd``/``--task``). This module exposes
that contract as structured data. It does not execute the harness.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import ECC_SOURCE_COMMIT


def _load_toml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        import tomllib  # Python 3.11+

        with path.open("rb") as handle:
            return tomllib.load(handle), None
    except ModuleNotFoundError:
        pass
    except Exception as exc:  # malformed TOML
        return None, f"toml parse error: {exc}"

    try:
        import tomli  # backport available in this environment

        with path.open("rb") as handle:
            return tomli.load(handle), None
    except ModuleNotFoundError:
        return None, "no TOML parser available (tomllib/tomli missing)"
    except Exception as exc:
        return None, f"toml parse error: {exc}"


def describe(root: Path | None = None) -> dict[str, Any]:
    base = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    config_path = base / "ecc2.toml"

    result: dict[str, Any] = {
        "source": {"file": "ecc/ecc2.toml", "commit": ECC_SOURCE_COMMIT},
        "parsed": False,
        "config_path": str(config_path),
    }
    if not config_path.is_file():
        result["error"] = "ecc2.toml not found in the curated snapshot"
        return result

    data, error = _load_toml(config_path)
    if data is None:
        result["error"] = error or "unable to parse ecc2.toml"
        return result

    runner = (data.get("harness_runners") or {}).get("purpleguard") or {}
    result.update(
        {
            "parsed": True,
            "default_agent": data.get("default_agent"),
            "harness_runners": {
                "purpleguard": {
                    "program": runner.get("program"),
                    "base_args_count": len(runner.get("base_args") or []),
                    "cwd_flag": runner.get("cwd_flag"),
                    "task_flag": runner.get("task_flag"),
                    "project_markers": list(runner.get("project_markers") or []),
                    "env": dict(runner.get("env") or {}),
                }
            },
        }
    )
    return result
