"""Read-only inventory, doctor and catalog commands; no automatic installers."""

import argparse
import json
import subprocess
from dataclasses import asdict
from pathlib import Path

from . import Catalog, RuntimeProfile, discover_cli, discover_conda


def doctor(profile):
    python = profile.python()
    modules = ["pandas", "pydantic", "dotenv", "langchain_core", "langgraph", "requests", "tqdm"]
    probe = "import importlib.util,json,sys;print(json.dumps({'python':sys.executable,'modules':{m:importlib.util.find_spec(m) is not None for m in sys.argv[1:]}}))"
    try:
        result = subprocess.run(
            [python, "-c", probe, *modules], capture_output=True, text=True, timeout=30, check=False
        )
        runtime = json.loads(result.stdout) if result.returncode == 0 else {"error": "Interpreter probe failed"}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        runtime = {"error": "Selected existing interpreter is unavailable"}
    missing = [name for name, present in runtime.get("modules", {}).items() if not present]
    return {
        "schema_version": 1,
        "runtime": runtime,
        "missing": missing,
        "ok": not missing and "error" not in runtime,
        "environment_paths": {name: Path(env.interpreter).is_file() for name, env in profile.environments.items()},
        "installation_policy": "Present reuse/install/defer choices. No installations were attempted.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--bin-dir", action="append", default=[])
    inventory.add_argument("--conda-prefix", action="append", default=[])
    inventory.add_argument("--output", required=True)
    check = commands.add_parser("doctor")
    check.add_argument("--profile", required=True)
    search = commands.add_parser("search")
    search.add_argument("--catalog", required=True)
    search.add_argument("query", nargs="?", default="")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--catalog", required=True)
    inspect.add_argument("id")
    args = parser.parse_args(argv)
    if args.command == "inventory":
        if Path(args.output).exists():
            parser.error("Choose a new dated inventory output; existing evidence is not overwritten")
        catalog = Catalog([*discover_cli(args.bin_dir), *discover_conda(args.conda_prefix)])
        catalog.to_file(args.output)
        print(json.dumps({"count": len(catalog.capabilities), "output": args.output}))
    elif args.command == "doctor":
        result = doctor(RuntimeProfile.from_file(args.profile))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    elif args.command == "search":
        print(json.dumps([asdict(c) for c in Catalog.from_file(args.catalog).search(args.query)[:200]], indent=2))
    else:
        try:
            print(json.dumps(asdict(Catalog.from_file(args.catalog).get(args.id)), indent=2))
        except KeyError:
            parser.error("Capability not found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
