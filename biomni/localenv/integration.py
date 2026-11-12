"""Static catalog helpers and conservative optional-import filtering for A1."""

import ast
import importlib.util
from dataclasses import asdict
from pathlib import Path

from .adapters import ScientificRunner
from .catalog import Catalog


def local_tools(module2api, profile):
    catalog = Catalog.from_file(profile.catalog_file) if profile.catalog_file else Catalog(profile.capabilities)
    runner = ScientificRunner(profile)

    def search_local_capabilities(query: str = ""):
        return [asdict(c) for c in catalog.search(query)[:50]]

    def inspect_local_capability(capability_id: str):
        return asdict(catalog.get(capability_id))

    def run_local_capability(capability_id: str, arguments: list, working_directory: str = "."):
        return runner.capability(catalog.get(capability_id), arguments, cwd=working_directory).to_dict()

    def run_local_script(environment_id: str, script_path: str, arguments: list, working_directory: str = "."):
        env = profile.environments[environment_id]
        if env.kind == "python":
            return runner.python(environment_id, script_path, args=arguments, cwd=working_directory).to_dict()
        if env.kind == "r":
            return runner.r(environment_id, script_path, args=arguments, cwd=working_directory).to_dict()
        raise ValueError("Select an existing Python or R environment")

    helpers = {
        f.__name__: f
        for f in (search_local_capabilities, inspect_local_capability, run_local_capability, run_local_script)
    }
    filtered, blockers = {}, {}
    for module, descriptions in module2api.items():
        path = Path(__file__).parents[1] / "tool" / (module.rsplit(".", 1)[-1] + ".py")
        if not path.exists():
            filtered[module] = list(descriptions)
            continue
        tree = ast.parse(path.read_text())
        global_imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for description in descriptions:
            function = functions.get(description["name"])
            imports = global_imports + (
                [n for n in ast.walk(function) if isinstance(n, (ast.Import, ast.ImportFrom))] if function else []
            )
            missing = set()
            for node in imports:
                roots = (
                    [alias.name.split(".")[0] for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [(node.module or "").split(".")[0]]
                )
                for root in roots:
                    if not root or root == "biomni":
                        continue
                    try:
                        available = importlib.util.find_spec(root) is not None
                    except (ValueError, ImportError):
                        available = False
                    if not available:
                        missing.add(root)
            if missing:
                blockers[description["name"]] = sorted(missing)
            else:
                filtered.setdefault(module, []).append(description)
    schemas = [
        {
            "name": "run_local_script",
            "description": "Run a Python or R script file in an existing named environment, without installing dependencies.",
            "required_parameters": [
                {"name": "environment_id", "type": "str", "description": "Profile environment ID"},
                {"name": "script_path", "type": "str", "description": "Existing script path"},
                {"name": "arguments", "type": "list", "description": "Script arguments"},
            ],
            "optional_parameters": [
                {"name": "working_directory", "type": "str", "description": "Working directory", "default": "."}
            ],
        },
        {
            "name": "search_local_capabilities",
            "description": "Search existing local software and its validation evidence.",
            "required_parameters": [],
            "optional_parameters": [{"name": "query", "type": "str", "description": "Search words", "default": ""}],
        },
        {
            "name": "inspect_local_capability",
            "description": "Inspect a versioned capability, prerequisites and readiness.",
            "required_parameters": [{"name": "capability_id", "type": "str", "description": "Catalog ID"}],
            "optional_parameters": [],
        },
        {
            "name": "run_local_capability",
            "description": "Run an existing catalog executable with explicit arguments; never install.",
            "required_parameters": [
                {"name": "capability_id", "type": "str", "description": "Catalog ID"},
                {"name": "arguments", "type": "list", "description": "Command arguments"},
            ],
            "optional_parameters": [
                {"name": "working_directory", "type": "str", "description": "Working directory", "default": "."}
            ],
        },
    ]
    filtered.setdefault("localenv", []).extend(schemas)
    return filtered, helpers, blockers
