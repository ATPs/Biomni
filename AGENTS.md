# Repository Guidelines

## Project Structure & Module Organization

`biomni/` contains the Python package: `agent/` handles orchestration, `tool/` holds domain-specific functions, `tool/tool_description/` defines their schemas, and `task/` and `eval/` contain benchmarks and evaluation logic. Configuration lives in `biomni/config.py`; environment descriptions live in `biomni/env_desc.py`. Tutorials and integration examples are under `tutorials/`, documentation under `docs/`, and images under `figs/`.

## Server Environment & Customization

Reuse existing server environments and scientific tools. `biomni` uses Python 3.14.10; upstream Python 3.11 configuration is reference only. Do not recreate environments or run bulk setup scripts. Check existing alternatives first.

Keep server paths, API endpoints, and credentials configurable through environment variables or local configuration. Use `.env.example` as a template; never commit credentials, private datasets, or generated analysis outputs.

## Build, Test, and Development Commands

Run from the repository root in zsh, with `/data/p/bin` on `PATH`, using the appropriate existing environment:

- `conda activate biomni`: select the local Python environment.
- `python -m compileall -q biomni`: check Python syntax without importing optional tools.
- `pre-commit run --all-files`: run checks only with existing pre-commit hook environments.
- `make -C docs html`: generate API documentation and HTML when Sphinx is available.

Never install automatically. Present reuse, install, and defer options, then wait for the user's explicit choice before changing software.

## Coding Style & Naming Conventions

Use four-space indentation, `snake_case` functions/modules, and `PascalCase` classes. Follow adjacent code and Ruff's 120-character format in `pyproject.toml`. Pre-commit checks Biome formatting, imports, LF endings, and whitespace. Keep tool signatures and description schemas synchronized; document package and executable requirements.

## Testing Guidelines

There is no dedicated unit-test directory or configured coverage threshold. Add focused regression tests as `tests/test_<feature>.py`; run them with `python -m pytest tests/` when pytest is available. Existing MCP smoke testing uses `python tutorials/examples/expose_biomni_server/test_mcp_server.py` and requires its service dependencies. Include a reproducible agent prompt for new tools; isolate network calls and large downloads.

## Commit & Pull Request Guidelines

Use concise, imperative subjects; the shallow history establishes no stricter convention. Work on feature branches; pre-commit rejects commits to `main`. Follow `CONTRIBUTION.md`: link issues, explain server-specific changes, include validation results and tool test prompts, and update documentation.

## Agent Execution

Follow `.local/AGENTS.md` for private plans, inventories, and configuration. Keep project-only skills in `.codex/skills/`; both directories are Git-ignored.

Run long jobs in detached tmux sessions; check after 300 seconds, then increase intervals. Collect results and clean up completed sessions. Use `/usr/bin/rm` for removals.
