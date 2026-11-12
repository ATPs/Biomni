"""Metadata-only discovery never imports, launches or installs scientific packages."""

import hashlib
import importlib.metadata
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Capability:
    id: str
    name: str
    domain: str = "software"
    description: str = ""
    entrypoint: str | None = None
    executable: str | None = None
    environment: str | None = None
    version: str | None = None
    version_evidence: tuple = ()
    requirements: tuple = ()
    data_requirements: tuple = ()
    hosts: tuple = ()
    resource_hints: dict = field(default_factory=dict)
    readiness_status: str = "discovered"
    last_checked: str | None = None
    restrictions: tuple = ()
    tags: tuple = ()

    def __post_init__(self):
        if (
            not self.id
            or not self.name
            or self.readiness_status
            not in {"discovered", "launch_checked", "import_checked", "fixture_validated", "unavailable", "failed"}
        ):
            raise ValueError("Invalid capability identity or readiness")
        for name in ("version_evidence", "requirements", "data_requirements", "hosts", "restrictions", "tags"):
            value = getattr(self, name)
            if not isinstance(value, (tuple, list)) or any(not isinstance(x, str) for x in value):
                raise ValueError(f"{name} must be a string list")
            object.__setattr__(self, name, tuple(value))

    def to_dict(self):
        return asdict(self)


class Catalog:
    def __init__(self, capabilities=()):
        self.capabilities = tuple(capabilities)
        self.by_id = {c.id: c for c in self.capabilities}
        if len(self.by_id) != len(self.capabilities):
            raise ValueError("Duplicate capability IDs")

    def get(self, id):
        return self.by_id[id]

    def search(self, query="", *, domain=None, readiness_status=None, host=None):
        return [
            c
            for c in self.capabilities
            if query.casefold()
            in " ".join([c.id, c.name, c.domain, c.description, c.environment or "", *c.tags]).casefold()
            and (domain is None or c.domain == domain)
            and (readiness_status is None or c.readiness_status == readiness_status)
            and (host is None or host in c.hosts)
        ]

    def to_dict(self):
        return {"schema_version": 1, "capabilities": [asdict(c) for c in self.capabilities]}

    def to_file(self, path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + chr(10))

    @classmethod
    def from_dict(cls, data):
        if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise ValueError("Unsupported catalog schema")
        return cls(Capability(**c) for c in data["capabilities"])

    @classmethod
    def from_file(cls, path):
        return cls.from_dict(json.loads(Path(path).read_text()))


def discover_cli(paths):
    if isinstance(paths, (str, Path)):
        paths = [paths]
    found = {}
    for root in map(Path, paths):
        for path in sorted(root.iterdir()) if root.is_dir() else [root]:
            if path.is_dir() and not path.is_symlink():
                continue
            absolute = str(path.absolute())
            resolved = path.resolve(strict=False)
            exists = resolved.is_file() and os.access(resolved, os.X_OK)
            found[absolute] = Capability(
                "cli:" + path.name + ":" + hashlib.sha256(absolute.encode()).hexdigest()[:12],
                path.name,
                domain="cli",
                entrypoint=absolute,
                executable=str(resolved),
                readiness_status="discovered" if exists else "unavailable",
                restrictions=() if exists else ("Dangling link or non-executable path",),
            )
    return list(found.values())


def discover_conda(prefixes):
    if isinstance(prefixes, (str, Path)):
        prefixes = [prefixes]
    records = []
    for prefix in map(Path, prefixes):
        if not (prefix / "conda-meta").is_dir():
            continue
        versions = set()
        for path in (prefix / "conda-meta").glob("python-*.json"):
            try:
                meta = json.loads(path.read_text())
                if meta.get("name") != "python":
                    continue
                match = re.match(r"^(\d+\.\d+)(?:\.|$)", meta["version"])
                if match:
                    versions.add(match[1])
            except (OSError, ValueError, KeyError):
                continue
        identity = prefix.name + ":" + hashlib.sha256(str(prefix).encode()).hexdigest()[:12]
        active = next(iter(versions)) if len(versions) == 1 else None
        records.append(
            Capability(
                "environment:" + identity,
                prefix.name,
                domain="environment",
                executable=str(prefix / "bin/python"),
                environment=str(prefix),
                version=active,
            )
        )
        if active is None:
            continue
        packages = {}
        site = prefix / "lib" / ("python" + active) / "site-packages"
        for dist in importlib.metadata.distributions(path=[str(site)]):
            name, version = dist.metadata.get("Name"), dist.version
            if name and version:
                key = re.sub(r"[-_.]+", "-", name).lower()
                packages.setdefault(key, {"name": name, "versions": set()})["versions"].add(version)
        for key, item in sorted(packages.items()):
            versions = tuple(sorted(item["versions"]))
            records.append(
                Capability(
                    "python:" + identity + ":" + key,
                    item["name"],
                    domain="python-package",
                    environment=str(prefix),
                    version=versions[0] if len(versions) == 1 else None,
                    version_evidence=versions,
                    restrictions=("Conflicting metadata; validate actual imported version",)
                    if len(versions) > 1
                    else (),
                )
            )
    return records
