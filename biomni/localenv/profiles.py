"""Versioned runtime configuration with explicit host and interpreter selection."""

import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ServerProfile:
    alias: str
    address: str
    cpu_threads: int
    memory_gb: float
    gpu: bool = False
    max_jobs: int = 1

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.alias) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.address):
            raise ValueError("Invalid server alias/address")
        if (
            type(self.cpu_threads) is not int
            or self.cpu_threads < 1
            or type(self.max_jobs) is not int
            or self.max_jobs < 1
        ):
            raise ValueError("CPU and concurrency must be positive integers")
        if isinstance(self.memory_gb, bool) or not math.isfinite(self.memory_gb) or self.memory_gb <= 0:
            raise ValueError("Memory must be positive and finite")
        if type(self.gpu) is not bool:
            raise ValueError("GPU must be a boolean")


@dataclass(frozen=True)
class EnvironmentProfile:
    id: str
    kind: str
    interpreter: str
    prefix: str | None = None
    library_paths: tuple = ()
    hosts: tuple = ()

    def __post_init__(self):
        if not self.id or self.kind not in {"python", "r", "cli"} or not Path(self.interpreter).is_absolute():
            raise ValueError("Environment requires an ID, kind and absolute interpreter")
        if self.prefix and not Path(self.prefix).is_absolute():
            raise ValueError("Environment prefix must be absolute")
        if any(not Path(p).is_absolute() for p in self.library_paths):
            raise ValueError("R library paths must be absolute")


@dataclass(frozen=True)
class RuntimeProfile:
    servers: dict = field(default_factory=dict)
    environments: dict = field(default_factory=dict)
    capabilities: list = field(default_factory=list)
    data_path: str = "./data"
    agent_environment: str = "biomni"
    timeout_seconds: int = 600
    catalog_file: str | None = None
    agent_python: str | None = None
    repository: str | None = None
    version: int = 1

    def __post_init__(self):
        if type(self.version) is not int or self.version != 1:
            raise ValueError("Unsupported runtime profile version")
        if type(self.timeout_seconds) is not int or self.timeout_seconds < 1:
            raise ValueError("Timeout must be a positive integer")
        if any(k != v.alias for k, v in self.servers.items()) or any(k != v.id for k, v in self.environments.items()):
            raise ValueError("Profile keys must match their IDs")
        for name in ("agent_python", "repository", "catalog_file"):
            value = getattr(self, name)
            if value and not Path(value).is_absolute():
                raise ValueError(f"{name} must be absolute")
        if self.agent_environment not in self.environments and not self.agent_python:
            raise ValueError("Select an existing agent environment or explicit agent_python")

    @classmethod
    def from_dict(cls, data):
        from .catalog import Capability

        data = dict(data)
        data["servers"] = {k: ServerProfile(**{"alias": k, **v}) for k, v in data.get("servers", {}).items()}
        data["environments"] = {
            k: EnvironmentProfile(**{"id": k, **v}) for k, v in data.get("environments", {}).items()
        }
        data["capabilities"] = [Capability(**v) for v in data.get("capabilities", [])]
        return cls(**data)

    @classmethod
    def from_file(cls, path):
        return cls.from_dict(json.loads(Path(path).read_text()))

    def to_dict(self):
        return asdict(self)

    def python(self):
        return self.agent_python or self.environments[self.agent_environment].interpreter
