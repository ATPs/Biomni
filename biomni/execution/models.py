"""Versioned task interfaces. Credentials belong only in the stdin envelope."""

import math
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class JobSpec:
    owner: str
    server: str
    prompt: str
    model: str
    provider: str
    cpu_threads: int = 1
    memory_gb: float = 4
    gpu: bool = False
    runtime_profile: dict = field(default_factory=dict)
    input_paths: tuple = ()
    command: tuple = ()
    timeout_seconds: int = 600
    schema_version: int = 1

    def __post_init__(self):
        for name in ("owner", "server", "provider"):
            if not isinstance(getattr(self, name), str) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,128}", getattr(self, name)
            ):
                raise ValueError(f"Invalid {name}")
        if (
            not isinstance(self.model, str)
            or not 0 < len(self.model) <= 512
            or not isinstance(self.prompt, str)
            or len(self.prompt) > 1000000
        ):
            raise ValueError("Invalid model or prompt")
        if type(self.cpu_threads) is not int or self.cpu_threads < 1:
            raise ValueError("CPU request must be a positive integer")
        if isinstance(self.memory_gb, bool) or not math.isfinite(self.memory_gb) or self.memory_gb <= 0:
            raise ValueError("Memory request must be finite and positive")
        if type(self.gpu) is not bool or type(self.timeout_seconds) is not int or self.timeout_seconds < 1:
            raise ValueError("Invalid GPU or timeout request")
        if self.schema_version != 1:
            raise ValueError("Unsupported task schema")
        if any(not isinstance(p, str) or not Path(p).is_absolute() for p in self.input_paths):
            raise ValueError("Input paths must be absolute")
        if self.command and (not isinstance(self.command, (tuple, list)) or not Path(self.command[0]).is_absolute()):
            raise ValueError("Use an absolute command executable")

        def check(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in {"api_key", "token", "password", "secret"}:
                        raise ValueError("Job specifications cannot contain credentials")
                    check(child)
            elif isinstance(value, (tuple, list)):
                for child in value:
                    check(child)

        check(self.runtime_profile)

    @classmethod
    def from_dict(cls, value):
        return cls(**value)

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Artifact:
    owner: str
    job_id: str
    relative_path: str
    size_bytes: int
    modified_time: float
