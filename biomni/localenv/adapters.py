"""Explicit scientific runners and small reproducible workflow adapters."""

import os
import re
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

INSTALL_PATTERNS = (
    r"\b(?:pip|pip3|uv\s+pip)\s+install\b",
    r"\b(?:conda|mamba|micromamba)\s+(?:install|create|update|upgrade)\b",
    r"\b(?:apt|apt-get|yum|dnf)\s+(?:install|upgrade|update)\b",
    r"(?:install\.packages|BiocManager\s*::\s*install|install_github|install_version)\s*\(",
    r"\b(?:docker|podman|singularity|apptainer)\s+(?:pull|build)\b",
    r"(?:-m|[\"'])\s*pip[\"']?\s*(?:[,\"'\s]+)install\b",
)


def require_no_install(command):
    """Reject recognizable installers; arbitrary analysis code is not sandboxed."""
    text = command if isinstance(command, str) else " ".join(map(str, command))
    if any(re.search(pattern, text, re.I) for pattern in INSTALL_PATTERNS):
        raise PermissionError(
            "Software installation requires a user choice: reuse an existing tool, approve a specific installation, or defer. No installer was run."
        )


@dataclass
class RunResult:
    command: list
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    environment: str | None = None

    def to_dict(self):
        return asdict(self)


def run_command(command, *, cwd, timeout=600, environment=None, extra_env=None):
    require_no_install(command)
    if not isinstance(command, (list, tuple)) or not command or not Path(command[0]).is_absolute():
        raise ValueError("Use an absolute executable and a list of arguments")
    working = Path(cwd).resolve(strict=True)
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    start = time.monotonic()
    process = subprocess.Popen(
        list(map(str, command)),
        cwd=working,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            out, err = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            out, err = process.communicate()
        raise TimeoutError("Scientific command exceeded its timeout; process group terminated") from None
    return RunResult(
        list(map(str, command)), str(working), process.returncode, out, err, time.monotonic() - start, environment
    )


class ScientificRunner:
    def __init__(self, profile):
        self.profile = profile

    def python(self, environment, script, *, cwd, args=()):
        env = self.profile.environments[environment]
        if env.kind != "python":
            raise ValueError("Select a Python environment")
        require_no_install(Path(script).read_text())
        command = [env.interpreter, str(Path(script).resolve()), *map(str, args)]
        return run_command(
            command,
            cwd=cwd,
            timeout=self.profile.timeout_seconds,
            environment=env.id,
            extra_env={
                "PATH": str(Path(env.interpreter).parent) + os.pathsep + os.environ.get("PATH", ""),
                **({"CONDA_PREFIX": env.prefix} if env.prefix else {}),
            },
        )

    def r(self, environment, script, *, cwd, args=()):
        env = self.profile.environments[environment]
        if env.kind != "r":
            raise ValueError("Select an R environment")
        require_no_install(Path(script).read_text())
        return run_command(
            [env.interpreter, "--vanilla", str(Path(script).resolve()), *map(str, args)],
            cwd=cwd,
            timeout=self.profile.timeout_seconds,
            environment=env.id,
            extra_env={
                "R_LIBS_USER": os.pathsep.join(env.library_paths),
                "R_LIBS_SITE": os.pathsep.join(env.library_paths),
            },
        )

    def capability(self, record, args=(), *, cwd):
        if record.readiness_status in {"unavailable", "failed"} or not record.executable:
            raise RuntimeError("Capability unavailable: " + "; ".join(record.restrictions))
        missing = [p for p in record.data_requirements if not Path(p).exists()]
        if missing:
            raise FileNotFoundError("Required data unavailable; choose an existing reference or defer")
        return run_command(
            [record.executable, *map(str, args)],
            cwd=cwd,
            timeout=self.profile.timeout_seconds,
            environment=record.environment,
        )


def fasta_summary(path):
    lengths, length, name = {}, 0, None
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            if line.startswith(">"):
                if name is not None:
                    lengths[name] = length
                name, length = line[1:].split()[0], 0
                if name in lengths:
                    raise ValueError("Duplicate FASTA identifier")
            else:
                if name is None:
                    raise ValueError("Sequence precedes FASTA header")
                length += len(line)
    if name is not None:
        lengths[name] = length
    return {"records": len(lengths), "bases": sum(lengths.values()), "lengths": lengths}


def curated_command(workflow, executables, inputs, output, *, cpus=1):
    """Resolve common CLI workflows; references and executables must already exist."""
    if type(cpus) is not int or cpus < 1:
        raise ValueError("Positive CPU count required")
    for value in inputs.values():
        if not Path(value).is_file():
            raise FileNotFoundError(f"Input/reference missing: {value}")
    forms = {
        "alignment": ("minimap2", ["-a", "-t", str(cpus), "-o", output, inputs.get("reference"), inputs.get("reads")]),
        "bam_summary": ("samtools", ["flagstat", inputs.get("bam")]),
        "vcf_summary": ("bcftools", ["stats", inputs.get("vcf")]),
        "coverage": ("bamCoverage", ["-b", inputs.get("bam"), "-o", output, "-p", str(cpus)]),
        "proteomics_conversion": ("msconvert", [inputs.get("spectra"), "--mzML", "--outdir", output]),
    }
    if workflow not in forms:
        raise ValueError("Unknown curated workflow")
    name, arguments = forms[workflow]
    if any(value is None for value in arguments):
        raise ValueError("Required workflow inputs were not supplied")
    executable = executables.get(name)
    if not executable or not Path(executable).is_file():
        raise FileNotFoundError(f"{name} unavailable; choose an existing installation or defer")
    if workflow == "proteomics_conversion" and Path(inputs["spectra"]).suffix.lower() not in {
        ".mzml",
        ".mzxml",
        ".mgf",
    }:
        raise ValueError("Only open-format spectra are enabled for this Linux adapter")
    return [executable, *arguments]
