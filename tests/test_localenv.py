import json
import tempfile
import unittest
from pathlib import Path

from biomni.localenv import Capability, Catalog, RuntimeProfile, ServerProfile, discover_cli, discover_conda
from biomni.localenv.adapters import fasta_summary, require_no_install, run_command


class CatalogTests(unittest.TestCase):
    def test_profile_validation_and_roundtrip(self):
        data = {
            "version": 1,
            "agent_python": "/some/existing/python",
            "servers": {"test": {"address": "host.example", "cpu_threads": 8, "memory_gb": 16}},
            "environments": {},
        }
        self.assertEqual(RuntimeProfile.from_dict(data).to_dict()["servers"]["test"]["cpu_threads"], 8)
        for bad in (0, True, 1.5):
            with self.assertRaises(ValueError):
                ServerProfile("test", "host.example", bad, 16)
        with self.assertRaises(ValueError):
            ServerProfile("test", "host;bad", 8, 16)

    def test_cli_dangling_links_are_not_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = root / "tool"
            command.write_text("#!/bin/sh\nexit 0\n")
            command.chmod(0o755)
            (root / "broken").symlink_to(root / "missing")
            records = {c.name: c for c in discover_cli(root)}
            self.assertEqual(records["tool"].readiness_status, "discovered")
            self.assertEqual(records["broken"].readiness_status, "unavailable")

    def test_conda_only_active_metadata_and_ambiguous_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "conda-meta").mkdir()
            (root / "conda-meta/python-3.14.json").write_text(json.dumps({"name": "python", "version": "3.14.10"}))
            for python, version in (("3.14", "1"), ("3.14", "2"), ("3.11", "0")):
                dist = root / "lib" / ("python" + python) / "site-packages" / ("Example-" + version + ".dist-info")
                dist.mkdir(parents=True)
                (dist / "METADATA").write_text(f"Metadata-Version: 2.1\nName: Example\nVersion: {version}\n")
            records = [c for c in discover_conda([root]) if c.domain == "python-package"]
            self.assertEqual(len(records), 1)
            self.assertIsNone(records[0].version)
            self.assertEqual(records[0].version_evidence, ("1", "2"))

    def test_catalog_search_and_duplicate_ids(self):
        item = Capability("r:seurat", "Seurat", domain="single-cell", readiness_status="import_checked")
        catalog = Catalog.from_dict(Catalog([item]).to_dict())
        self.assertEqual(catalog.search("single-cell"), [item])
        with self.assertRaises(ValueError):
            Catalog([item, item])

    def test_known_install_commands_are_blocked(self):
        for command in [
            "pip install x",
            "python -m pip install x",
            "conda create -n x",
            "mamba install x",
            "install.packages('x')",
            "BiocManager::install('x')",
            "apptainer pull x",
        ]:
            with self.subTest(command=command), self.assertRaises(PermissionError):
                require_no_install(command)
        require_no_install("samtools stats input.bam")

    def test_scientific_fixture_and_safe_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            fasta = Path(tmp) / "toy.fa"
            fasta.write_text(">a\nACGT\n>b\nAA\n")
            self.assertEqual(fasta_summary(fasta), {"records": 2, "bases": 6, "lengths": {"a": 4, "b": 2}})
            result = run_command(["/usr/bin/printf", "%s", "a; echo unsafe"], cwd=tmp)
            self.assertEqual(result.stdout, "a; echo unsafe")
            self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
