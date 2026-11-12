"""Small end-to-end fixtures through existing shared installations (never installs anything).

Paths default to the lab's shared locations and can be overridden with environment
variables; a missing tool skips its test rather than triggering installation.
"""

import json
import os
import random
import tempfile
import unittest
from pathlib import Path

from biomni.localenv import EnvironmentProfile, RuntimeProfile
from biomni.localenv.adapters import ScientificRunner, curated_command, fasta_summary, run_command

BIN = Path(os.environ.get("BIOMNI_FIXTURE_BIN", "/data/p/bin"))
RSCRIPT = os.environ.get("BIOMNI_FIXTURE_RSCRIPT", "/data/p/R/R-4.5.2_install/bin/Rscript")
R_LIBRARY = os.environ.get("BIOMNI_FIXTURE_R_LIBRARY", "/data/p/R/R-4.5.2_install/lib64/R/library")
BASE_PYTHON = os.environ.get("BIOMNI_FIXTURE_PYTHON", "/data/p/anaconda3/bin/python")
DEEPTOOLS = os.environ.get("BIOMNI_FIXTURE_BAMCOVERAGE", "/data/p/anaconda3/envs/deeptools/bin/bamCoverage")


def tool(name):
    path = BIN / name
    return str(path) if path.exists() and os.access(path.resolve(), os.X_OK) else None


def runner():
    environments = {}
    if Path(RSCRIPT).is_file():
        environments["r-4.5.2"] = EnvironmentProfile("r-4.5.2", "r", RSCRIPT, library_paths=(R_LIBRARY,))
    if Path(BASE_PYTHON).is_file():
        environments["base"] = EnvironmentProfile(
            "base", "python", BASE_PYTHON, prefix=str(Path(BASE_PYTHON).parents[1])
        )
    profile = RuntimeProfile(environments=environments, agent_python=BASE_PYTHON, timeout_seconds=300)
    return ScientificRunner(profile)


class SequenceFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        rng = random.Random(7)
        self.reference = "".join(rng.choice("ACGT") for _ in range(2000))
        (self.dir / "ref.fa").write_text(">chrToy\n" + self.reference + "\n")
        with open(self.dir / "reads.fq", "w") as handle:
            for i in range(40):
                start = rng.randrange(0, 1850)
                read = self.reference[start : start + 120]
                handle.write(f"@read{i}\n{read}\n+\n{'I' * len(read)}\n")

    @unittest.skipUnless(tool("minimap2") and tool("samtools"), "minimap2/samtools unavailable")
    def test_alignment_sort_index_and_flagstat(self):
        self.assertEqual(fasta_summary(self.dir / "ref.fa")["bases"], 2000)
        command = curated_command(
            "alignment",
            {"minimap2": tool("minimap2")},
            {"reference": str(self.dir / "ref.fa"), "reads": str(self.dir / "reads.fq")},
            str(self.dir / "aln.sam"),
            cpus=2,
        )
        command.insert(2, "sr")
        command.insert(2, "-x")
        self.assertEqual(run_command(command, cwd=self.dir).exit_code, 0)
        samtools = tool("samtools")
        self.assertEqual(run_command([samtools, "sort", "-o", "aln.bam", "aln.sam"], cwd=self.dir).exit_code, 0)
        self.assertEqual(run_command([samtools, "index", "aln.bam"], cwd=self.dir).exit_code, 0)
        stats = run_command(
            curated_command("bam_summary", {"samtools": samtools}, {"bam": str(self.dir / "aln.bam")}, ""), cwd=self.dir
        )
        self.assertIn("40 + 0 mapped (100.00%", stats.stdout)
        version = run_command([samtools, "--version"], cwd=self.dir).stdout.splitlines()[0]
        self.assertTrue(version.startswith("samtools 1."))
        if Path(DEEPTOOLS).is_file():
            coverage = run_command(
                [DEEPTOOLS, "-b", "aln.bam", "-o", "cov.bedgraph", "--outFileFormat", "bedgraph", "-p", "1"],
                cwd=self.dir,
            )
            self.assertEqual(coverage.exit_code, 0, coverage.stderr[-2000:])
            self.assertTrue(
                any(line.startswith("chrToy\t") for line in (self.dir / "cov.bedgraph").read_text().splitlines())
            )

    @unittest.skipUnless(tool("bcftools"), "bcftools unavailable")
    def test_vcf_summary(self):
        (self.dir / "toy.vcf").write_text(
            "##fileformat=VCFv4.2\n##contig=<ID=chrToy,length=2000>\n"
            "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
            f"chrToy\t10\t.\t{self.reference[9]}\t{'A' if self.reference[9] != 'A' else 'C'}\t50\tPASS\t.\n"
            f"chrToy\t20\t.\t{self.reference[19]}\t{'G' if self.reference[19] != 'G' else 'T'}\t50\tPASS\t.\n"
            f"chrToy\t30\t.\t{self.reference[29:31]}\t{self.reference[29]}\t50\tPASS\t.\n"
        )
        result = run_command(
            curated_command("vcf_summary", {"bcftools": tool("bcftools")}, {"vcf": str(self.dir / "toy.vcf")}, ""),
            cwd=self.dir,
        )
        self.assertEqual(result.exit_code, 0, result.stderr)
        summary = {
            line.split("\t")[2]: int(line.split("\t")[3])
            for line in result.stdout.splitlines()
            if line.startswith("SN\t")
        }
        self.assertEqual((summary["number of SNPs:"], summary["number of indels:"]), (2, 1))


class StatisticsFixtures(unittest.TestCase):
    @unittest.skipUnless(Path(RSCRIPT).is_file(), "shared R unavailable")
    def test_edger_count_analysis_preserves_ids_and_records_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            rng = random.Random(3)
            samples = ["ctl1", "ctl2", "ctl3", "trt1", "trt2", "trt3"]
            lines = ["gene_id\t" + "\t".join(samples)]
            for g in range(200):
                base = rng.randint(50, 500)
                fold = 8 if g < 10 else 1
                row = [rng.randint(int(base * 0.9), int(base * 1.1)) for _ in range(3)] + [
                    rng.randint(int(base * fold * 0.9), int(base * fold * 1.1)) for _ in range(3)
                ]
                lines.append(f"GENE{g:04d}\t" + "\t".join(map(str, row)))
            (tmp / "counts.tsv").write_text("\n".join(lines) + "\n")
            (tmp / "de.R").write_text("""
args <- commandArgs(trailingOnly = TRUE)
suppressPackageStartupMessages(library(edgeR))
counts <- as.matrix(read.delim(args[1], row.names = 1, check.names = FALSE))
group <- factor(c("ctl", "ctl", "ctl", "trt", "trt", "trt"))
y <- calcNormFactors(DGEList(counts, group = group))
y <- estimateDisp(y, model.matrix(~group))
fit <- glmQLFit(y, model.matrix(~group))
res <- topTags(glmQLFTest(fit, coef = 2), n = Inf)$table
write.table(data.frame(gene_id = rownames(res), res), args[2], sep = "\\t", quote = FALSE, row.names = FALSE)
writeLines(jsonlite::toJSON(list(r = R.version.string, edgeR = as.character(packageVersion("edgeR")),
                                 libpaths = .libPaths()), auto_unbox = TRUE), args[3])
""")
            result = runner().r("r-4.5.2", tmp / "de.R", cwd=tmp, args=["counts.tsv", "de.tsv", "versions.json"])
            self.assertEqual(result.exit_code, 0, result.stderr[-3000:])
            rows = [line.split("\t") for line in (tmp / "de.tsv").read_text().splitlines()]
            header, body = rows[0], rows[1:]
            self.assertEqual(header[0], "gene_id")
            self.assertEqual(len(body), 200)
            self.assertEqual({r[0] for r in body}, {f"GENE{g:04d}" for g in range(200)})
            fdr = header.index("FDR")
            significant = {r[0] for r in body if float(r[fdr]) < 0.01}
            self.assertTrue({f"GENE{g:04d}" for g in range(10)} <= significant, significant)
            versions = json.loads((tmp / "versions.json").read_text())
            self.assertIn("4.5.2", versions["r"])
            self.assertIn(R_LIBRARY, versions["libpaths"])


class AnnDataFixtures(unittest.TestCase):
    @unittest.skipUnless(Path(BASE_PYTHON).is_file(), "base Python unavailable")
    def test_anndata_roundtrip_preserves_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "ad.py").write_text("""
import json, sys
import anndata as ad, numpy as np, pandas as pd, scanpy as sc
# pandas 3 indexes are nullable strings; anndata needs an explicit opt-in to write them.
ad.settings.allow_write_nullable_strings = True
rng = np.random.default_rng(0)
X = rng.poisson(2, size=(30, 12)).astype("float32")
a = ad.AnnData(X, obs=pd.DataFrame(index=[f"cell{i}" for i in range(30)]), var=pd.DataFrame(index=[f"gene{j}" for j in range(12)]))
a.write_h5ad(sys.argv[1])
b = ad.read_h5ad(sys.argv[1])
sc.pp.normalize_total(b, target_sum=1e4)
sc.pp.log1p(b)
json.dump({"obs": list(b.obs_names[:3]), "var": list(b.var_names[:3]), "shape": list(b.shape),
           "anndata": ad.__version__, "scanpy": sc.__version__}, open(sys.argv[2], "w"))
""")
            result = runner().python("base", tmp / "ad.py", cwd=tmp, args=["toy.h5ad", "out.json"])
            self.assertEqual(result.exit_code, 0, result.stderr[-3000:])
            out = json.loads((tmp / "out.json").read_text())
            self.assertEqual(
                (out["obs"], out["var"], out["shape"]),
                (["cell0", "cell1", "cell2"], ["gene0", "gene1", "gene2"], [30, 12]),
            )


if __name__ == "__main__":
    unittest.main()
