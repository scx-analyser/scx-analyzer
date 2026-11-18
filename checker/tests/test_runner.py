"""C1 test suite. Uses fixtures to test the contracts, not kernel semantics."""
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import jsonschema

from checker import runner
from checker.__main__ import main
from checker.checkers import register, registered, _REGISTRY

ROOT = Path(__file__).resolve().parents[2]


class FixtureTests(unittest.TestCase):
    def setUp(self):
        registry_patch = patch.dict(_REGISTRY, {}, clear=True)
        registry_patch.start()
        self.addCleanup(registry_patch.stop)
        self.graph = runner.load_data(ROOT / "contracts/fixtures/callgraph.example.json")
        self.catalog = runner.load_data(ROOT / "contracts/fixtures/catalog.example.yaml")

    def finding(self, invariant="I1"):
        return {
            "kfunc": self.graph["roots"][0],
            "invariant": invariant,
            "verdict": "unknown",
            "enforcement": ["unknown"],
            "explanation": "Illustrative fixture provides no kernel proof: é",
        }


class RunnerTests(FixtureTests):
    def test_empty_registry_is_not_a_success_claim(self):
        self.assertEqual([], runner.check(self.graph, self.catalog))

    def test_valid_plugin_works(self):
        finding = self.finding()
        register("I1", lambda g, c: [finding])
        self.assertEqual([finding], runner.check(self.graph, self.catalog))

    def test_duplicate_plugin_rejected(self):
        register("I1", lambda g, c: [])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            register("I1", lambda g, c: [])

    def test_incorrect_plugin_invariant_rejected(self):
        register("I1", lambda g, c: [self.finding("I2")])
        with self.assertRaisesRegex(ValueError, "mismatched"):
            runner.check(self.graph, self.catalog)

    def test_bad_root_rejected(self):
        finding = self.finding()
        finding["kfunc"] = "not_root"
        register("I1", lambda g, c: [finding])
        with self.assertRaisesRegex(ValueError, "non-root"):
            runner.check(self.graph, self.catalog)

    def test_catalog_kernel_mismatch(self):
        self.catalog["kernel_version"] = "different-source-version"
        with self.assertRaisesRegex(ValueError, "kernel version mismatch"):
            runner.check(self.graph, self.catalog)

    def test_invalid_callgraph_rejected(self):
        del self.graph["roots"]
        with self.assertRaises(jsonschema.ValidationError):
            runner.check(self.graph, self.catalog)

    def test_invalid_catalog_rejected(self):
        del self.catalog["invariants"]
        with self.assertRaises(jsonschema.ValidationError):
            runner.check(self.graph, self.catalog)

    def test_real_fixtures_match_real_schemas(self):
        for kind, suffix in (("callgraph", "json"), ("catalog", "yaml"), ("findings", "json")):
            with self.subTest(contract=kind):
                data = runner.load_data(ROOT / f"contracts/fixtures/{kind}.example.{suffix}")
                runner.validate(kind, data)

    def test_unknown_contract_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown contract"):
            runner.validate("missing", {})

    def test_invalid_registration_rejected(self):
        for invariant_id, fn in ((None, lambda g, c: []), ([], lambda g, c: []),
                                 ("", lambda g, c: []), ("I1", None)):
            with self.subTest(invariant_id=invariant_id, fn=fn):
                with self.assertRaisesRegex(ValueError, "nonempty string"):
                    register(invariant_id, fn)

    def test_registry_snapshot_cannot_modify_registry(self):
        register("I1", lambda g, c: [])
        registered().clear()
        self.assertEqual(["I1"], list(registered()))

    def test_plugins_run_in_deterministic_order(self):
        called = []

        def plugin(invariant):
            def run(g, c):
                called.append(invariant)
                return [self.finding(invariant)]
            return run

        for invariant in ("I3", "I1", "I2"):
            register(invariant, plugin(invariant))
        findings = runner.check(self.graph, self.catalog)
        self.assertEqual(["I1", "I2", "I3"], called)
        self.assertEqual(called, [finding["invariant"] for finding in findings])

    def test_plugin_missing_from_catalog_rejected(self):
        register("I99", lambda g, c: [])
        with self.assertRaisesRegex(ValueError, "not present"):
            runner.check(self.graph, self.catalog)

    def test_duplicate_catalog_invariant_rejected(self):
        self.catalog["invariants"].append(self.catalog["invariants"][0])
        with self.assertRaisesRegex(ValueError, "duplicate invariant"):
            runner.check(self.graph, self.catalog)

    def test_missing_root_node_rejected(self):
        del self.graph["nodes"][self.graph["roots"][0]]
        with self.assertRaisesRegex(ValueError, "roots missing"):
            runner.check(self.graph, self.catalog)

    def test_plugin_must_return_list(self):
        for result in (None, {}, ()):
            with self.subTest(result=result), patch.dict(_REGISTRY, {"I1": lambda g, c: result}):
                with self.assertRaisesRegex(TypeError, "must return a list"):
                    runner.check(self.graph, self.catalog)

    def test_non_object_finding_rejected(self):
        register("I1", lambda g, c: [None])
        with self.assertRaisesRegex(TypeError, "non-object finding"):
            runner.check(self.graph, self.catalog)

    def test_malformed_finding_rejected_by_schema(self):
        for changes in ({"verdict": "safe"}, {"enforcement": ["invented"]},
                        {"evidence": [{}]}, {"unexpected": True}):
            finding = self.finding() | changes
            with self.subTest(changes=changes), patch.dict(_REGISTRY, {"I1": lambda g, c: [finding]}):
                with self.assertRaises(jsonschema.ValidationError):
                    runner.check(self.graph, self.catalog)

    def test_finding_missing_required_field_rejected(self):
        finding = self.finding()
        del finding["verdict"]
        register("I1", lambda g, c: [finding])
        with self.assertRaises(jsonschema.ValidationError):
            runner.check(self.graph, self.catalog)

    def test_unhashable_finding_kfunc_rejected_explicitly(self):
        finding = self.finding() | {"kfunc": []}
        register("I1", lambda g, c: [finding])
        with self.assertRaisesRegex(ValueError, "non-root kfunc"):
            runner.check(self.graph, self.catalog)

    def test_non_json_finding_metadata_rejected(self):
        # Evidence allows extra properties in the real schema.
        for metadata in ({"python-set"}, float("nan"), {1: "number", "key": "string"}):
            finding = self.finding() | {"evidence": [{
                "function": self.graph["roots"][0], "detail": "test", "metadata": metadata,
            }]}
            with self.subTest(metadata=metadata), patch.dict(_REGISTRY, {"I1": lambda g, c: [finding]}):
                with self.assertRaisesRegex(ValueError, "JSON-serializable"):
                    runner.check(self.graph, self.catalog)


class CliTests(FixtureTests):
    def setUp(self):
        super().setUp()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)

    def cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["check", *map(str, args)])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_cli_error(self, *args):
        code, stdout, stderr = self.cli(*args)
        self.assertEqual(2, code, stderr)
        self.assertEqual("", stdout)
        self.assertIn("scxa check:", stderr)
        self.assertNotIn("Traceback", stderr)
        return stderr

    def test_cli_runs_fixture(self):
        completed = subprocess.run([sys.executable, "-m", "checker", "check"],
                                   cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        output = json.loads(completed.stdout)
        self.assertEqual([], output["findings"])
        runner.validate("findings", output)
        self.assertIn("no semantic checkers installed", completed.stderr)
        self.assertIn("no safety claim", completed.stderr)

    def test_cli_explicit_fixture_paths(self):
        graph = ROOT / "contracts/fixtures/callgraph.example.json"
        catalog = ROOT / "contracts/fixtures/catalog.example.yaml"
        code, stdout, stderr = self.cli("--callgraph", graph, "--catalog", catalog)
        self.assertEqual(0, code, stderr)
        output = json.loads(stdout)
        self.assertEqual(str(graph), output["callgraph"])
        self.assertEqual(self.graph["kernel_version"], output["kernel_version"])
        runner.validate("findings", output)

    def test_script_defaults_work_outside_repository(self):
        completed = subprocess.run([sys.executable, str(ROOT / "scxa"), "check"],
                                   cwd=self.temp, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        runner.validate("findings", json.loads(completed.stdout))

    def test_missing_file(self):
        for option in ("--callgraph", "--catalog"):
            with self.subTest(option=option):
                self.assertIn("file not found", self.assert_cli_error(option, self.temp / "missing.json"))

    def test_bad_json(self):
        path = self.temp / "bad.json"
        path.write_text("{invalid", encoding="utf-8")
        self.assert_cli_error("--callgraph", path)

    def test_bad_yaml(self):
        path = self.temp / "bad.yaml"
        path.write_text("invariants: [", encoding="utf-8")
        self.assert_cli_error("--catalog", path)

    def test_invalid_document_roots(self):
        for content in ("[]", "null", '"scalar"'):
            with self.subTest(content=content):
                path = self.temp / "bad.json"
                path.write_text(content, encoding="utf-8")
                self.assertIn("document root", self.assert_cli_error("--callgraph", path))

    def test_invalid_utf8(self):
        path = self.temp / "bad.json"
        path.write_bytes(b"\xff")
        self.assert_cli_error("--callgraph", path)

    def test_schema_mismatch(self):
        path = self.temp / "bad.json"
        path.write_text("{}", encoding="utf-8")
        self.assert_cli_error("--callgraph", path)

    def test_kernel_mismatch(self):
        path = self.temp / "catalog.json"
        self.catalog["kernel_version"] = "different-source-version"
        path.write_text(json.dumps(self.catalog), encoding="utf-8")
        self.assertIn("kernel version mismatch", self.assert_cli_error("--catalog", path))

    def test_output_serialization(self):
        finding = self.finding()
        register("I1", lambda g, c: [finding])
        path = self.temp / "nested" / "findings.json"
        code, stdout, stderr = self.cli("-o", path)
        self.assertEqual(0, code, stderr)
        self.assertEqual("", stdout)
        self.assertIn("wrote 1 finding(s)", stderr)
        serialized = path.read_text(encoding="utf-8")
        self.assertTrue(serialized.endswith("\n"))
        output = json.loads(serialized)
        self.assertEqual([finding], output["findings"])
        runner.validate("findings", output)

    def test_bad_plugin_does_not_overwrite_existing_output(self):
        path = self.temp / "findings.json"
        path.write_text("existing output", encoding="utf-8")
        register("I1", lambda g, c: [self.finding() | {"verdict": "safe"}])
        self.assert_cli_error("-o", path)
        self.assertEqual("existing output", path.read_text(encoding="utf-8"))

    def test_output_io_error(self):
        self.assert_cli_error("-o", self.temp)

    def test_empty_result_from_installed_plugin_is_described_accurately(self):
        register("I1", lambda g, c: [])
        code, stdout, stderr = self.cli()
        self.assertEqual(0, code, stderr)
        self.assertEqual([], json.loads(stdout)["findings"])
        self.assertIn("installed checkers returned 0 findings", stderr)
        self.assertNotIn("no semantic checkers installed", stderr)
        self.assertIn("no safety claim", stderr)


if __name__ == "__main__":
    unittest.main()
