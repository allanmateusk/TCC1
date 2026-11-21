from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from sistema.core.behavior import corrupt_relative, corrupt_with_noise
from sistema.node.inference import ModelBackend, _build_prompt
from sistema.node.dedicated_inference import DedicatedModel
from . import benchmark


class N20ConfigurationTests(unittest.TestCase):
    def test_campaign_paired_schedule_and_one_seed(self):
        profile, scenarios = benchmark.load_profile()
        schedules = {tag: benchmark.scenario_args(profile, row, 0)[1]["audit_plan"] for tag, row in scenarios.items()}
        self.assertEqual(len(scenarios), 18)
        self.assertEqual(profile["seeds"], [0])
        for smaller, larger in (("C02","C03"), ("C04","C05")):
            self.assertLess(set(schedules[smaller]["planned_rounds"]), set(schedules[larger]["planned_rounds"]))
        self.assertEqual(schedules["C03"]["planned_rounds"], schedules["C05"]["planned_rounds"])
        for tag in ("C01","C16","C17","C10","C14"):
            self.assertEqual(schedules[tag]["planned_rounds"], [])
        for tag in ("C09","C06","C13"):
            self.assertEqual(schedules[tag]["genesis_rounds"], [1,2,3])
            self.assertEqual(set(schedules[tag]["planned_rounds"]), set(schedules["C08"]["planned_rounds"])-{1,2,3})
        self.assertEqual(len(schedules["C11"]["planned_rounds"]), len(schedules["C08"]["planned_rounds"]))
        self.assertNotEqual(schedules["C11"]["planned_rounds"], schedules["C08"]["planned_rounds"])
        for tag in scenarios:
            fixed = set(schedules[tag]["fixed_test_rounds"])
            self.assertFalse(fixed & set(schedules[tag]["planned_rounds"]))
        absences = schedules["C13"]["simulated_absences"]
        self.assertTrue(absences)
        self.assertEqual({n for nodes in absences.values() for n in nodes}, {f"node-{i}" for i in range(16)})
        self.assertEqual(schedules["C06"]["simulated_absences"], {})

    def test_mapping_for_baseline_and_each_collusion_scenario(self):
        profile, scenarios = benchmark.load_profile()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for scenario in scenarios.values():
                for seed in profile["seeds"]:
                    benchmark.check_mapping(profile, scenario, seed, root, root)

    def test_strong_noise_for_synthetic_numeric_answers(self):
        for base in (-31, 0, 37):
            for seed in range(5):
                high = corrupt_with_noise(base, random.Random(seed))
                subtle = corrupt_relative(base, random.Random(seed), 0.2)
                self.assertGreaterEqual(abs(high), (abs(base) + 1) * 1000)
                self.assertLess(abs(subtle), abs(high))

    def test_smollm3_uses_official_no_think_while_qwen_keeps_existing_prompt(self):
        tokenizer = Mock(chat_template="official tokenizer template")
        _build_prompt(tokenizer, "7 + 5?", model_type="smollm3")
        args, kwargs = tokenizer.apply_chat_template.call_args
        self.assertEqual(args[0][0], {"role": "system", "content": "/no_think"})
        self.assertIn("####", args[0][1]["content"])
        self.assertNotIn("enable_thinking", kwargs)
        _build_prompt(tokenizer, "7 + 5?", model_type="qwen3")
        args, kwargs = tokenizer.apply_chat_template.call_args
        self.assertEqual(args[0][0]["role"], "user")
        self.assertIs(kwargs["enable_thinking"], False)

    def test_baseline_only_pilot_has_distinct_id_and_count(self):
        profile, scenarios = benchmark.load_profile()
        for tag, rounds, count in (("pilot", 5, 100), ("C01", 50, 1000)):
            config, entry = benchmark.scenario_args(profile, scenarios[tag], 0)
            self.assertEqual(config["quantization"], "none")
            self.assertEqual(config["dtype"], "bfloat16")
            self.assertEqual(entry["run_kind"], "official" if rounds == 50 else "pilot")
            self.assertEqual(entry["expected_own_generations"], count)
            self.assertIn(f"-r{rounds}-", entry["id"])
        with self.assertRaisesRegex(ValueError, "Only the separate pilot"):
            benchmark.scenario_args(profile, scenarios["C05"], 0, 5)
        with self.assertRaisesRegex(ValueError, "Only the separate pilot"):
            benchmark.scenario_args(profile, scenarios["pilot"], 0, 10)

    def test_bf16_load_is_explicit_native_and_unquantized(self):
        bf16 = object()
        cuda = Mock()
        cuda.is_bf16_supported.return_value = True
        fake_torch = SimpleNamespace(cuda=cuda, bfloat16=bf16)
        loaded = SimpleNamespace(dtype=bf16, device=SimpleNamespace(type="cuda"),
                                 is_quantized=False, config=SimpleNamespace())
        model_loader = Mock()
        model_loader.from_pretrained.return_value = loaded
        fake_transformers = SimpleNamespace(AutoModelForCausalLM=model_loader,
                                            AutoTokenizer=Mock(), BitsAndBytesConfig=Mock())
        with patch.dict("sys.modules", {"transformers": fake_transformers, "torch": fake_torch}):
            self.assertIs(ModelBackend("/local", device="cuda", dtype="bfloat16").model, loaded)
            model_loader.from_pretrained.assert_called_once_with(
                "/local", torch_dtype=bf16, device_map={"": 0}, local_files_only=True)
            fake_transformers.BitsAndBytesConfig.assert_not_called()
            loaded.dtype = object()
            with self.assertRaisesRegex(RuntimeError, "refusing fallback"):
                ModelBackend("/local", device="cuda", dtype="bfloat16")
            cuda.is_bf16_supported.return_value = False
            with self.assertRaisesRegex(ValueError, "Native CUDA BF16"):
                ModelBackend("/local", device="cuda", dtype="bfloat16")

    def test_wrong_dedicated_precision_is_rejected_before_ledger_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "ghost"
            with self.assertRaisesRegex(ValueError, "unquantized bfloat16"):
                DedicatedModel(node_id="node-0", run_id="pilot", model_name="/local",
                               cache_dir=output, quantization="none", dtype="float16")
            self.assertFalse(output.exists())

    def test_live_fails_closed_without_explicit_approval(self):
        profile, scenarios = benchmark.load_profile()
        with patch.dict(benchmark.os.environ, {"TCC_LIVE_N20_APPROVED": ""}):
            with self.assertRaisesRegex(RuntimeError, "approval"):
                benchmark.live(profile, scenarios["C01"], 0, None, None)


if __name__ == "__main__":
    unittest.main()
