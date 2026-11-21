"""Torn-write and restore fixtures with real ledger/state replay; no service."""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from sistema.core.ledger import RoundRecord
from sistema.core.protocol import ProtocolConfig, apply_record
from sistema.core.replica import Replica
from sistema.core.topology import build_graph

from .checkpoint import (CheckpointStore, Identity, LOGS, NODES, ZERO, export_replica,
                         replay_replica, verify_log_prefixes)


class CheckpointTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.identity = Identity("a"*32, "demo-s0", "pilot", 0, 5, "b"*40, "c"*40,
                                 "d"*64, "e"*64, "f"*64)
        self.path = Path(self.folder.name) / self.identity.run_id
        self.path.mkdir()
        self.store = CheckpointStore(self.path, self.identity)
        self.cfg = ProtocolConfig()
        self.graph = build_graph(sorted(NODES), "kregular", degree=4, seed=0)
        self.nodes = {node: Replica(node, NODES, self.cfg, self.graph) for node in NODES}

    def boundary(self, index):
        for node in self.nodes.values():
            record = RoundRecord("void", index, prev_hash=node.head, task_id=f"t{index}",
                                 leader="node-0", penalties=(("node-0", "test"),)).sealed()
            node.ledger.append(record)
            apply_record(node.state, record)
        data = b"r11\n" * (index + 1)
        return {"replicas": {k: export_replica(r) for k,r in self.nodes.items()},
                "groups": {k: 0 for k in NODES}, "next_gid": 1,
                "log_prefixes": {name: {"bytes": len(data), "sha256": sha256(data).hexdigest()} for name in LOGS}}

    def test_torn_temp_ignored_and_same_checkpoint_idempotent(self):
        self.assertEqual(self.store.recover(), (None, ZERO))
        (self.path / ".checkpoint-00.json.torn").write_bytes(b"{")
        boundary = self.boundary(0)
        mark = self.store.publish(0, **boundary)
        self.assertEqual(self.store.publish(0, **boundary), mark)
        self.assertEqual(self.store.recover()[0]["round_index"], 0)
        with self.assertRaises(ValueError):
            self.store.publish(0, **{**boundary, "next_gid": 2})

    def test_identity_gap_corruption_fail_closed(self):
        boundary = self.boundary(0)
        with self.assertRaises(ValueError):
            self.store.publish(1, **boundary)
        self.store.publish(0, **boundary)
        with self.assertRaises(ValueError):
            CheckpointStore(self.path, replace(self.identity, config_sha256="a"*64)).recover()
        path = self.path / "checkpoint-00.json"
        path.write_bytes(path.read_bytes().replace(b'"next_gid": 1', b'"next_gid": 2'))
        with self.assertRaises(ValueError):
            self.store.recover()

    def test_two_round_replay_restores_live_replica(self):
        self.store.publish(0, **self.boundary(0))
        self.store.publish(1, **self.boundary(1))
        data, _ = self.store.recover()
        payload = data["replicas"]["node-3"]
        restored = replay_replica(payload, 1, self.cfg, self.graph)
        self.assertEqual(export_replica(restored), payload)
        self.assertEqual(restored.state.rotation, 2)
        self.assertEqual(restored.state.last_leader, "node-0")
        self.assertNotEqual(restored.state.power.get("node-0"), self.cfg.initial)
        payload["state"]["rotation"] = 5
        with self.assertRaises(ValueError):
            replay_replica(payload, 1, self.cfg, self.graph)

    def test_valid_but_rewritten_ledger_rejected(self):
        self.store.publish(0, **self.boundary(0))
        self.nodes["node-3"] = Replica("node-3", NODES, self.cfg, self.graph)
        r = self.nodes["node-3"]
        different = RoundRecord("void", 0, task_id="t0", leader="node-1").sealed()
        r.ledger.append(different)
        apply_record(r.state, different)
        with self.assertRaisesRegex(ValueError, "rewrites"):
            self.store.publish(1, **self.boundary(1))

    def test_log_prefix_allows_visible_suffix_but_fails_corruption(self):
        self.store.publish(0, **self.boundary(0))
        data, _ = self.store.recover()
        for name in LOGS:
            (self.path / name).write_bytes(b"r11\nunfinished")
        verify_log_prefixes(self.path, data)
        (self.path / "rounds.csv").write_bytes(b"r12\nunfinished")
        with self.assertRaises(ValueError):
            verify_log_prefixes(self.path, data)


class EndpointScopeTests(unittest.TestCase):
    def test_disables_export_without_exact_loopback_token_and_run(self):
        import asyncio
        import importlib.util
        from types import SimpleNamespace
        from unittest.mock import patch
        if not all(importlib.util.find_spec(x) for x in ("fastapi","httpx")):
            self.skipTest("Node dependencies not installed")
        from fastapi import HTTPException
        from sistema.node import app
        other={"X-N20-Checkpoint-Token":"fixture-valid","X-N20-Checkpoint-Run":"fixture-pilot"}
        with patch.dict("os.environ",{"N20_CHECKPOINT_TOKEN":"fixture-valid",
                       "N20_CHECKPOINT_RUN_ID":"fixture-pilot"}),patch.object(app,"_require_replica") as replica:
            for host,headers in (("192.0.2.12",other),("127.0.0.1",{}),
                                  ("localhost",other),("127.0.0.1",dict(other,**{"X-N20-Checkpoint-Run":"bad"}))):
                with self.assertRaises(HTTPException) as denied:
                    asyncio.run(app.checkpoint_state(SimpleNamespace(client=SimpleNamespace(host=host),headers=headers),0))
                self.assertEqual(denied.exception.status_code,404)
            replica.assert_not_called()
