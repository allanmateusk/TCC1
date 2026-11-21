
"""EMA telemetry distinguishes applied rates, skips, and sealed non-EMA state."""
from dataclasses import replace
import unittest

from sistema.core.defenses import preset
from sistema.core.ledger import canonical_hash
from sistema.core.protocol import NetworkState, ProtocolConfig, Vote, apply_record, calibration_record, oracle_record, propose_record
from sistema.core.replica import Replica
from sistema.core.topology import build_graph

NODES=["node-0","node-1","node-2"]


class AlphaTelemetry(unittest.TestCase):
    def state(self, mechanism="ema_slow_up"):
        cfg=ProtocolConfig(signal="hybrid", mechanism=mechanism, consensus_mode="distance", validation_score="exact",
                           defense=replace(preset("all"),leaderless_calibration=True))
        s=NetworkState(NODES,cfg)
        s.trace_reputation()
        return s

    def test_real_genesis_rates_skip_and_nonmutation_from_tracing(self):
        s=self.state()
        clone=s.clone()
        r=calibration_record(prev_hash="0"*64,round_index=0,task_id="q",expected=10,
                             responses=dict(zip(NODES,[10,20,None],strict=True)),consensus=10)
        apply_record(s,r)
        apply_record(clone,r)
        self.assertEqual(s.state_hash(),clone.state_hash())
        transitions={e["node_id"]:e for e in s.reputation_events if e["track"]=="consensus"}
        self.assertEqual([transitions[n]["alpha_used"] for n in NODES],[.1,.8,None])
        self.assertEqual(transitions["node-2"]["operation"],"skip")
        self.assertEqual(transitions["node-2"]["before"],transitions["node-2"]["after"])
        self.assertTrue(all(e["kind"]=="calibration" and e["record_hash"]==r.hash for e in transitions.values()))

    def test_two_real_updates_from_same_round_and_next_round_resets(self):
        s=self.state("ema")
        r=propose_record(s,round_index=3,task_id="q",leader=NODES[0],auditor=NODES[1],
                         responses=dict(zip(NODES,[10,10,10],strict=True)),prev_hash="0"*64)
        apply_record(s,r)
        truth=oracle_record(prev_hash=r.hash,round_index=3,task_id="q",expected=10,
                            graded=dict(zip(NODES,[10,20,None],strict=True)))
        apply_record(s,truth)
        for i in range(3):
            own=[e for e in s.reputation_events if e["track"]=="consensus" and e["node_id"]==NODES[i]]
            self.assertEqual([e["kind"] for e in own],["round","oracle"])
            self.assertEqual([e["alpha_used"] for e in own],[.05,None if i==2 else .8])
            self.assertAlmostEqual(own[0]["after"],own[1]["before"],places=6)
        nxt=propose_record(s,round_index=4,task_id="q2",leader=NODES[0],auditor=NODES[1],
                           responses=dict(zip(NODES,[10,10,10],strict=True)),prev_hash=truth.hash)
        apply_record(s,nxt)
        self.assertEqual(s.trace_round,4)
        self.assertTrue(all(e["record_hash"]==nxt.hash for e in s.reputation_events))

    def test_sealed_forgery_never_claims_ema_alpha(self):
        s=self.state()
        r=propose_record(s,round_index=4,task_id="q",leader=NODES[0],auditor=NODES[1],
                         responses=dict(zip(NODES,[10,10,10],strict=True)),prev_hash="0"*64,
                         attack="forge",colluders=[NODES[0]])
        apply_record(s,r)
        self.assertTrue(s.reputation_events)
        self.assertTrue(all(e["operation"]=="snapshot_without_ema" and e["alpha_used"] is None
                            for e in s.reputation_events))
        self.assertEqual(canonical_hash(s.snapshot()),r.state_hash)

    def test_blocked_ground_truth_does_not_create_ema_event(self):
        cfg=ProtocolConfig(consensus_mode="distance",defense=preset("none"))
        rep=Replica(NODES[0],NODES,cfg,build_graph(NODES,"star"))
        r=oracle_record(prev_hash=rep.head,round_index=0,task_id="q",expected=10,graded={NODES[0]:10})
        self.assertEqual(rep.oracle(r,{n:False for n in NODES}),"blocked")
        self.assertEqual(rep.snapshot()["reputation_events"],[])
        self.assertIsNone(rep.snapshot()["reputation_trace_round"])

    def test_exact_commit_and_oracle_retries_do_not_duplicate_updates(self):
        cfg=ProtocolConfig(consensus_mode="distance",validation_score="exact",defense=preset("all"))
        rep=Replica(NODES[0],NODES,cfg,build_graph(NODES,"star"))
        record=propose_record(rep.state,round_index=1,task_id="q",leader=NODES[0],auditor=NODES[1],
                              responses={n:10 for n in NODES},prev_hash=rep.head)
        votes={n:Vote(n,True) for n in NODES}
        self.assertTrue(rep.commit(record,votes)[0].accepted)
        once=rep.snapshot()["reputation_events"]
        with self.assertRaises(ValueError):
            rep.commit(record,votes)  # direct Replica call; HTTP also deduplicates by round and head
        self.assertEqual(rep.snapshot()["reputation_events"],once)
        oracle=oracle_record(prev_hash=rep.head,round_index=1,task_id="q",expected=10,graded={n:10 for n in NODES})
        self.assertEqual(rep.oracle(oracle,None),"applied")
        both=rep.snapshot()["reputation_events"]
        self.assertEqual([e["kind"] for e in both if e["track"]=="consensus"],["round","oracle"])
        self.assertEqual(rep.oracle(oracle,None),"stale")
        self.assertEqual(rep.snapshot()["reputation_events"],both)


if __name__=="__main__":
    unittest.main()
