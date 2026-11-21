"""Offline checks for the version boundary; no inference/provider."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from . import artifact_store as art, benchmark as bm, campaign, campaign_profiles as cp, checkpoint, incremental_campaign as inc, r2_verified_pilot as pub, watchdog as wd


class VersionBoundary(unittest.TestCase):
    def setUp(self):
        self.profile,self.cases=bm.load_profile("incremental-v1")
        self.scope=cp.scope(self.profile)
        self.case=next(iter(self.cases.values()))
        self.run="a"*32

    def test_twenty_and_old_pilot_separate(self):
        old,legacy=bm.load_profile()
        self.assertEqual(tuple(legacy),(*campaign.IDS,"pilot"))
        self.assertEqual(tuple(self.cases),inc.IDS)
        self.assertEqual(len(self.cases),20)
        self.assertNotIn("pilot",self.cases)
        self.assertEqual(cp.scope(old),{})
        with self.assertRaises(ValueError): bm.load_profile("../profile.json")

    def test_producer_and_archive_agree_and_overlap_is_intended(self):
        config,entry=bm.scenario_args(self.profile,self.case,0)
        self.assertEqual(config["noise_policy"],"incremental_upward")
        self.assertEqual((config["consensus_alpha"],config["oracle_alpha"]),(.05,.95))
        self.assertEqual(config["audit_mode"],self.case["audit"])
        m={"profile":self.profile,"scenario":entry,"scenario_id":self.case["id"],
           "run_kind":"official","rounds":50,"experiment_id":entry["id"],**self.scope}
        case,plan,n,tasks=art._definition(m)
        self.assertEqual((case["mechanism"],n,len(tasks)),("ema",50,50))
        self.assertEqual(plan["planned_rounds"],[10,20,30,40,50])
        self.assertEqual(plan["planned_rounds"],plan["fixed_test_rounds"])
        for bad in ({**m,"profile_sha256":"0"*64},{k:v for k,v in m.items() if k!="campaign_id"},
                    {k:v for k,v in m.items() if k not in cp.FIELDS},
                    {**m,"scenario":{**entry,"collusion":not entry["collusion"]}}):
            with self.assertRaises(ValueError): art._definition(bad)

    def test_checkpoint_and_watchdog_binding_legacy_preserved(self):
        basic={"run_id":self.run,"experiment_id":"scope-test","scenario_id":self.case["id"],"seed":0,"rounds":50,
               **{k:"a"*40 for k in ("git_sha","model_revision")},
               **{k:"c"*64 for k in ("config_sha256","tasks_sha256","audit_sha256")}}
        iid=checkpoint.Identity(**basic,**self.scope)
        self.assertEqual({k:iid.serialized()[k] for k in cp.FIELDS},self.scope)
        with self.assertRaises(ValueError): checkpoint.Identity(**basic)
        old=checkpoint.Identity(**{**basic,"scenario_id":"pilot","rounds":5})
        self.assertNotIn("campaign_id",old.serialized())
        b=wd.Binding(self.run,"fake-pod","tcc",200,100,20,run_kind="official",scenario_id=self.case["id"],**self.scope)
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/"test-state.json"
            wd.arm(path,b)
            criteria=dict(run_id=self.run,run_kind="official",scenario_id=self.case["id"])
            self.assertEqual(wd.require_armed(path,101,**criteria,**self.scope),b)
            with self.assertRaises(ValueError): wd.require_armed(path,101,**criteria)
            fake=Mock()
            with self.assertRaises(ValueError): wd.tick(path,101,apply=True,backend=fake)
            fake.inspect_exact.assert_not_called()
            self.assertEqual(wd.tick(path,101)["status"],"dry-run")

    def test_candidate_cannot_use_old_live_switches_or_uploader(self):
        with patch.dict("os.environ",{"TCC_LIVE_N20_APPROVED":"true","TCC_N20_OFFICIAL_QUALIFIED":"true"}), \
                patch.object(bm,"check_mapping") as mapping:
            with self.assertRaisesRegex(RuntimeError,"not qualified"):
                bm.live(self.profile,self.case,0,Path("/missing"))
        mapping.assert_not_called()
        with tempfile.TemporaryDirectory() as t:
            d=Path(t)
            (d/art.MANIFEST).write_bytes(art.json_bytes(self.scope))
            opener=Mock()
            with self.assertRaisesRegex(pub.TransferError,"not qualified"):
                pub.upload(d,self.run,None,None,None,opener=opener)
            opener.assert_not_called()
