"""Short-mode window, readback limits, and unchanged long mode (no deployment)."""
import unittest
from unittest.mock import patch

from . import campaign_profiles as cp, incremental_first_live as live, prepare_batch_cutoff as prep
from .incremental_batch_protection import BatchProtection, QualificationProtection, SHORT_MODE, protection_for
from .incremental_campaign import IDS
from .incremental_warm_journal import Scope
from .test_prepare_batch_cutoff import fixture, START, GIT

class ShortQualificationTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture()
        self.p=self.f["protection"]
        self.p.update(qualification_mode=SHORT_MODE,stop_at=START+3300,hard_deadline=START+3600)

    def test_exact_short_scope_never_third_and_budget_window_total(self):
        p=protection_for(self.p)
        self.assertIs(type(p),QualificationProtection)
        self.assertEqual(p.cost_ceiling_microusd,p.hourly_compute_microusd)
        s=Scope(p,"f721260c-fedf-4fda-ad01-5544d2c49de2","f721260c-fedf-4fda-ad01-5544d2c49de3",
                "f721260c-fedf-4fda-ad01-5544d2c49de4","5"*64,"6"*64)
        self.assertEqual(s.case_ids,IDS[:2])
        self.assertEqual(p.queue_plan().case_ids,IDS[:2])
        old=fixture()["protection"]
        self.assertIs(type(protection_for(old)),BatchProtection)
        self.assertEqual(protection_for(old).queue_plan().case_ids,IDS)

    def test_crossed_or_invalid_mode_never_accepted(self):
        wrong=[{"stop_at":START+3299},{"hard_deadline":START+3601},
               {"qualification_mode":"any"},{"qualification_mode":None},
               {"approved_cap_microusd":1}]
        for diff in wrong:
            with self.subTest(diff=diff),self.assertRaises(ValueError):
                protection_for({**self.p,**diff})
        with self.assertRaises(ValueError):
            protection_for({k:v for k,v in self.p.items() if k!="qualification_mode"})

    def test_offline_payload_and_no_standalone_cold_execution(self):
        out=prep.prepare(self.f,release=GIT,source_hashes={},now=START+120)
        self.assertEqual(out["unarmed_payload_proposal"]["qualificationMode"],SHORT_MODE)
        self.assertFalse(out["eligible_for_live_admission"])
        with patch.object(live,"load_verified_handoff",return_value=({},{"qualification_mode":SHORT_MODE})):
            with self.assertRaisesRegex(ValueError,"two-case warm"):
                live.run()
