import logging
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from case_handler.models import Campaign, CampaignMember, Case, ChallengeTriage
from tasp.services.challenge import CaseChallengeService
from tasp.services.challenge_triage import ALERT, ANALYST, Facts, decide, triage


def facts(**kw):
    base = dict(verdict="Suspicious", proposed="", reason="", campaign_verdicts=(), denylisted=False)
    return Facts(**{**base, **kw})


class DecideTest(SimpleTestCase):
    def test_a_compromise_claim_alerts_even_when_the_reporter_says_false_positive(self):
        for text in ("I clicked the link", "j'ai cliqué sur le lien", "I entered my password",
                     "j'ai saisi mon mot de passe", "I opened the attachment", "ouvert la pièce jointe"):
            d = decide(facts(verdict="Safe", proposed="Safe", reason=text))
            self.assertEqual((d.decision, d.reason_code), (ALERT, "compromise-claimed"), text)

    def test_a_negated_claim_is_still_treated_as_a_claim(self):
        # untrusted text can only escalate, so "did not click" alerting is the safe side
        self.assertEqual(decide(facts(proposed="Safe", reason="I did not click")).decision, ALERT)

    def test_a_dangerous_case_alerts(self):
        d = decide(facts(verdict="Dangerous", proposed="Safe"))
        self.assertEqual((d.decision, d.reason_code), (ALERT, "case-dangerous"))

    def test_a_campaign_with_a_dangerous_member_alerts(self):
        d = decide(facts(verdict="Safe", proposed="Safe", campaign_verdicts=("Safe", "Dangerous")))
        self.assertEqual((d.decision, d.reason_code), (ALERT, "campaign-dangerous"))

    def test_a_denylisted_sender_alerts(self):
        d = decide(facts(verdict="Safe", proposed="Safe", denylisted=True))
        self.assertEqual((d.decision, d.reason_code), (ALERT, "denylisted"))

    def test_a_false_positive_claim_goes_to_an_analyst(self):
        for verdict in ("Safe", "Inconclusive", "Suspicious"):
            d = decide(facts(verdict=verdict, proposed="Safe", reason="This is our own newsletter"))
            self.assertEqual((d.decision, d.reason_code), (ANALYST, "reporter-false-positive"), verdict)

    def test_a_missed_threat_on_a_suspicious_case_alerts(self):
        d = decide(facts(verdict="Suspicious", proposed="Dangerous"))
        self.assertEqual((d.decision, d.reason_code), (ALERT, "missed-threat-corroborated"))

    def test_a_missed_threat_on_a_safe_case_goes_to_an_analyst(self):
        for verdict in ("Safe", "Inconclusive"):
            d = decide(facts(verdict=verdict, proposed="Dangerous"))
            self.assertEqual((d.decision, d.reason_code), (ANALYST, "missed-threat-uncorroborated"), verdict)

    def test_no_proposal_and_no_rule_alerts_as_before(self):
        d = decide(facts(proposed=""))
        self.assertEqual((d.decision, d.reason_code), (ALERT, "no-rule-matched"))

    def test_the_decision_names_its_rule_set_version(self):
        self.assertTrue(decide(facts()).ruleset)


class TriageTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="tri", password="x")

    def _case(self, **kw):
        return Case.objects.create(description="", reporter=self.user, is_challenged=True, **kw)

    def test_facts_come_from_the_case_and_its_campaign(self):
        case = self._case(results="Safe", challenge_proposed_result="Safe", is_denylisted=True)
        other = self._case(results="Dangerous")
        camp = Campaign.objects.create(title="c")
        CampaignMember.objects.create(campaign=camp, case=case)
        CampaignMember.objects.create(campaign=camp, case=other)
        with patch("tasp.services.challenge_triage._mode", return_value="log"):
            row = triage(case)
        self.assertEqual((row.decision, row.reason_code), (ALERT, "campaign-dangerous"))
        self.assertTrue(row.facts["denylisted"])
        self.assertEqual(sorted(row.facts["campaign_verdicts"]), ["Dangerous", "Safe"])

    def test_off_records_nothing(self):
        case = self._case(challenge_proposed_result="Safe")
        with patch("tasp.services.challenge_triage._mode", return_value="off"):
            self.assertIsNone(triage(case))
        self.assertFalse(ChallengeTriage.objects.exists())

    def test_log_mode_never_applies(self):
        case = self._case(results="Safe", challenge_proposed_result="Safe")
        with patch("tasp.services.challenge_triage._mode", return_value="log"):
            row = triage(case)
        self.assertEqual(row.decision, ANALYST)
        self.assertFalse(row.applied)

    def test_enforce_applies_only_an_analyst_decision(self):
        a = self._case(results="Safe", challenge_proposed_result="Safe")
        b = self._case(results="Dangerous", challenge_proposed_result="Safe")
        with patch("tasp.services.challenge_triage._mode", return_value="enforce"):
            self.assertTrue(triage(a).applied)
            self.assertFalse(triage(b).applied)

    def test_an_unknown_mode_is_log(self):
        from tasp.services.challenge_triage import _mode
        with patch("tasp.services.challenge_triage._config", return_value={"challenge_triage": "bogus"}):
            self.assertEqual(_mode(), "log")
        with patch("tasp.services.challenge_triage._config", return_value={}):
            self.assertEqual(_mode(), "log")


class NotifyTriageTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="nt", password="x")
        self.case = Case.objects.create(description="", reporter=user, is_challenged=True,
                                        results="Safe", challenge_proposed_result="Safe")

    def _notify(self, mode):
        with patch("tasp.services.challenge._load_thehive_config", return_value={"enabled": True}), \
             patch("tasp.services.challenge_triage._mode", return_value=mode), \
             patch("tasp.tasks.push_challenge_to_thehive.delay") as m_delay:
            CaseChallengeService(self.case, logging.getLogger("t")).notify()
        return m_delay

    def test_log_mode_still_alerts(self):
        self._notify("log").assert_called_once()
        self.assertEqual(ChallengeTriage.objects.get().decision, ANALYST)

    def test_enforce_skips_the_alert_for_an_analyst_decision(self):
        self._notify("enforce").assert_not_called()
        self.assertTrue(ChallengeTriage.objects.get().applied)

    def test_enforce_skips_the_cert_mail_too_when_thehive_is_off(self):
        with patch("tasp.services.challenge._load_thehive_config", return_value={"enabled": False}), \
             patch("tasp.services.challenge_triage._mode", return_value="enforce"), \
             patch("tasp.services.challenge.ChallengeToTheHiveService") as m_mail:
            CaseChallengeService(self.case, logging.getLogger("t")).notify()
        m_mail.assert_not_called()

    def test_a_triage_failure_alerts_as_before(self):
        with patch("tasp.services.challenge._load_thehive_config", return_value={"enabled": True}), \
             patch("tasp.services.challenge.triage", side_effect=RuntimeError("boom")), \
             patch("tasp.tasks.push_challenge_to_thehive.delay") as m_delay:
            CaseChallengeService(self.case, logging.getLogger("t")).notify()
        m_delay.assert_called_once()
