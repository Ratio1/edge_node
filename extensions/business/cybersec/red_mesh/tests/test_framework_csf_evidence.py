"""Offline real endpoint candidates and pre-refactor full DNSC DTO parity."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from .test_framework_assessment import FrameworkAssessmentFixture
from . import test_framework_evidence as fixtures
from ..references.framework_packs import load_framework_pack
from ..services import framework_evidence as evidence

CSF = 'us.nist.csf-2.0'




class TestCsfEvidence(FrameworkAssessmentFixture):
  job, triage = fixtures.TestFrameworkEvidenceSuggestions.job, fixtures.TestFrameworkEvidenceSuggestions.triage
  HIGH_AUTH, LOW_TLS = fixtures.TestFrameworkEvidenceSuggestions.HIGH_AUTH, fixtures.TestFrameworkEvidenceSuggestions.LOW_TLS

  def setUp(self):
    super().setUp()
    evidence.reset_cache()
    self.archives = {}
    self.plugin.r1fs = SimpleNamespace(get_json=lambda cid, *args, **kwargs: deepcopy(self.archives.get(cid)))
    self.csf = self.ok(self.plugin.create_framework_assessment(self.admin, self.tenant, CSF, str(uuid4()), 'CSF'))
    self.aid = self.csf['assessmentId']

  def suggest(self):
    return self.ok(self.plugin.suggest_framework_assessment_evidence(self.admin, self.tenant, CSF, self.aid))

  def test_selected_controls_and_explicit_translation_strategies(self):
    from ..services.framework_evidence_mapping import resolve, PACK_STRATEGIES
    selected = [{'ref_id': 'ID.RA-01'}, {'ref_id': 'GV.OC-01'}]
    self.assertEqual(evidence.mapped_controls(CSF, selected), {'ID.RA-01': 'vulnerability_management'})
    with patch.dict(PACK_STRATEGIES, {'test': {'strategy': 'identity'}}):
      self.assertEqual(list(resolve('test', [{'ref_id': 'ID.RA-01'}]).values()), ['vulnerability_management'])
    for strategy in ('prefix', 'mapping'):  # retired: a pack naming one translates nothing
      with patch.dict(PACK_STRATEGIES, {'test': {'strategy': strategy, 'mapping': {'LOCAL': 'ID.RA-01'}}}):
        self.assertEqual(resolve('test', [{'ref_id': 'ID.RA-01.7'}, {'ref_id': 'LOCAL'}]), {})
    self.assertEqual(resolve('unknown', selected), {})

  def test_candidates_null_level_and_reads_preserve_every_answer_and_tier_without_writes(self):
    entry = {'included': False, 'rationale': 'Outside scope', 'current_rating': 2, 'target_rating': 5,
             'evidence_refs': [{'ref': 'contract', 'review_state': 'linked'}]}
    self.ok(self.plugin.save_framework_assessment_draft(self.admin, self.tenant, CSF,
      {'scores': {'ID.RA-01': entry}, 'function_tiers': {'ID': {'current': 1, 'target': 4}}}, 1, self.aid))
    self.job('job-open', findings=[self.HIGH_AUTH, self.LOW_TLS], soc={'last_status': 'sent'})
    before, writes = deepcopy(self.storage.data), deepcopy(self.storage.writes)
    data = self.suggest()
    self.assertIsNone(data['assuranceLevel'])
    self.assertEqual(set(data['suggestions']), {'ID.RA-01', 'PR.DS-02', 'PR.AA-03', 'PR.AA-05', 'ID.IM-02'})
    self.assertEqual(data['overriding'], [])
    self.assertTrue(all(item['status'] == 'needs_review' for rows in data['suggestions'].values() for item in rows))
    self.assertIn('identification', data['suggestions']['ID.RA-01'][0]['summary'])
    self.assertIn('potential improvements', data['suggestions']['ID.IM-02'][0]['summary'])
    self.assertEqual((self.storage.data, self.storage.writes), (before, writes))
    linked = {**entry, 'evidence_refs': entry['evidence_refs'] + [{'ref': data['suggestions']['ID.RA-01'][0]['ref'], 'review_state': 'linked'}]}
    saved = self.ok(self.plugin.save_framework_assessment_draft(self.admin, self.tenant, CSF,
      {'scores': {'ID.RA-01': linked}}, 2, self.aid))
    self.assertEqual({key: saved['scores']['ID.RA-01'][key] for key in linked}, linked)
    self.assertEqual(saved['function_tiers'], {'ID': {'current': 1, 'target': 4}})

  def test_empty_unrelated_auth_and_tls_never_establish_achievement(self):
    cases = [([], {'ID.IM-02'}), ([{'title': 'Unrelated issue', 'severity': 'HIGH'}], {'ID.RA-01', 'ID.IM-02'}),
             ([self.HIGH_AUTH], {'ID.RA-01', 'ID.IM-02', 'PR.AA-03', 'PR.AA-05'}),
             ([self.LOW_TLS], {'ID.RA-01', 'ID.IM-02', 'PR.DS-02'})]
    for index, (findings, expected) in enumerate(cases):
      self.job('job-case', findings=findings, completed=1770000300 + index)
      evidence.reset_cache()
      self.assertEqual(set(self.suggest()['suggestions']), expected)

  def test_soc_variants_never_suggest_monitoring_or_analysis(self):
    for soc, correlation in [({'last_status': 'sent'}, None), (None, {'status': 'completed'}),
                             (None, None), ({'last_status': 'pending'}, None), ({'last_status': 'failed'}, None)]:
      self.job('job-soc', soc=soc)
      if correlation is not None:
        self.archives['archive-job-soc']['detection_correlation'] = correlation
      evidence.reset_cache()
      self.assertEqual(set(self.suggest()['suggestions']), {'ID.IM-02'})

  def test_foreign_unfinalized_bounds_order_and_triage(self):
    for index in range(25):
      self.job(f'job-{index:02d}', findings=[self.HIGH_AUTH], completed=1770000000 + index)
    self.job('foreign', tenant='tn_' + str(uuid4()), completed=1770009999)
    self.job('pending', finalized=False)
    data = self.suggest()
    self.assertEqual((data['jobsAvailable'], data['jobsConsidered']), (25, 20))
    self.assertEqual([item['ref'] for item in data['suggestions']['PR.AA-03']],
                     ['job:job-24:2', 'job:job-23:2', 'job:job-22:2'])
    self.assertNotIn('foreign', str(data))
    for index in range(25):
      self.triage(f'job-{index:02d}', 'f-auth', 'remediated')
    evidence.reset_cache()
    self.assertEqual(set(self.suggest()['suggestions']), {'ID.IM-02'})
