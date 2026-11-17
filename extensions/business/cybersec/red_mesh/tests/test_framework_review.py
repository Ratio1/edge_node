"""RM-183 review through plugin, service and real CStore adapter."""
from uuid import uuid4
from .test_framework_assessment import FrameworkAssessmentFixture, PACK


class TestFrameworkReview(FrameworkAssessmentFixture):
  def submitted(self):
    self.ok(self.submit(self.complete_basic_draft(), str(uuid4())))

  def review(self, actor=None, revision=1):
    return self.plugin.get_framework_assessment_review(actor or self.creator, self.tenant, PACK, revision)

  def mutate(self, action, expected=1, actor=None, request=None, control=None, comment=None, revision=1):
    return self.plugin.mutate_framework_assessment_review(actor or self.creator, self.tenant, PACK, revision,
      action, expected, request or str(uuid4()), control, comment)

  def test_review_projects_authorized_actor_labels_without_profile_contacts(self):
    self.submitted()
    self.ok(self.plugin.update_account_profile(self.creator, 'initial', {'full_name': 'Reviewer Name', 'contact_email': 'private@example.com'}))
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'initial', True))
    self.ok(self.mutate('approve', actor=self.admin))
    view = self.ok(self.review(actor=self.viewer))
    self.assertEqual(view['actor_names']['initial'], 'Reviewer Name')
    self.assertEqual(view['history'][-1]['actor'], 'initial')
    self.assertNotIn('private@example.com', str(view))

  def test_submission_freezes_export_capabilities_from_rules(self):
    from unittest.mock import patch
    from ..tenancy import compliance as c
    self.submitted()
    context = self.ok(self.review())['historical_context']
    self.assertIn('eval_mms', context['manifest']['exports'])
    manifest = {**c.manifest_pack(PACK), 'rules': {**c.manifest_pack(PACK)['rules'], 'exports': ['json']}}
    with patch.object(c, 'manifest_pack', return_value=manifest):
      self.assertEqual(self.ok(self.review())['historical_context'], context)

  def test_sta_defaults_on_submit_history_and_comment_revision_is_independent(self):
    self.submitted()
    before = self.ok(self.get())['assessmentRevision']
    view = self.ok(self.review())
    self.assertTrue(view['can_review'])
    self.assertEqual([e['action'] for e in view['history']], ['submit'])
    view = self.ok(self.mutate('comment', control=next(iter(self.basic_scores())), comment='Evidence checked'))
    self.assertEqual(view['review_revision'], 2)
    self.assertEqual(self.ok(self.get())['assessmentRevision'], before)
    self.assertEqual([e['action'] for e in view['history']], ['submit', 'comment'])

  def test_denied_roles_designation_defaults_and_self_approval(self):
    self.submitted()
    self.refused(self.mutate('approve', actor=self.admin), 403, 'reviewer_not_designated')
    self.refused(self.mutate('approve', actor=self.viewer), 403, 'forbidden')
    self.refused(self.mutate('approve', actor=self.pentester), 403, 'forbidden')
    self.refused(self.plugin.set_compliance_reviewer(self.admin, 'initial', True), 403, 'forbidden')
    self.refused(self.plugin.update_account_profile(self.admin, 'initial', {'compliance_reviewer': True}), 400, 'invalid_request')
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'initial', True))
    self.ok(self.plugin.update_tenant_allow_pentester(self.creator, self.tenant, False))
    approved = self.ok(self.mutate('approve', actor=self.admin))
    self.assertTrue(approved['self_approved'])
    self.assertEqual(approved['status'], 'internally_approved')
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'creator', False))
    self.refused(self.mutate('approve', expected=2), 403, 'reviewer_not_designated')
    self.assertFalse(self.ok(self.plugin.get_account_profile(self.creator))['compliance_reviewer'])
    # Recreated account must not inherit old designation or false override.
    self.storage.data[('auth', 'initial')]['createdAt'] = '2026-11-16T08:00:00.000Z'
    self.refused(self.mutate('approve', expected=2, actor=self.admin), 403, 'reviewer_not_designated')
    self.storage.data[('auth', 'creator')]['createdAt'] = '2026-11-16T08:00:00.000Z'
    self.assertTrue(self.ok(self.review())['can_review'])

  def test_flagged_admin_review_dto_matches_mutation_authority(self):
    self.submitted()
    self.assertFalse(self.ok(self.review(actor=self.admin))['can_review'])
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'initial', True))
    self.assertTrue(self.ok(self.review(actor=self.admin))['can_review'])
    result = self.ok(self.mutate('comment', actor=self.admin,
      control=next(iter(self.basic_scores())), comment='Designated reviewer'))
    self.assertTrue(result['can_review'])

  def test_disabled_sta_review_dto_matches_mutation_authority(self):
    self.submitted()
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'creator', False))
    self.assertFalse(self.ok(self.review())['can_review'])
    self.refused(self.mutate('approve'), 403, 'reviewer_not_designated')

  def test_malformed_unicode_comment_is_refused_without_state_change(self):
    import copy
    import json
    self.submitted()
    before_review = self.ok(self.review())
    before_assessment = self.ok(self.get())
    before_storage = copy.deepcopy(self.storage.data)
    for codepoint in ('d800', 'dfff'):
      with self.subTest(codepoint=codepoint):
        comment = json.loads('"\\u' + codepoint + '"')
        self.refused(self.mutate('comment', control=next(iter(self.basic_scores())), comment=comment),
          400, 'invalid_request')
        self.assertEqual(self.storage.data, before_storage)
        self.assertEqual(self.ok(self.review()), before_review)
        self.assertEqual(self.ok(self.get()), before_assessment)

  def test_stale_revision_and_request_binding(self):
    self.submitted()
    request = str(uuid4())
    result = self.ok(self.mutate('comment', request=request, control=next(iter(self.basic_scores())), comment='First'))
    self.assertEqual(result['review_revision'], 2)
    self.refused(self.mutate('approve'), 409, 'review_stale')
    replay = self.ok(self.mutate('comment', request=request, control=next(iter(self.basic_scores())), comment='First'))
    self.assertTrue(replay['replayed'])
    self.assertEqual(replay['review_revision'], 2)
    self.refused(self.mutate('comment', expected=2, request=request, control=next(iter(self.basic_scores())), comment='Changed'), 409, 'conflict')
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'initial', True))
    self.refused(self.mutate('comment', actor=self.admin, expected=2, request=request,
      control=next(iter(self.basic_scores())), comment='First'), 409, 'conflict')
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'creator', False))
    self.refused(self.mutate('comment', request=request, control=next(iter(self.basic_scores())), comment='First'), 403, 'reviewer_not_designated')

  def test_return_reopens_and_history_survives_resubmission(self):
    self.submitted()
    before = self.ok(self.get())['assessmentRevision']
    request = str(uuid4())
    result = self.ok(self.mutate('return', request=request))
    self.assertEqual(result['status'], 'returned_for_changes')
    current = self.ok(self.get())
    self.assertEqual(current['assessmentRevision'], before + 1)
    self.assertEqual((current['state'], current['managementSignoff'], current['completionDate']), ('draft', None, ''))
    self.assertTrue(self.ok(self.mutate('return', request=request))['replayed'])
    self.refused(self.mutate('approve', expected=2), 409, 'review_not_current')
    current = self.ok(self.save({'completion_date': '2026-11-16', 'management_signoff': {
      'name': 'Ana Pop', 'role': 'Director', 'date': '2026-11-16'}}, current['assessmentRevision']))
    self.ok(self.submit(current['assessmentRevision'], str(uuid4())))
    self.assertEqual([e['action'] for e in self.ok(self.review())['history']], ['submit', 'return'])
    self.assertTrue(self.ok(self.mutate('return', request=request))['replayed'])
    self.refused(self.mutate('approve', expected=2), 409, 'review_not_current')
    self.assertEqual(len(self.ok(self.review(revision=2))['history']), 1)

  def test_comment_control_and_fingerprint_mismatch(self):
    self.submitted()
    self.refused(self.mutate('comment', control='no-such-control', comment='Oops'), 400, 'review_control_invalid')
    from unittest.mock import patch
    original = self.Plugin._framework_assessment_artifact
    def tampered(plugin, *args, **kwargs):
      result = original(plugin, *args, **kwargs)
      result['data']['snapshot']['submission']['fingerprint'] = 'a' * 64
      return result
    with patch.object(self.Plugin, '_framework_assessment_artifact', tampered):
      self.refused(self.mutate('approve'), 409, 'document_integrity')

  def test_malformed_history_and_capacity_are_refused_without_truncation(self):
    import copy
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    self.submitted()
    key = next(key for key, value in self.storage.data.items() if isinstance(value, dict) and value.get('kind') == r.KIND)
    original = copy.deepcopy(self.storage.data[key])
    self.storage.data[key]['history'][0]['action'] = 'unknown'
    self.refused(self.review(), 503, 'unavailable')
    self.storage.data[key] = original
    with patch.object(r, 'EVENT_MAX', 1):
      self.refused(self.mutate('return'), 409, 'review_capacity')
      self.assertEqual(self.ok(self.get())['state'], 'submitted')
    self.assertEqual(self.storage.data[key], original)

  def test_frozen_context_has_no_verification_identity_and_is_used_after_retirement(self):
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.tenancy import compliance as c
    self.submitted()
    view = self.ok(self.review())
    context = view['historical_context']
    self.assertNotIn('verified_by', str(context))
    self.assertIn('licence', context['manifest'])
    with patch.object(c, 'load_framework_text', side_effect=AssertionError('current text accessed')):
      view = self.ok(self.review())
      self.assertEqual(view['historical_context'], context)

  def test_legacy_snapshot_missing_provenance_is_honest(self):
    self.submitted()
    # Simulate a pre-RM183 receipt and immutable snapshot.
    from unittest.mock import patch
    row = self.stored_row()
    row['submissions'][0].pop('context_sha256')
    row['submissions'][0].pop('assessable_ids')
    self.write_row(row)
    original = self.Plugin._framework_assessment_artifact
    def legacy(plugin, *args, **kwargs):
      result = original(plugin, *args, **kwargs)
      result['data']['snapshot'].pop('historical_context')
      return result
    with patch.object(self.Plugin, '_framework_assessment_artifact', legacy):
      view = self.ok(self.review())
      self.assertTrue(view['missing_historical_provenance'])
      self.assertIsNone(view['historical_context'])
      self.refused(self.mutate('comment', control=next(iter(self.basic_scores())), comment='Cannot bind'), 400, 'review_control_invalid')

  def test_failure_at_each_submit_write_recovers_after_restart(self):
    # Pending, assessment receipt, review creation: before-write and error-after-write cases.
    for offset in (1, 2, 3):
      for after in (False, True):
        with self.subTest(offset=offset, after=after):
          self.setUp()
          revision = self.complete_basic_draft()
          request = str(uuid4())
          self.storage.fail_write = len(self.storage.writes) + offset
          self.storage.fail_after_write = after
          self.refused(self.submit(revision, request), 503, 'unavailable')
          self.storage.fail_write = None
          self.restart()
          self.ok(self.submit(revision, request))
          history = self.ok(self.review())['history']
          self.assertEqual([e['action'] for e in history], ['submit'])
          self.assertEqual(history[0]['request_id'], request)

  def restart(self):
    # Throw away plugin/service instances; preserve CStore and document store only.
    old = self.plugin
    self.plugin = object.__new__(self.Plugin)
    for name in ('cfg_tenancy_namespace', 'cfg_instance_id', 'P', 'chainstore_hget', 'chainstore_hgetall',
                 'chainstore_hkeys', 'chainstore_hset', '_log_audit_event', 'configured_peers_reader'):
      setattr(self.plugin, name, getattr(old, name))
    self.plugin._document_store = lambda: self.documents

  def test_failure_at_each_return_write_recovers_after_restart_and_later_edit(self):
    for offset in (1, 2):
      for after in (False, True):
        with self.subTest(offset=offset, after=after):
          self.setUp()
          self.submitted()
          request = str(uuid4())
          self.storage.fail_write = len(self.storage.writes) + offset
          self.storage.fail_after_write = after
          self.refused(self.mutate('return', request=request), 503, 'unavailable')
          self.storage.fail_write = None
          self.restart()
          if offset == 1 and not after:
            self.ok(self.mutate('return', request=request))
          draft = self.ok(self.get())  # repairs receipt before later draft edits
          self.ok(self.save({'sectoral_requirements': 'Later edit'}, draft['assessmentRevision']))
          view = self.ok(self.mutate('return', request=request))
          self.assertTrue(view['replayed'])
          self.assertEqual([e['action'] for e in view['history']], ['submit', 'return'])

  def test_forged_self_approved_metadata_is_refused(self):
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    self.submitted()
    self.ok(self.mutate('approve'))  # STA did not submit this assessment
    key = next(key for key, value in self.storage.data.items() if isinstance(value, dict) and value.get('kind') == r.KIND)
    self.storage.data[key]['history'][-1]['self_approved'] = True
    self.refused(self.review(), 503, 'unavailable')

  def test_readback_failures_at_each_submit_and_return_write_never_report_success(self):
    from .test_framework_assessment import COMPLIANCE_HKEY
    for operation, offsets in (('submit', (1, 2, 3)), ('return', (1, 2))):
      for offset in offsets:
        with self.subTest(operation=operation, offset=offset):
          self.setUp()
          if operation == 'submit':
            revision = self.complete_basic_draft()
          else:
            self.submitted()
          request = str(uuid4())
          original_get = self.storage.chainstore_hget
          target = len(self.storage.writes) + offset
          failed = []
          def readback(**kwargs):
            if (kwargs['hkey'] == COMPLIANCE_HKEY and len(self.storage.writes) == target
                and self.storage.writes[-1] == (kwargs['hkey'], kwargs['key']) and not failed):
              failed.append(True)
              raise RuntimeError('readback unavailable')
            return original_get(**kwargs)
          self.plugin.chainstore_hget = readback
          result = self.submit(revision, request) if operation == 'submit' else self.mutate('return', request=request)
          self.refused(result, 503, 'unavailable')
          self.assertEqual(failed, [True])
          self.plugin.chainstore_hget = original_get
          self.restart()
          self.ok(self.submit(revision, request) if operation == 'submit' else self.mutate('return', request=request))
          history = self.ok(self.review())['history']
          self.assertEqual([e['action'] for e in history], ['submit'] if operation == 'submit' else ['submit', 'return'])

  def test_comment_failure_and_noop_are_recoverable_without_duplicate_events(self):
    from unittest.mock import patch
    self.submitted()
    for after in (False, True):
      request = str(uuid4())
      expected = self.ok(self.review())['review_revision']
      self.storage.fail_write = len(self.storage.writes) + 1
      self.storage.fail_after_write = after
      self.refused(self.mutate('comment', expected, request=request,
        control=next(iter(self.basic_scores())), comment='Durable'), 503, 'unavailable')
      self.storage.fail_write = None
      self.restart()
      result = self.ok(self.mutate('comment', expected, request=request,
        control=next(iter(self.basic_scores())), comment='Durable'))
      self.assertEqual(sum(e['request_id'] == request for e in result['history']), 1)
    self.storage.noop = True
    self.refused(self.mutate('approve', expected=result['review_revision']), 503, 'unavailable')
    self.storage.noop = False

  def test_concurrent_reviewers_leave_editor_revision_intact_and_return_reopen_race(self):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    self.submitted()
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'initial', True))
    before = self.ok(self.get())['assessmentRevision']
    gate = Barrier(2)
    def comment(actor):
      gate.wait()
      return self.mutate('comment', actor=actor, control=next(iter(self.basic_scores())), comment='Concurrent')
    with ThreadPoolExecutor(max_workers=2) as pool:
      results = list(pool.map(comment, (self.creator, self.admin)))
    self.assertEqual(sum(result['success'] for result in results), 1)
    loser = next(result for result in results if not result['success'])
    self.refused(loser, 409, 'review_stale')
    self.assertEqual(self.ok(self.get())['assessmentRevision'], before)
    gate = Barrier(2)
    def transition(action):
      gate.wait()
      return self.mutate('return', expected=2) if action == 'return' else self.reopen(before, str(uuid4()))
    with ThreadPoolExecutor(max_workers=2) as pool:
      results = list(pool.map(transition, ('return', 'reopen')))
    self.assertEqual(sum(result['success'] for result in results), 1)
    self.assertEqual(self.ok(self.get())['state'], 'draft')
    self.assertFalse(self.ok(self.review())['can_review'])

  def test_review_reads_survive_retired_pack_and_archiving_and_tenant_purge(self):
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.tenancy import compliance as c
    self.submitted()
    context = self.ok(self.review())['historical_context']
    manifest = {**c.manifest_pack(PACK), 'status': 'retired', 'title': 'Changed current title'}
    with patch.object(c, 'manifest_pack', return_value=manifest), patch.object(c, 'load_framework_text', side_effect=AssertionError('current text')):
      self.assertEqual(self.ok(self.review())['historical_context'], context)
    current = self.ok(self.get())
    self.ok(self.plugin.archive_framework_assessment(self.creator, self.tenant, PACK, '', True, current['assessmentRevision']))
    self.assertFalse(self.ok(self.review())['can_review'])
    self.refused(self.mutate('approve'), 409, 'assessment_archived')
    for name in ('initial', 'viewer', 'pentester'):
      self.storage.account(name, memberships=[])
    self.ok(self.plugin.delete_tenant(self.creator, self.tenant))
    self.assertEqual([v for v in self.compliance_rows().values() if v is not None], [])

  def test_frozen_context_is_pinned_at_preparation_across_retry(self):
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.tenancy import compliance as c
    revision = self.complete_basic_draft()
    request = str(uuid4())
    self.documents.fail = True
    self.refused(self.submit(revision, request), 503, 'unavailable')
    context = self.stored_row()['pending']['historical_context']
    self.documents.fail = False
    with patch.object(c, 'load_framework_text', side_effect=AssertionError('retry loaded current text')):
      self.ok(self.submit(revision, request))
      self.assertEqual(self.ok(self.review())['historical_context'], context)

  def test_adapter_key_validation_and_per_tenant_enumeration(self):
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    self.submitted()
    store = CstoreComplianceStore(self.plugin, 'deployment')
    self.assertEqual(store.tenant_record_ids(r.KIND, self.tenant), [[self.tenant, PACK, 'default', '1']])
    for tail in ((), ('1',), ('default', '0'), ('default', '-1'), ('default', '01'), ('bad', '1'), ('default', 1)):
      with self.subTest(tail=tail), self.assertRaises(TenantStoreError):
        store.get(r.KIND, self.tenant, PACK, *tail)
    self.assertEqual(store.tenant_record_ids(r.KIND, 'other'), [])

  def test_submission_retry_does_not_recompute_frozen_snapshot_with_current_scorer(self):
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.tenancy import compliance as c
    revision = self.complete_basic_draft()
    request = str(uuid4())
    self.documents.fail = True
    self.refused(self.submit(revision, request), 503, 'unavailable')
    self.documents.fail = False
    with patch.object(c.scorer_for(self.pack), 'compute', side_effect=AssertionError('recomputed pending snapshot')):
      result = self.submit(revision, request)
      self.assertTrue(result['success'])

  def test_comment_and_approve_storage_failures_preserve_history_on_retry(self):
    self.submitted()
    for action in ('comment', 'approve'):
      for after in (False, True):
        with self.subTest(action=action, after=after):
          request = str(uuid4())
          expected = self.ok(self.review())['review_revision']
          self.storage.fail_write = len(self.storage.writes) + 1
          self.storage.fail_after_write = after
          kwargs = {'control': next(iter(self.basic_scores())), 'comment': 'Checked'} if action == 'comment' else {}
          self.refused(self.mutate(action, expected, request=request, **kwargs), 503, 'unavailable')
          self.storage.fail_write = None
          self.restart()
          result = self.ok(self.mutate(action, expected, request=request, **kwargs))
          self.assertEqual(result['review_revision'], expected + 1)
          self.assertEqual(sum(e['request_id'] == request for e in result['history']), 1)

  def test_comment_and_row_byte_bounds_refuse_without_losing_history(self):
    import copy
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    self.submitted()
    self.refused(self.mutate('comment', control=next(iter(self.basic_scores())), comment='x' * (r.COMMENT_MAX + 1)), 400, 'invalid_request')
    before = self.ok(self.review())
    key = next(key for key, value in self.storage.data.items() if isinstance(value, dict) and value.get('kind') == r.KIND)
    original = copy.deepcopy(self.storage.data[key])
    with patch.object(r, 'ROW_BYTES_MAX', r._size(original) + 1024):
      self.refused(self.mutate('comment', control=next(iter(self.basic_scores())), comment='界' * r.COMMENT_MAX), 409, 'review_capacity')
    self.assertEqual(self.ok(self.review())['history'], before['history'])
    self.storage.data[key]['oversized'] = 'x' * r.ROW_BYTES_MAX
    self.refused(self.review(), 503, 'unavailable')
    self.storage.data[key] = original

  def test_designation_never_grants_viewer_or_pentester_and_missing_sta_profile_flag_stays_default(self):
    self.submitted()
    for name, actor in (('viewer', self.viewer), ('pentester', self.pentester)):
      self.ok(self.plugin.set_compliance_reviewer(self.creator, name, True))
      self.refused(self.mutate('approve', actor=actor), 403, 'forbidden')
    self.assertFalse(self.ok(self.review(actor=self.viewer))['can_review'])
    self.ok(self.plugin.update_account_profile(self.creator, 'creator', {'full_name': 'STA Profile'}))
    self.assertTrue(self.ok(self.review())['can_review'])
    self.storage.account('sp-user', memberships=[{'role': 'super_pentester', 'tenant_id': None}])
    self.refused(self.plugin.set_compliance_reviewer({'account_id': 'sp-user'}, 'initial', True), 403, 'forbidden')
    self.ok(self.plugin.set_compliance_reviewer(self.creator, 'sp-user', True))
    self.refused(self.mutate('approve', actor={'account_id': 'sp-user'}), 403, 'forbidden')
