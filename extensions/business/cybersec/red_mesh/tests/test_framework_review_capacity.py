"""Review transport admission: one row cap, durable receipts."""
import copy
from uuid import uuid4
from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
from .test_framework_assessment import FrameworkAssessmentFixture, PACK
from . import test_framework_review as existing


def sized_history(review, target):
  """Build a validator-valid older history at an exact UTF-8 size, no unknown padding fields."""
  row = copy.deepcopy(review)
  template = {'revision': row['submitted_revision'], 'actor': row['history'][0]['actor']}
  while r._size(row) < target:
    row['history'].append(r.event(template, 'comment', 'creator', str(uuid4()),
      control_id='GV.PO-01.1', comment='\U00010000' * 1500))
    row['review_revision'] = len(row['history'])
  excess = r._size(row) - target
  comment = row['history'][-1]['comment']
  if excess < len(comment.encode()):
    remove = (excess + 3) // 4
    row['history'][-1]['comment'] = comment[:len(comment)-remove] + 'x' * (remove*4-excess)
  else:
    row['history'].pop()
    row['review_revision'] = len(row['history'])
    row['history'][-1]['comment'] += 'x' * (target-r._size(row))
  assert r._size(row) == target
  r.validate_review(row, row['ids'])
  return row


class TestReviewTransportAdmission(FrameworkAssessmentFixture):
  submitted = existing.TestFrameworkReview.submitted
  review = existing.TestFrameworkReview.review
  mutate = existing.TestFrameworkReview.mutate
  restart = existing.TestFrameworkReview.restart

  def review_key(self):
    return next(key for key, value in self.storage.data.items()
                if isinstance(value, dict) and value.get('kind') == r.KIND)

  def test_exact_write_boundary_and_one_byte_over(self):
    self.assertEqual(r.ROW_BYTES_MAX, 512*1024)
    self.submitted()
    original = self.storage.data[self.review_key()]
    entry = r.event({'revision':1,'actor':'initial'}, 'approve', 'creator', str(uuid4()))
    overhead = r._size({**original,'history':[*original['history'],entry],
                        'review_revision':original['review_revision']+1}) - r._size(original)
    boundary = r.ROW_BYTES_MAX - 1024
    row = sized_history(original,boundary-overhead)
    accepted = r._append(row,entry)
    self.assertEqual(r._size(accepted),boundary)
    with self.assertRaises(Exception) as raised:
      r._append(sized_history(original,boundary-overhead+1),entry)
    self.assertEqual(raised.exception.error,'review_capacity')

  def test_row_at_cap_reads_replays_and_refuses_all_new_mutations_without_writes(self):
    self.submitted()
    request = str(uuid4())
    control = next(iter(self.basic_scores()))
    self.ok(self.mutate('comment',request=request,control=control,comment='Existing comment'))
    key = self.review_key()
    self.storage.data[key] = sized_history(self.storage.data[key], r.ROW_BYTES_MAX - 1024)
    history = copy.deepcopy(self.storage.data[key]['history'])
    self.assertEqual(self.ok(self.review())['history'],history)
    self.assertTrue(self.ok(self.mutate('comment',request=request,control=control,comment='Existing comment'))['replayed'])
    before = copy.deepcopy(self.storage.data)
    writes = len(self.storage.writes)
    for action in ('comment','approve','return'):
      kwargs = {'control':control,'comment':'New comment'} if action=='comment' else {}
      self.refused(self.mutate(action,expected=len(history),**kwargs),409,'review_capacity')
      self.assertEqual(self.storage.data,before)
      self.assertEqual(len(self.storage.writes),writes)

  def test_dnsc_row_with_fifty_submissions_stays_far_under_the_sender_guard(self):
    import json
    from extensions.business.cybersec.red_mesh.tenancy import compliance as c
    revision = self.complete_basic_draft()
    for _ in range(c.MAX_SUBMISSIONS):
      revision = self.ok(self.submit(revision, str(uuid4())))['assessmentRevision']
      if len(self.stored_row()['submissions']) < c.MAX_SUBMISSIONS:
        revision = self.ok(self.reopen(revision, str(uuid4())))['assessmentRevision']
        revision = self.ok(self.save({'completion_date': '2026-10-06', 'management_signoff': {
          'name': 'Ana Pop', 'role': 'Director', 'date': '2026-10-06'}}, revision))['assessmentRevision']
    row = self.stored_row()
    self.assertEqual(len(row['submissions']), c.MAX_SUBMISSIONS)
    self.assertTrue(all('historical_context' not in sub and len(sub['context_sha256']) == 64 for sub in row['submissions']))
    size = len(json.dumps(row, ensure_ascii=False).encode('utf-8'))
    self.assertLess(size, 512 * 1024)

  def test_assessment_get_never_reads_or_repairs_a_review_row(self):
    self.submitted()
    request = str(uuid4())
    self.storage.fail_write = len(self.storage.writes) + 2
    self.refused(self.mutate('return',request=request),503,'unavailable')
    self.storage.fail_write = None
    key = self.review_key()
    self.storage.data[key]['oversized'] = 'x' * r.ROW_BYTES_MAX  # a review row the validator refuses
    before = copy.deepcopy(self.storage.data)
    writes = len(self.storage.writes)
    self.restart()
    self.assertEqual(self.get()['success'],True)  # was 409 review_capacity
    self.assertEqual(self.storage.data,before)
    self.assertEqual(len(self.storage.writes),writes)
    self.refused(self.review(),503,'unavailable')

  def test_new_return_receipt_repairs_under_write_budget(self):
    self.submitted()
    request = str(uuid4())
    self.storage.fail_write = len(self.storage.writes) + 2
    self.refused(self.mutate('return',request=request),503,'unavailable')
    self.storage.fail_write = None
    self.restart()
    self.ok(self.get())
    review = self.ok(self.review())
    self.assertEqual([e['action'] for e in review['history']],['submit','return'])
    self.assertTrue(self.ok(self.mutate('return',request=request))['replayed'])
