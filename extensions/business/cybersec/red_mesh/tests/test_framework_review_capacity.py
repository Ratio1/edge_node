"""Review transport admission preserves larger historical rows and durable receipts."""
import copy
from uuid import uuid4
from ..tenancy import compliance_review as r
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
    self.assertEqual(r.ROW_WRITE_BYTES_MAX, 512*1024)
    self.assertEqual(r.ROW_BYTES_MAX, 2*1024*1024)
    self.submitted()
    original = self.storage.data[self.review_key()]
    entry = r.event({'revision':1,'actor':'initial'}, 'approve', 'creator', str(uuid4()))
    overhead = r._size({**original,'history':[*original['history'],entry],
                        'review_revision':original['review_revision']+1}) - r._size(original)
    boundary = r.ROW_WRITE_BYTES_MAX - 1024
    row = sized_history(original,boundary-overhead)
    accepted = r._append(row,entry)
    self.assertEqual(r._size(accepted),boundary)
    with self.assertRaises(Exception) as raised:
      r._append(sized_history(original,boundary-overhead+1),entry)
    self.assertEqual(raised.exception.error,'review_capacity')

  def test_larger_old_row_reads_replays_and_refuses_all_new_mutations_without_writes(self):
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

  def test_old_oversized_pending_return_preserves_receipt_and_refuses_repair_without_writes(self):
    from unittest.mock import patch
    self.submitted()
    key = self.review_key()
    self.storage.data[key] = sized_history(self.storage.data[key], r.ROW_WRITE_BYTES_MAX + 4096)
    request = str(uuid4())
    # Old software wrote assessment receipt, then failed writing its review event.
    with patch.object(r,'ROW_WRITE_BYTES_MAX',r.ROW_BYTES_MAX):
      self.storage.fail_write = len(self.storage.writes) + 2
      self.refused(self.mutate('return',expected=self.storage.data[key]['review_revision'],request=request),503,'unavailable')
    self.storage.fail_write = None
    receipt = copy.deepcopy(self.stored_row()['submissions'][0]['review_return'])
    self.assertEqual(receipt['request_id'],request)
    before = copy.deepcopy(self.storage.data)
    writes = len(self.storage.writes)
    self.restart()
    self.refused(self.get(),409,'review_capacity')
    self.assertEqual(self.storage.data,before)
    self.assertEqual(len(self.storage.writes),writes)
    self.assertEqual(self.stored_row()['submissions'][0]['review_return'],receipt)
    r.validate_review(self.storage.data[key],self.storage.data[key]['ids'])

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
