"""NIS2 production pack through actual endpoint, adapter, snapshot and review seams."""
import copy
from uuid import uuid4
from extensions.business.cybersec.red_mesh.references import framework_packs as packs
from extensions.business.cybersec.red_mesh.tenancy import compliance
from .test_framework_assessment import FrameworkAssessmentFixture

PACK = 'eu.ec.ir-2024-2690'
EU27 = 'AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE'.split()

class StatusLifecycleFixture(FrameworkAssessmentFixture):
  def create_status(self, country='DE'):
    return self.ok(self.plugin.create_framework_assessment(self.admin,self.tenant,PACK,str(uuid4()),'Annex '+str(country),None,None,country))

  def save_status(self, aid, body, revision):
    return self.plugin.save_framework_assessment_draft(self.admin,self.tenant,PACK,body,revision,aid)

  def submit_status(self, aid, revision, request=None):
    return self.plugin.submit_framework_assessment(self.admin,self.tenant,PACK,revision,request or str(uuid4()),None,aid)

  def full_scores(self):
    return {c['ref_id']:{'status':'implemented'} for c in packs.load_framework_pack(PACK)['controls']}

class TestStatusLifecycle(StatusLifecycleFixture):
  def test_eu27_country_catalogue_and_non_eu_rejection(self):
    for country in sorted(EU27):
      self.assertEqual(compliance.resolve_country(PACK,country),country)
    self.create_status('DE')
    self.assertEqual(self.stored_row()['country'],'DE')
    for country in ('US','GB','ZZ','de'):
      self.refused(self.plugin.create_framework_assessment(self.admin,self.tenant,PACK,str(uuid4()),'Annex '+str(country),None,None,country),400,'assessment_invalid')
    listed=self.ok(self.plugin.list_framework_packs(self.admin,self.tenant))
    nis=next(p for p in listed['packs'] if p['packId']==PACK)
    self.assertEqual(nis['exports'],['json','csv','pdf'])
    self.assertEqual(nis['entries'][0]['jurisdiction'],'EU')
    self.assertFalse(nis['capabilities']['has_verdict'])

  def test_evidence_only_deletion_foreign_fields_and_job_ownership(self):
    made=self.create_status();aid=made['assessmentId'];ref=next(iter(self.full_scores()))
    saved=self.ok(self.save_status(aid,{'scores':{ref:{'evidence_refs':['contract']}}},1))
    self.assertIsNone(saved['scores'][ref]['status'])
    self.assertEqual(saved['computed']['counts']['unanswered'],161)
    self.refused(self.submit_status(aid,saved['assessmentRevision']),400,'assessment_invalid')
    for entry in ({'status':'na'},{'documentation':3},{'status':'wrong'}, {'evidence_refs':['job:foreign:1']}):
      self.refused(self.save_status(aid,{'scores':{ref:entry}},saved['assessmentRevision']),400,'assessment_invalid')
    before=copy.deepcopy(self.storage.data)
    for surrogate in ("\ud800","\udfff"):  # lone surrogate rationale: refused, storage untouched
      self.refused(self.save_status(aid,{'scores':{ref:{'status':'partial','rationale':surrogate}}},saved['assessmentRevision']),400,'assessment_invalid')
      self.assertEqual(self.storage.data,before)
    deleted=self.ok(self.save_status(aid,{'scores':{ref:None}},saved['assessmentRevision']))
    self.assertEqual(deleted['scores'],{})
    self.refused(self.save_status(aid,{'completion_date':'2026-02-30'},deleted['assessmentRevision']),400,'assessment_invalid')

  def test_submit_freezes_then_review_return_and_resubmit(self):
    made=self.create_status();aid=made['assessmentId'];scores=self.full_scores();refs=list(scores)
    scores[refs[0]]={'status':'na','rationale':'Proportionate alternative, Article 2/Recital 4.'}
    scores[refs[1]]={'status':'partial'};scores[refs[2]]={'status':'not_implemented'}
    saved=self.ok(self.save_status(aid,{'scores':scores},1))
    self.assertEqual(saved['submitErrors'],[])
    self.assertEqual(saved['computed']['counts'],dict(implemented=158,partial=1,not_implemented=1,na=1,unanswered=0))
    self.documents.fail=True;request=str(uuid4())
    self.refused(self.submit_status(aid,saved['assessmentRevision'],request),503,'unavailable')
    row=self.stored_row();frozen=copy.deepcopy(row['pending']['historical_context'])
    self.assertEqual(row['pending']['computed'],saved['computed'])
    self.refused(self.save_status(aid,{'scores':{refs[0]:None}},row['assessment_revision']),409,'assessment_submit_pending')
    self.documents.fail=False
    done=self.ok(self.submit_status(aid,saved['assessmentRevision'],request))
    self.assertIsNone(done['verdict']['passed'])
    submission=self.stored_row()['submissions'][0]
    self.assertNotIn('historical_context',submission)
    self.assertEqual(submission['context_sha256'],compliance.context_digest(frozen))
    self.assertEqual(submission['assessable_ids'],frozen['assessable_ids'])
    review=self.ok(self.plugin.get_framework_assessment_review(self.creator,self.tenant,PACK,1,aid))
    self.assertEqual(review['historical_context'],frozen)
    reviewed=self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,1,'comment',1,str(uuid4()),refs[0],'Checked',aid))
    self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,1,'return',reviewed['review_revision'],str(uuid4()),None,None,aid))
    returned=self.stored_row();self.assertEqual(returned['state'],'draft')
    self.assertEqual(returned['submissions'][0]['review_return']['action'],'return')
    self.ok(self.submit_status(aid,returned['assessment_revision']))
    done=self.stored_row();self.assertEqual(len(done['submissions']),2)
    self.assertIsNone(done['submissions'][1]['verdict']['passed'])
    self.ok(self.plugin.reopen_framework_assessment(self.admin,self.tenant,PACK,done['assessment_revision'],str(uuid4()),aid))
    self.assertEqual(self.stored_row()['state'],'draft')
