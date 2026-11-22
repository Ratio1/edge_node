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
    return {c['ref_id']:{'status':'criteria_met'} for c in packs.load_framework_pack(PACK)['controls']}

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
    for entry in ({'status':'na'},{'applicability':'not_applicable'},{'documentation':3},{'status':'wrong'}, {'evidence_refs':['job:foreign:1']}):
      self.refused(self.save_status(aid,{'scores':{ref:entry}},saved['assessmentRevision']),400,'assessment_invalid')
    before=copy.deepcopy(self.storage.data)
    for surrogate in ("\ud800","\udfff"):  # lone surrogate rationale: refused, storage untouched
      self.refused(self.save_status(aid,{'scores':{ref:{'status':'partly_met','rationale':surrogate}}},saved['assessmentRevision']),400,'assessment_invalid')
      self.assertEqual(self.storage.data,before)
    deleted=self.ok(self.save_status(aid,{'scores':{ref:None}},saved['assessmentRevision']))
    self.assertEqual(deleted['scores'],{})
    self.refused(self.save_status(aid,{'completion_date':'2026-02-30'},deleted['assessmentRevision']),400,'assessment_invalid')

  def test_submit_freezes_then_review_return_and_resubmit(self):
    made=self.create_status();aid=made['assessmentId'];scores=self.full_scores();refs=list(scores)
    scores[refs[0]]={'applicability':'not_applicable','rationale':'Proportionate alternative, Article 2/Recital 4.'}
    scores[refs[1]]={'status':'partly_met'};scores[refs[2]]={'status':'criteria_not_met'}
    saved=self.ok(self.save_status(aid,{'scores':scores},1))
    self.assertEqual(saved['submitErrors'],[])
    self.assertEqual(saved['computed']['counts'],dict(insufficient_evidence=0,criteria_met=158,partly_met=1,criteria_not_met=1,not_applicable=1,unanswered=0))
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

  def test_list_summary_carries_review_status_of_latest_submission(self):
    made=self.create_status();aid=made['assessmentId']
    def listed():
      row=next(r for r in self.ok(self.plugin.list_framework_assessments(self.admin,self.tenant,PACK,False)) if r['assessmentId']==aid)
      return row['reviewStatus'],row['selfApproved']
    self.assertEqual(listed(),(None,None))
    saved=self.ok(self.save_status(aid,{'scores':self.full_scores()},1))
    self.ok(self.submit_status(aid,saved['assessmentRevision']))
    self.assertEqual(listed(),('submitted',False))
    self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,1,'return',1,str(uuid4()),None,None,aid))
    self.assertEqual(listed(),('returned_for_changes',False))
    self.ok(self.submit_status(aid,self.stored_row()['assessment_revision']))
    self.assertEqual(listed(),('submitted',False))
    self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,2,'approve',1,str(uuid4()),None,None,aid))
    self.assertEqual(listed(),('internally_approved',False))
    own=self.create_status('FR')['assessmentId']  # submitted and approved by the same reviewer: self-approved
    saved=self.ok(self.plugin.save_framework_assessment_draft(self.creator,self.tenant,PACK,{'scores':self.full_scores()},1,own))
    self.ok(self.plugin.submit_framework_assessment(self.creator,self.tenant,PACK,saved['assessmentRevision'],str(uuid4()),None,own))
    self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,1,'approve',1,str(uuid4()),None,None,own))
    row=next(r for r in self.ok(self.plugin.list_framework_assessments(self.admin,self.tenant,PACK,False)) if r['assessmentId']==own)
    self.assertEqual((row['reviewStatus'],row['selfApproved']),('internally_approved',True))

  def test_list_summary_survives_unusable_review_rows(self):
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    aid=self.create_status('DE')['assessmentId'];other=self.create_status('FR')['assessmentId']
    def listed(which):
      return next(x for x in self.ok(self.plugin.list_framework_assessments(self.admin,self.tenant,PACK,False)) if x['assessmentId']==which)
    for which in (aid,other):
      saved=self.ok(self.save_status(which,{'scores':self.full_scores()},1))
      self.ok(self.submit_status(which,saved['assessmentRevision']))
    key=next(k for k,v in self.storage.data.items() if isinstance(v,dict) and v.get('kind')==r.KIND and v['ids'][2]==aid)
    good=copy.deepcopy(self.storage.data[key])
    self.storage.data[key]['history'][0]['action']='unknown'  # refused by the validator
    self.assertEqual((listed(aid)['reviewStatus'],listed(aid)['selfApproved']),(None,None))
    self.assertEqual(listed(other)['reviewStatus'],'submitted')
    self.storage.data[key]={**good,'fingerprint':'b'*64}  # bound to another submission
    self.assertIsNone(listed(aid)['reviewStatus'])
    self.storage.data[key]=None  # review row not written yet: still submitted
    self.assertEqual(listed(aid)['reviewStatus'],'submitted')
    self.storage.data[key]=good
    self.assertEqual(listed(aid)['reviewStatus'],'submitted')
    self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,1,'return',1,str(uuid4()),None,None,aid))
    returned=copy.deepcopy(self.storage.data[key])
    self.storage.data[key]={**returned,'history':returned['history'][:1],'review_revision':1}  # receipt not yet copied
    self.assertEqual((listed(aid)['reviewStatus'],listed(aid)['selfApproved']),('returned_for_changes',False))
    self.storage.data[key]=None  # receipt alone, review row missing
    self.assertEqual(listed(aid)['reviewStatus'],'returned_for_changes')

  def test_list_summary_survives_a_review_read_error(self):
    from unittest import mock
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore as S
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    aid=self.create_status('DE')['assessmentId'];other=self.create_status('FR')['assessmentId']
    def listed(which):
      return next(x for x in self.ok(self.plugin.list_framework_assessments(self.admin,self.tenant,PACK,False)) if x['assessmentId']==which)
    for which in (aid,other):
      saved=self.ok(self.save_status(which,{'scores':self.full_scores()},1))
      self.ok(self.submit_status(which,saved['assessmentRevision']))
    original=S.raw_record
    def flaky(store,kind,*ids):
      if kind==r.KIND and ids[2]==aid:
        raise TenantStoreError('Compliance storage cannot be read')
      return original(store,kind,*ids)
    with mock.patch.object(S,'raw_record',flaky):
      self.assertEqual((listed(aid)['reviewStatus'],listed(aid)['selfApproved']),(None,None))
      self.assertEqual(listed(other)['reviewStatus'],'submitted')

  def test_list_summary_ignores_a_malformed_return_receipt(self):
    from types import SimpleNamespace
    from extensions.business.cybersec.red_mesh.tenancy import compliance_review as r
    service=SimpleNamespace(compliance=SimpleNamespace(raw_record=lambda *ids:None))  # no review row yet
    sub={'revision':1,'fingerprint':'a'*64,'request_id':'q','actor':'u','submitted_at':'t'}
    row={'tenant_id':'t','pack_id':'p','assessment_id':'default','submissions':[sub]}
    good={'actor':'u2','action':'return','time':'t','revision':1,'request_id':'r','control_id':None,'comment':None,'self_approved':False}
    for label,receipt in (('wrong action',{**good,'action':'approve'}),('extra key',{**good,'x':1}),('revision',{**good,'revision':2})):
      with self.subTest(label):
        row['submissions']=[{**sub,'review_return':receipt}]
        self.assertEqual(r.latest_status(service,row),('submitted',False))
    row['submissions']=[{**sub,'review_return':good}]
    self.assertEqual(r.latest_status(service,row),('returned_for_changes',False))
