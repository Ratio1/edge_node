"""CSF through real endpoint/adapter/document/review lifecycle, without runtime writes."""
import copy
from unittest.mock import patch
from uuid import uuid4
from extensions.business.cybersec.red_mesh.references import framework_packs as packs
from extensions.business.cybersec.red_mesh.services import framework_csf_scoring as csf
from extensions.business.cybersec.red_mesh.tenancy import compliance as c
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .test_framework_assessment import FrameworkAssessmentFixture

PACK='us.nist.csf-2.0'

class CsfLifecycleFixture(FrameworkAssessmentFixture):
  def create_status(self,country='US'):
    return self.ok(self.plugin.create_framework_assessment(self.admin,self.tenant,PACK,str(uuid4()),'CSF profile '+str(country),None,None,country))

  def save_status(self,aid,body,revision):
    return self.plugin.save_framework_assessment_draft(self.admin,self.tenant,PACK,body,revision,aid)

  def submit_status(self,aid,revision,request=None):
    return self.plugin.submit_framework_assessment(self.admin,self.tenant,PACK,revision,request or str(uuid4()),None,aid)

  def full_scores(self):
    return {x['ref_id']:{'included':True,'current_rating':1,'target_rating':5} for x in packs.load_framework_pack(PACK)['controls']}

  def full_tiers(self):
    return {f:{'current':1,'target':4} for f in csf.FUNCTIONS}

class TestCsfLifecycle(CsfLifecycleFixture):
  def test_worldwide_country_catalogue_and_legacy_scope(self):
    for country in ('US','RO','DE','GB','JP',None):
      self.assertEqual(c.resolve_country(PACK,country),country)
    for country in ('ZZ','us','USA',True,1):
      with self.assertRaises(ValueError):c.resolve_country(PACK,country)
    for pack,country in (('ro.dnsc.o1-2026','US'),('eu.ec.ir-2024-2690','GB')):
      with self.assertRaises(ValueError):c.resolve_country(pack,country)
    made=self.create_status();self.assertEqual(self.stored_row()['country'],'US')
    for country in ('RO','DE','GB','JP',None):
      made=self.create_status(country)
      self.assertEqual(self.ok(self.plugin.get_framework_assessment(self.admin,self.tenant,PACK,made['assessmentId']))['packId'],PACK)
    before=copy.deepcopy(self.storage.data)
    for country in ('ZZ','us','USA'):
      self.refused(self.plugin.create_framework_assessment(self.admin,self.tenant,PACK,str(uuid4()),'Invalid',None,None,country),400,'assessment_invalid')
      self.assertEqual(self.storage.data,before)
    listed=self.ok(self.plugin.list_framework_packs(self.admin,self.tenant))
    entry=next(p for p in listed['packs'] if p['packId']==PACK)
    self.assertEqual(entry['entries'][0]['jurisdiction'],'WORLDWIDE')
    self.assertEqual(entry['entries'][0]['legal_force'],'voluntary')
    self.assertEqual(entry['exports'],['json','csv','pdf'])
    self.assertFalse(entry['capabilities']['has_verdict'])

  def test_tier_replacement_null_digest_and_entry_replacement(self):
    made=self.create_status();aid=made['assessmentId'];before=c.intent_digest(self.stored_row())
    saved=self.ok(self.save_status(aid,{'function_tiers':self.full_tiers()},1))
    self.assertNotEqual(before,c.intent_digest(self.stored_row()))
    saved=self.ok(self.save_status(aid,{'function_tiers':{'GV':{'target':2}}},saved['assessmentRevision']))
    self.assertEqual(saved['function_tiers'],{'GV':{'current':None,'target':2}})
    ref=next(iter(self.full_scores()))
    saved=self.ok(self.save_status(aid,{'scores':{ref:{'included':False,'current_rating':1,'target_rating':5}}},saved['assessmentRevision']))
    self.assertEqual(saved['function_tiers'],{'GV':{'current':None,'target':2}})
    self.assertEqual(saved['scores'][ref]['target_rating'],5)
    self.assertEqual(saved['computed']['current_profile'],[])
    saved=self.ok(self.save_status(aid,{'scores':{ref:{'evidence_refs':['contract']}},'function_tiers':None},saved['assessmentRevision']))
    self.assertEqual(saved['function_tiers'],{})
    self.assertIsNone(saved['scores'][ref]['included'])
    self.assertIsNone(saved['scores'][ref]['current_rating'])

  def test_invalid_patches_refuse_without_writes_and_permissions(self):
    made=self.create_status();aid=made['assessmentId'];ref=next(iter(self.full_scores()))
    for body in ({'scores':{ref:{'rationale':'\ud800'}}},{'function_tiers':{'GV':{'target':True}}},
      {'function_tiers':{'XX':{}}},{'scores':{ref:{'current_rating':1.0}}},
      {'scores':{ref:{'included':True,'evidence_refs':['job:foreign:1']}}},{'scores':{'XX':{}}}):
      before=copy.deepcopy(self.storage.data)
      self.refused(self.save_status(aid,body,made['assessmentRevision']),400,'assessment_invalid')
      self.assertEqual(self.storage.data,before)
    result=self.plugin.save_framework_assessment_draft(self.viewer,self.tenant,PACK,{},1,aid)
    self.refused(result,403,'forbidden')
    legacy=packs.load_framework_pack('ro.dnsc.o1-2026')
    with self.assertRaises(ValueError):c.apply_patch(c.new_row('tenant',legacy,actor='actor',now='clock'),{'function_tiers':{}},legacy,actor='actor',now='clock')

  def test_stored_tiers_validation_and_readback_failure(self):
    made=self.create_status();aid=made['assessmentId'];row=copy.deepcopy(self.stored_row())
    adapter=CstoreComplianceStore(self.plugin,'deployment');ids=(self.tenant,PACK,aid)
    for value in (None,{'GV':{'target':1}},{'GV':{'current':True,'target':4}},{'XX':{}}):
      with self.assertRaisesRegex(TenantStoreError,'Invalid framework assessment storage record'):adapter.validate_record(dict(row,function_tiers=value),c.KIND,*ids)
    original_get=self.storage.chainstore_hget
    original_set=self.storage.chainstore_hset
    written=[]
    def write(hkey,key,value):
      result=original_set(hkey=hkey,key=key,value=value)
      if 'tenancy-compliance' in hkey:written.append(key)
      return result
    def read(hkey,key):
      if written and 'tenancy-compliance' in hkey:raise RuntimeError('readback failure')
      return original_get(hkey=hkey,key=key)
    with patch.object(self.plugin,'chainstore_hset',side_effect=write),patch.object(self.plugin,'chainstore_hget',side_effect=read):
      self.assertFalse(self.save_status(aid,{'function_tiers':self.full_tiers()},1)['success'])
    self.assertTrue(written)  # failure occurred after write, at the readback seam

  def test_submit_fallbacks_freeze_return_reopen(self):
    made=self.create_status();aid=made['assessmentId'];tiers=self.full_tiers()
    saved=self.ok(self.save_status(aid,{'scores':self.full_scores(),'function_tiers':tiers},1))
    self.assertEqual(saved['submitErrors'],[])
    self.documents.fail=True;request=str(uuid4())
    self.refused(self.submit_status(aid,saved['assessmentRevision'],request),503,'unavailable')
    row=self.stored_row();frozen=copy.deepcopy(row['pending']['historical_context'])
    self.refused(self.save_status(aid,{'function_tiers':None},row['assessment_revision']),409,'assessment_submit_pending')
    # Exercise both historical compute fallbacks, not just the cached computed branch.
    row['pending'].pop('computed');row['pending'].pop('verdict')
    self.documents.fail=False
    result=self.ok(self.submit_status(aid,saved['assessmentRevision'],request))
    snapshot=self.documents.envelopes['doc-1']['snapshot']
    self.assertEqual(snapshot['function_tiers'],tiers)
    self.assertEqual(snapshot['computed'],saved['computed'])
    self.assertEqual(snapshot['historical_context'],frozen)
    self.assertEqual(snapshot['country'],'US')
    self.assertEqual(snapshot['historical_context']['pack']['extras']['rating_label'],'RedMesh rating')
    self.assertEqual(len(self.stored_row()['submissions'][0]['verdict']),3)
    puts=len(self.documents.puts)
    self.ok(self.submit_status(aid,saved['assessmentRevision'],request))
    self.assertEqual(len(self.documents.puts),puts)
    review=self.ok(self.plugin.get_framework_assessment_review(self.creator,self.tenant,PACK,1,aid))
    self.ok(self.plugin.mutate_framework_assessment_review(self.creator,self.tenant,PACK,1,'return',review['review_revision'],str(uuid4()),None,None,aid))
    row=self.stored_row();self.assertEqual(row['function_tiers'],tiers)
    self.ok(self.submit_status(aid,row['assessment_revision']))
    row=self.stored_row()
    reopened=self.ok(self.plugin.reopen_framework_assessment(self.admin,self.tenant,PACK,row['assessment_revision'],str(uuid4()),aid))
    self.assertEqual(reopened['function_tiers'],tiers)
    # Original immutable revision remains unchanged after subsequent edits.
    self.ok(self.save_status(aid,{'function_tiers':None},reopened['assessmentRevision']))
    artifact=self.ok(self.plugin.get_framework_assessment_artifact(self.admin,self.tenant,PACK,1,aid))
    self.assertEqual(artifact['snapshot']['function_tiers'],tiers)
    self.assertEqual(artifact['snapshot']['computed']['scoring'],'csf_profile.v1')

  def test_archive_keeps_historical_profile(self):
    made=self.create_status();aid=made['assessmentId']
    saved=self.ok(self.save_status(aid,{'scores':self.full_scores(),'function_tiers':self.full_tiers()},1))
    self.ok(self.submit_status(aid,saved['assessmentRevision']))
    row=self.stored_row()
    self.ok(self.plugin.archive_framework_assessment(self.admin,self.tenant,PACK,aid,True,row['assessment_revision']))
    artifact=self.ok(self.plugin.get_framework_assessment_artifact(self.admin,self.tenant,PACK,1,aid))
    self.assertEqual(artifact['snapshot']['function_tiers'],self.full_tiers())
