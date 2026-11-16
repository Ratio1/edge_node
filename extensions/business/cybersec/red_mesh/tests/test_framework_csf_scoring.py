"""Hand-derived CSF profile expectations, independent of computation implementation."""
import copy
import json
from pathlib import Path
import unittest
from ..references.framework_packs import load_framework_pack, load_framework_text
from ..services import framework_csf_scoring as csf
from ..services.framework_entry_validation import AssessmentInvalid

PACK='us.nist.csf-2.0'

class TestCsfScoring(unittest.TestCase):
  def setUp(self):
    self.pack=load_framework_pack(PACK)
    self.refs=[c['ref_id'] for c in self.pack['controls']]

  def normalize(self,scores):
    return csf.normalise_patch(self.pack,{},scores,actor='actor',now='clock')

  def test_empty_exact_golden(self):
    expected={'scoring':'csf_profile.v1','current_profile':[],'target_profile':[],'gaps':[],
      'missing_answers':[{'ref_id':r,'fields':['included']} for r in self.refs],
      'missing_target_tiers':['GV','ID','PR','DE','RS','RC'],'tier_comparisons':[],
      'counts':{'included':0,'excluded':0,'unanswered':106,'gaps':0},'verdict':{'passed':None}}
    self.assertEqual(csf.compute(self.pack,None,{}),expected)

  def test_mixed_exact_golden_and_excluded_retention(self):
    refs=self.refs[:4]
    scores=self.normalize({refs[0]:{'included':True,'current_rating':1,'target_rating':5},
      refs[1]:{'included':True,'current_rating':3,'target_rating':3},
      refs[2]:{'included':True,'current_rating':5,'target_rating':1},
      refs[3]:{'included':False,'current_rating':1,'target_rating':5}})
    result=csf.compute(self.pack,None,scores,context={'function_tiers':{'GV':{'current':4,'target':1}}})
    self.assertEqual(result['current_profile'],[{'ref_id':r,'rating':v} for r,v in zip(refs,[1,3,5])])
    self.assertEqual(result['target_profile'],[{'ref_id':r,'rating':v} for r,v in zip(refs,[5,3,1])])
    self.assertEqual(result['gaps'],[{'ref_id':refs[0],'current_rating':1,'target_rating':5,'gap':4}])
    self.assertEqual(result['tier_comparisons'],[{'function_id':'GV','current':4,'target':1,'gap':-3}])
    self.assertEqual(result['counts'],dict(included=3,excluded=1,unanswered=102,gaps=1))
    self.assertEqual(scores[refs[3]]['target_rating'],5)
    self.assertEqual(csf.verdict_summary(result),{'scoring':'csf_profile.v1','passed':None,'counts':result['counts']})

  def test_complete_and_optional_current_tiers(self):
    scores=self.normalize({r:{'included':True,'current_rating':1,'target_rating':1} for r in self.refs})
    draft={'scores':scores,'function_tiers':{f:{'current':None,'target':4} for f in csf.FUNCTIONS}}
    errors,computed=csf.validate_for_submit(self.pack,{},None,draft)
    self.assertEqual(errors,[]);self.assertEqual(computed['gaps'],[])
    self.assertEqual(computed['tier_comparisons'],[])
    self.assertEqual(len(computed['current_profile']),106)
    draft['scores'][self.refs[0]]=self.normalize({self.refs[0]:{'included':False}})[self.refs[0]]
    self.assertIn('exclusion_justification_missing',[e['code'] for e in csf.validate_for_submit(self.pack,{},None,draft)[0]])

  def test_invalid_inputs_and_stored_canonical(self):
    for key,values in {'included':[0,1,'true'], 'current_rating':[True,1.0,0,6,'1'],
                       'target_rating':[False,-1,6], 'rationale':['x'*501,'\ud800'], 'status':['partial']}.items():
      for value in values:
        with self.subTest(key=key,value=repr(value)),self.assertRaises(AssessmentInvalid):
          self.normalize({self.refs[0]:{key:value}})
    good=self.normalize({self.refs[0]:{}})[self.refs[0]]
    self.assertEqual(csf.validate_stored_entry(self.pack,self.refs[0],good),[])
    for bad in ({},dict(good,rationale=' padded '),dict(good,extra=1),dict(good,evidence_refs=['contract'])):
      self.assertTrue(csf.validate_stored_entry(self.pack,self.refs[0],bad))
    for bad in ({'XX':{}},{'GV':{'target':True}},{'GV':{'target':1.0}}, {'GV':{'current':5}}, {'GV':None}):
      with self.assertRaises(AssessmentInvalid):csf.normalize_tiers(bad)
    self.assertEqual(csf.normalize_tiers(None),{})
    self.assertEqual(csf.normalize_tiers({'GV':{'target':1}}),{'GV':{'current':None,'target':1}})

  def test_full_pack_text_hierarchy(self):
    text=load_framework_text(PACK);csf.check_pack(self.pack,text)
    for key in ('controls','hierarchy'):
      bad=copy.deepcopy(text)
      if key=='controls':bad[key].pop(self.refs[0])
      else:bad[key][0]['id']='wrong'
      with self.assertRaises(ValueError):csf.check_pack(self.pack,bad)

  def test_independent_fixture_goldens(self):
    fixture=json.loads((Path(__file__).parent/'fixtures/framework_csf_goldens.json').read_text())
    for case in fixture['cases']:
      with self.subTest(case=case['name']):
        result=csf.compute(self.pack,None,self.normalize(case['scores']))
        for key in ('current_profile','target_profile','gaps','counts'):
          self.assertEqual(result[key],case[key])
        if 'missing_first' in case:
          self.assertEqual(result['missing_answers'][0],case['missing_first'])
        self.assertEqual(result['verdict'],{'passed':None})

  def test_existing_scorers_ignore_context_with_identical_results(self):
    from ..services.framework_scoring import scorer_for
    for pid,level in (('ro.dnsc.o1-2026','basic'),('eu.ec.ir-2024-2690',None)):
      pack=load_framework_pack(pid);scorer=scorer_for(pack)
      self.assertEqual(scorer.compute(pack,level,{}),scorer.compute(pack,level,{},context={'function_tiers':{'GV':{'current':1,'target':4}}}))
    with self.assertRaises(AssessmentInvalid):
      csf.compute(self.pack,None,{},context={'unknown':'ignored?'})
