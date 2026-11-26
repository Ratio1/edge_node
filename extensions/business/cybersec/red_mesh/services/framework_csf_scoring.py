"""User-authored CSF profiles: neutral ratings and independently chosen Function tiers."""
from ..references.framework_packs import FrameworkPackError, pack_levels
from .framework_entry_validation import AssessmentInvalid, bounded_text, normalize_evidence_refs

SCORING_ID = 'csf_profile.v1'
FUNCTIONS = ('GV', 'ID', 'PR', 'DE', 'RS', 'RC')
FUNCTION_COUNTS = (31, 21, 22, 11, 13, 8)
TIER_LABELS = ('Partial', 'Risk Informed', 'Repeatable', 'Adaptive')
CAPS = {'rationale': 500, 'evidence_refs': 5}
_ENTRY_KEYS = frozenset(('included', 'rationale', 'current_rating', 'target_rating',
                         'evidence_refs', 'updated_by', 'updated_at'))


def _number(value, maximum):
  if value is not None and (type(value) is not int or not 1 <= value <= maximum):
    raise AssessmentInvalid('invalid_score_value')
  return value


def normalize_tiers(value):
  if value is None:
    return {}
  if not isinstance(value, dict) or set(value) - set(FUNCTIONS):
    raise AssessmentInvalid('invalid_function_tiers')
  result = {}
  for fid in FUNCTIONS:
    if fid not in value:
      continue
    tiers = value[fid]
    if not isinstance(tiers, dict) or set(tiers) - {'current', 'target'}:
      raise AssessmentInvalid('invalid_function_tiers')
    result[fid] = {key: _number(tiers.get(key), 4) for key in ('current', 'target')}
  return result


def check_pack(pack, text):
  controls = pack['controls']
  ids = [c['ref_id'] for c in controls]
  if (pack_levels(pack) or len(ids) != 106 or len(set(ids)) != 106
      or [c['order'] for c in controls] != list(range(1,107))
      or tuple(sum(c.get('category') == f for c in controls) for f in FUNCTIONS) != FUNCTION_COUNTS
      or any(not c['ref_id'].startswith(c.get('subcategory', '') + '-')
             or not c.get('subcategory', '').startswith(c.get('category', '') + '.') for c in controls)
      or pack.get('counts', {}).get('controls') != 106):
    raise FrameworkPackError('invalid CSF Core hierarchy/counts')
  if text is not None:
    hierarchy = text.get('hierarchy', [])
    parents = {n['id']:n.get('parent') for n in hierarchy}
    if (list(text['controls']) != ids or len(hierarchy) != 28
        or [n['id'] for n in hierarchy if n.get('parent') is None] != list(FUNCTIONS)
        or any(parents.get(c['subcategory']) != c['category'] for c in controls)
        or sum(len(t.get('implementation_examples', [])) for t in text['controls'].values()) != 363
        or any(not isinstance(t.get('requirement'), str) or not t['requirement'] for t in text['controls'].values())):
      raise FrameworkPackError('invalid CSF text hierarchy/coverage')


def _entry(entry, *, actor, now):
  if not isinstance(entry, dict) or set(entry) - _ENTRY_KEYS:
    raise AssessmentInvalid('invalid_score_value')
  included = entry.get('included')
  if included is not None and type(included) is not bool:
    raise AssessmentInvalid('invalid_score_value')
  rationale = bounded_text(entry.get('rationale'), CAPS['rationale'])
  try:
    rationale.encode('utf-8')
  except UnicodeEncodeError:
    raise AssessmentInvalid('invalid_request') from None
  return {'included': included, 'rationale': rationale,
          'current_rating': _number(entry.get('current_rating'),5),
          'target_rating': _number(entry.get('target_rating'),5),
          'evidence_refs': normalize_evidence_refs(entry.get('evidence_refs')),
          'updated_by': actor, 'updated_at': now}


def normalise_patch(pack, rules, scores, *, actor, now):
  result = {}
  for ref, entry in scores.items():
    try:
      result[ref] = None if entry is None else _entry(entry, actor=actor, now=now)
    except AssessmentInvalid as exc:
      raise AssessmentInvalid(exc.code, [ref], **exc.extra) from None
  return result


def validate_stored_entry(pack, ref_id, entry):
  try:
    if (ref_id not in {c['ref_id'] for c in pack['controls']} or not isinstance(entry,dict)
        or set(entry) != _ENTRY_KEYS or not all(isinstance(entry[k],str) for k in ('updated_by','updated_at'))
        or _entry(entry,actor=entry['updated_by'],now=entry['updated_at']) != entry):
      raise AssessmentInvalid('invalid_stored_entry')
  except (AssessmentInvalid, TypeError, ValueError):
    return [{'code':'invalid_stored_entry','ids':[ref_id]}]
  return []


def compute(pack, level, scores, *, context=None):
  if context is not None and (not isinstance(context,dict) or set(context) - {'function_tiers'}):
    raise AssessmentInvalid('invalid_function_tiers')
  tiers = normalize_tiers((context or {}).get('function_tiers'))
  current, target, gaps, missing = [], [], [], []
  counts = dict(included=0, excluded=0, unanswered=0, gaps=0)
  for control in pack['controls']:
    ref = control['ref_id']
    entry = scores.get(ref) or {}
    included = entry.get('included')
    counts['unanswered' if included is None else 'included' if included else 'excluded'] += 1
    fields = ['included'] if included is None else []
    if included is True:
      for key, profile in (('current_rating',current),('target_rating',target)):
        if entry.get(key) is None:
          fields.append(key)
        else:
          profile.append({'ref_id':ref,'rating':entry[key]})
      a,b = entry.get('current_rating'),entry.get('target_rating')
      if a is not None and b is not None and b > a:
        gaps.append({'ref_id':ref,'current_rating':a,'target_rating':b,'gap':b-a})
    elif included is False and not entry.get('rationale'):
      fields.append('rationale')
    if fields:
      missing.append({'ref_id':ref,'fields':fields})
  counts['gaps'] = len(gaps)
  comparisons = [{'function_id':f, **tiers[f], 'gap':tiers[f]['target']-tiers[f]['current']}
                 for f in FUNCTIONS if f in tiers and all(tiers[f][k] is not None for k in ('current','target'))]
  return {'scoring':SCORING_ID,'current_profile':current,'target_profile':target,'gaps':gaps,
          'missing_answers':missing,'missing_target_tiers':[f for f in FUNCTIONS if tiers.get(f,{}).get('target') is None],
          'tier_comparisons':comparisons,'counts':counts,'verdict':{'passed':None}}


def validate_for_submit(pack, rules, level, draft):
  scores = draft.get('scores') or {}
  errors = [e for ref,entry in scores.items() for e in validate_stored_entry(pack,ref,entry)]
  if level is not None:
    errors.append({'code':'unknown_level','level':level})
  try:
    tiers = normalize_tiers(draft.get('function_tiers'))
  except AssessmentInvalid as exc:
    return [*errors,exc.as_error()],None
  if errors:
    return errors,None
  result = compute(pack,level,scores,context={'function_tiers':tiers})
  for missing in result['missing_answers']:
    for field in missing['fields']:
      errors.append({'code':'exclusion_justification_missing' if field=='rationale' else 'unscored',
                     'ids':[missing['ref_id']],'field':field})
  if result['missing_target_tiers']:
    errors.append({'code':'function_tiers_missing','ids':result['missing_target_tiers']})
  return errors,result


def entry_schema(pack):
  return {'fields':['included','rationale','current_rating','target_rating','evidence_refs'],
          'rating_values':[1,2,3,4,5],'rating_label':'RedMesh rating','caps':dict(CAPS)}


def verdict_summary(computed):
  return {'scoring':SCORING_ID,'passed':None,'counts':dict(computed['counts'])}


def pack_view_extras(pack, text):
  return {'rating_label':'RedMesh rating','functions':list(FUNCTIONS),
          'tiers':[{'value':i,'label':label} for i,label in enumerate(TIER_LABELS,1)],
          'tier_source':'https://doi.org/10.6028/NIST.CSWP.29, final Appendix B'}


def capabilities():
  return {'has_levels':False,'has_verdict':False,'has_remediation':False,'axes':[]}
