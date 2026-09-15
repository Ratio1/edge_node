"""RM-026 C1b: launcher heartbeat and ownership projection.

Ownership is *derived*, not stored as a new counter. The job record already names the controlling
node (`launcher`) and the execution binding already carries the immutable `participant_order` that
D1's takeover arithmetic walks. What was missing is liveness -- when ownership was taken, and when
the owner was last alive -- which C1a put in the `:live:launcher` hset.

The C1 architecture gate rejected an `ownership_revision` explicitly: `_write_job_record` fences on
`job_revision`, 38 of 40 call sites pass `expected_revision=None`, and a second counter would vanish
at finalization because `CStoreJobFinalized` carries no revision field.
"""
from ..constants import JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED
from ..models import LauncherLiveness, launcher_liveness_state

# A job in one of these states is finished; ownership liveness is not a question about it.
TERMINAL_JOB_STATUSES = (JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED)
from ..repositories import JobStateRepository


def _repo(owner):
  return JobStateRepository(owner)


def publish_launcher_liveness(owner, job_id, job_specs):
  """Publish this node's heartbeat for a job it controls.

  Refuses to publish for a job it does not control: a heartbeat is a claim to be the current
  controller, and one written by a bystander would make that bystander look like the owner to C2's
  loss detection and D1's takeover.

  `launcher_since` is set once per tenure and never refreshed, because it answers "when did this
  node take ownership" -- D1 measures its deadline from it, and refreshing it every 30 seconds would
  make an owner of one hour indistinguishable from one of thirty seconds.
  """
  if not isinstance(job_specs, dict):
    return None
  launcher = job_specs.get("launcher")
  ee_addr = getattr(owner, "ee_addr", None)
  if not isinstance(launcher, str) or not launcher.strip() or launcher != ee_addr:
    return None
  if not isinstance(job_id, str) or not job_id.strip():
    return None

  repo = _repo(owner)
  now = float(owner.time())
  previous = repo.get_launcher_liveness_model(job_id)
  # A successor is not a continuation of its predecessor's tenure.
  since = previous.launcher_since if previous is not None and previous.launcher == launcher else now
  row = LauncherLiveness(job_id=job_id, launcher=launcher, launcher_since=since, last_seen_at=now)
  repo.put_launcher_liveness(job_id, row.to_dict())
  return row


def project_ownership(owner, job_specs, *, loss_after):
  """Project who controls a job, since when, and whether they are still alive.

  Returns `participant_order` as None rather than [] for a legacy unbound job: an empty order reads
  as "no candidates", which D1 treats as a decision, while None says the question cannot be answered
  from this record.

  A liveness row naming a different launcher than the job record is `unresolved`, not `live`. It is
  a disagreement between two sources, and resolving it in favour of either would be an invention --
  the same rule the plan applies to a future timestamp.
  """
  if not isinstance(job_specs, dict):
    return {"launcher": None, "launcher_since": None, "liveness": "unavailable",
            "participant_order": None}
  launcher = job_specs.get("launcher")
  binding = job_specs.get("execution_binding")
  order = None
  if isinstance(binding, dict):
    candidates = binding.get("participant_order")
    if isinstance(candidates, list) and all(isinstance(node, str) for node in candidates):
      order = list(candidates)

  # A terminal job has no controller to be alive. The heartbeat stops refreshing at finalization but
  # nothing deletes the row until purge, so without this the projection reads `lost` once the last
  # heartbeat ages out -- the signal D1 acts on to take over a job that ended normally.
  if job_specs.get("job_status") in TERMINAL_JOB_STATUSES:
    return {"launcher": launcher, "launcher_since": None, "liveness": "terminal",
            "participant_order": order}

  job_id = job_specs.get("job_id")
  row = _repo(owner).get_launcher_liveness_model(job_id) if isinstance(job_id, str) else None
  if row is not None and row.launcher != launcher:
    liveness = "unresolved"
    since = None
  else:
    liveness = launcher_liveness_state(row, now=float(owner.time()), loss_after=loss_after)
    since = row.launcher_since if row is not None else None
  return {"launcher": launcher, "launcher_since": since, "liveness": liveness,
          "participant_order": order}
