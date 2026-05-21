import json
import os
import random
import shutil
import statistics
import tempfile
import time
import unittest

from pathlib import Path


RUN_PROFILE_TESTS = os.getenv("EE_RUN_HF_PROFILE_TESTS") == "1"


DEFAULT_PROFILE_TEXTS = [
  "Short status: all clear.",
  "Please classify this short customer support message about a delayed shipment.",
  "The robot cell stopped after station 3 reported a missing safety acknowledgement at 06:41 UTC.",
  (
    "A technician reports intermittent failures in the packaging line. "
    "The PLC shows normal voltage, but the camera trigger sometimes arrives "
    "late and causes the downstream reject gate to miss the product window."
  ),
  (
    "Contact john.doe@example.com about order RF-2026-05-11. "
    "The payload includes an address, a phone number, and an internal ticket id."
  ),
  (
    "We need a concise operational summary for a factory shift handoff. "
    "Include the machine status, recent alerts, inferred severity, and whether "
    "the next operator should escalate to maintenance before restarting."
  ),
  (
    "Long diagnostic note: the API gateway accepted a request from the local "
    "RobotFactory client, forwarded it to the text classifier, then waited for "
    "the asynchronous result. During that interval the conveyor supervisor "
    "published two state changes, one warning, and one final recovery message."
  ),
  (
    "Privacy review text with mixed content: Maria Ionescu, phone +40 721 123 456, "
    "email maria.ionescu@example.org, visited the Bucharest site on 2026-05-11 "
    "and reported that badge number BC-4421 failed twice at the entrance."
  ),
  (
    "Factory note: camera CAM-07 saw three rejected parts after the gripper changed "
    "speed from 70 percent to 92 percent during the night shift."
  ),
  (
    "Billing escalation for Acme Robotics: invoice INV-2026-0512 was disputed by "
    "accounts-payable@example.net after the VAT identifier changed."
  ),
  (
    "Health and safety report: worker badge BC-4421 entered Zone C at 2026-05-11 "
    "09:32, then left before the evacuation drill started."
  ),
  (
    "Plain operational prose with no obvious private entities. The scheduler queued "
    "five maintenance jobs and left two optional inspections for tomorrow."
  ),
  (
    "Longer diagnostic paragraph: the API gateway accepted a request, submitted it "
    "to the privacy filter, polled for completion, and returned a redacted response "
    "after the downstream inference service completed its model call."
  ),
  (
    "Mixed identifier sample: user alex.smith@example.org, phone 555-0188, customer "
    "ID CUST-88019, device serial RF-AX-0091, and address 24 Industrial Way."
  ),
  (
    "Legal-style note: the contractor named Jordan Blake signed amendment A-17 on "
    "May 9, 2026, but requested that their home address remain confidential."
  ),
  (
    "Small multilingual-looking ASCII text: Ana Popescu said bonjour to Carlos "
    "before sending order number FR-2026-771 to logistics."
  ),
  (
    "Stack trace excerpt: ValueError at worker.py line 184 while handling request "
    "req_01HX9, no email address or person name is expected in this text."
  ),
  (
    "Customer support message: Priya asked support to call +1 415 555 0134 after "
    "her access token expired during login from office IP 203.0.113.42."
  ),
  "Very short PII sample: Sam, 555-0101.",
  (
    "A medium privacy-heavy example lists Jane Roe, employee E-3812, jane.roe@corp.example, "
    "passport P1234567, and a meeting room booking for Floor 14."
  ),
  (
    "A longer privacy-heavy example mentions Michael Turner, phone +49 30 1234 5678, "
    "email michael.turner@example.de, bank reference DE89 3704 0044 0532 0130 00, "
    "and shipment route Berlin to Cluj for audit review."
  ),
  (
    "A long non-private factory narrative describes conveyor speeds, motor current, "
    "temperature drift, retry counters, watchdog resets, operator acknowledgements, "
    "and a planned calibration window with no customer or employee identifiers."
  ),
]


def _env_int(name, default):
  value = os.getenv(name)
  if value is None:
    return default
  return int(value)


def _env_float(name, default=None):
  value = os.getenv(name)
  if value is None or value == "":
    return default
  return float(value)


def _env_bool(name, default=False):
  value = os.getenv(name)
  if value is None:
    return default
  return value.strip().lower() in {"1", "true", "yes", "on"}


def _latency_summary_ms(latencies):
  ordered = sorted(latencies)
  p95_index = min(len(ordered) - 1, int(len(ordered) * 0.95))
  return {
    "runs": len(latencies),
    "mean_ms": statistics.fmean(latencies) * 1000.0,
    "median_ms": statistics.median(latencies) * 1000.0,
    "p95_ms": ordered[p95_index] * 1000.0,
    "min_ms": ordered[0] * 1000.0,
    "max_ms": ordered[-1] * 1000.0,
  }


def _print_profile_summary(label, load_seconds, stage_latencies, input_count=None, seed=None):
  input_info = ""
  if input_count is not None:
    input_info = f" inputs={input_count}"
  if seed is not None:
    input_info = f"{input_info} seed={seed}"
  print(f"{label} profile: load={load_seconds:.3f}s{input_info}")

  summaries = {}
  for stage_name, latencies in stage_latencies.items():
    if not latencies:
      continue
    summary = _latency_summary_ms(latencies)
    summaries[stage_name] = summary
    print(
      "  {}: runs={} mean={:.3f}ms median={:.3f}ms p95={:.3f}ms min={:.3f}ms max={:.3f}ms".format(
        stage_name,
        summary["runs"],
        summary["mean_ms"],
        summary["median_ms"],
        summary["p95_ms"],
        summary["min_ms"],
        summary["max_ms"],
      )
    )
  return summaries


def _comma_list_env(name, default):
  value = os.getenv(name)
  if value is None:
    return list(default)
  return [item.strip() for item in value.split(",") if item.strip()]


def _split_text_env(value):
  if not value:
    return []
  return [item.strip() for item in value.split("|||") if item.strip()]


def _profile_texts_from_env():
  text_file = os.getenv("EE_HF_PROFILE_TEXT_FILE")
  if text_file:
    return [
      line.strip()
      for line in Path(text_file).read_text(encoding="utf-8").splitlines()
      if line.strip()
    ]
  texts = _split_text_env(os.getenv("EE_HF_PROFILE_TEXTS"))
  if texts:
    return texts
  text = os.getenv("EE_HF_PROFILE_TEXT")
  if text:
    return [text]
  return list(DEFAULT_PROFILE_TEXTS)


def _build_profile_input_sequence(runs, seed):
  texts = _profile_texts_from_env()
  if not texts:
    raise ValueError("At least one profiling text must be configured.")
  allow_repeats = _env_bool("EE_HF_PROFILE_ALLOW_REPEATS", default=False)
  if not allow_repeats and runs > len(texts):
    raise ValueError(
      f"EE_HF_PROFILE_RUNS={runs} requires {runs} unique texts, but only "
      f"{len(texts)} are available. Provide EE_HF_PROFILE_TEXTS, "
      "EE_HF_PROFILE_TEXT_FILE, or set EE_HF_PROFILE_ALLOW_REPEATS=1."
    )
  if allow_repeats:
    repeats = (runs + len(texts) - 1) // len(texts)
    sequence = (texts * repeats)[:runs]
  else:
    sequence = list(texts)
  random.Random(seed).shuffle(sequence)
  return sequence[:runs]


def _warmup_texts_from_env(default_sequence, warmup_runs):
  warmup_texts = _split_text_env(os.getenv("EE_HF_PROFILE_WARMUP_TEXTS"))
  if warmup_texts:
    return warmup_texts
  if warmup_runs <= 0:
    return []
  return default_sequence[:warmup_runs] or default_sequence[:1]


def _onnx_allow_patterns(model_file):
  model_path = Path(model_file)
  model_dir = model_path.parent.as_posix()
  model_name = model_path.name
  sidecar_prefix = f"{model_file}_data"
  if model_dir == ".":
    sidecar_prefix = f"{model_name}_data"
  return _comma_list_env(
    "EE_HF_PROFILE_ONNX_ALLOW_PATTERNS",
    [
      model_file,
      f"{sidecar_prefix}*",
      "config.json",
      "tokenizer.json",
      "tokenizer_config.json",
      "special_tokens_map.json",
      "vocab.txt",
      "merges.txt",
      "sentencepiece.bpe.model",
      "spiece.model",
      "viterbi_calibration.json",
    ],
  )


def _copy_or_link(source, destination):
  destination.parent.mkdir(parents=True, exist_ok=True)
  source = source.resolve()
  if destination.exists():
    return
  try:
    os.link(source, destination)
  except OSError:
    shutil.copy2(source, destination)
  return


def _materialize_onnx_for_runtime(snapshot_dir, model_file, tmpdir):
  snapshot_dir = Path(snapshot_dir)
  source_model = snapshot_dir / model_file
  materialized_root = Path(tmpdir) / "materialized_onnx"
  materialized_model = materialized_root / model_file
  _copy_or_link(source_model, materialized_model)

  sidecar_globs = [
    f"{source_model.name}_data*",
    f"{source_model.name}.data*",
  ]
  for sidecar_glob in sidecar_globs:
    for sidecar in source_model.parent.glob(sidecar_glob):
      if sidecar.is_file() or sidecar.is_symlink():
        relative_sidecar = sidecar.relative_to(snapshot_dir)
        _copy_or_link(sidecar, materialized_root / relative_sidecar)
  return str(materialized_model)


def _session_inputs(session, encoded):
  inputs = {}
  encoded_items = dict(encoded.items()) if hasattr(encoded, "items") else dict(encoded)
  for input_meta in session.get_inputs():
    input_name = input_meta.name
    if input_name not in encoded_items:
      continue
    value = encoded_items[input_name]
    input_type = getattr(input_meta, "type", "")
    if "int64" in input_type and hasattr(value, "astype"):
      value = value.astype("int64")
    elif "int32" in input_type and hasattr(value, "astype"):
      value = value.astype("int32")
    inputs[input_name] = value
  if inputs:
    return inputs
  return encoded_items


def _resolve_decoder_kind(model_name):
  decoder_kind = os.getenv("EE_HF_PROFILE_ONNX_DECODER", "auto").strip().lower()
  if decoder_kind in {"", "none", "null", "off", "false", "0"}:
    return None
  if decoder_kind == "auto":
    if model_name == "openai/privacy-filter":
      return "privacy_filter"
    return None
  return decoder_kind


def _build_privacy_filter_decoder(snapshot_dir):
  from extensions.serving.default_inference.nlp.th_privacy_filter import ThPrivacyFilter

  snapshot_dir = Path(snapshot_dir)
  config = json.loads((snapshot_dir / "config.json").read_text(encoding="utf-8"))
  calibration_path = snapshot_dir / "viterbi_calibration.json"
  calibration = {}
  if calibration_path.exists():
    calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
  schema = {
    "id2label": config.get("id2label", {}),
    "viterbi_calibration": calibration,
  }
  decoder_owner = object.__new__(ThPrivacyFilter)

  def decode(outputs_by_name, text, encoded):
    return decoder_owner._decode_privacy_filter_onnx_outputs(
      outputs_by_name,
      schema,
      text=text,
      tokenizer_output=encoded,
    )

  return decode


def _build_onnx_decoder(model_name, snapshot_dir):
  decoder_kind = _resolve_decoder_kind(model_name=model_name)
  if decoder_kind is None:
    return None
  if decoder_kind == "privacy_filter":
    return _build_privacy_filter_decoder(snapshot_dir=snapshot_dir)
  raise ValueError(f"Unsupported EE_HF_PROFILE_ONNX_DECODER={decoder_kind!r}.")


def _run_onnx_once(tokenizer, session, output_names, tokenize_kwargs, text, decoder=None):
  total_started = time.perf_counter()

  started = time.perf_counter()
  encoded = tokenizer(text, **tokenize_kwargs)
  tokenize_seconds = time.perf_counter() - started

  started = time.perf_counter()
  inputs = _session_inputs(session=session, encoded=encoded)
  prepare_seconds = time.perf_counter() - started

  started = time.perf_counter()
  raw_outputs = session.run(output_names, inputs)
  session_seconds = time.perf_counter() - started

  started = time.perf_counter()
  outputs_by_name = {
    output_name: output_value
    for output_name, output_value in zip(output_names, raw_outputs)
  }
  if decoder is None:
    decoded = outputs_by_name
  else:
    decoded = decoder(outputs_by_name=outputs_by_name, text=text, encoded=encoded)
  decode_seconds = time.perf_counter() - started

  return {
    "decoded": decoded,
    "total": time.perf_counter() - total_started,
    "tokenize": tokenize_seconds,
    "prepare_inputs": prepare_seconds,
    "session_run": session_seconds,
    "decode": decode_seconds,
  }


@unittest.skipUnless(
  RUN_PROFILE_TESTS,
  "Set EE_RUN_HF_PROFILE_TESTS=1 to run real HF runtime profiling tests.",
)
class ThHfRuntimeProfileTests(unittest.TestCase):
  """Opt-in profiling checks for real Transformers/PyTorch and ONNX Runtime paths."""

  def setUp(self):
    self.runs = _env_int("EE_HF_PROFILE_RUNS", 10)
    self.warmup_runs = _env_int("EE_HF_PROFILE_WARMUP_RUNS", 2)
    self.seed = _env_int("EE_HF_PROFILE_SHUFFLE_SEED", 12345)
    if self.runs <= 0:
      raise ValueError("EE_HF_PROFILE_RUNS must be greater than 0.")
    if self.warmup_runs < 0:
      raise ValueError("EE_HF_PROFILE_WARMUP_RUNS must not be negative.")
    self.profile_texts = _build_profile_input_sequence(runs=self.runs, seed=self.seed)
    self.warmup_texts = _warmup_texts_from_env(
      default_sequence=self.profile_texts,
      warmup_runs=self.warmup_runs,
    )
    return

  def _assert_optional_threshold(self, label, summary, env_name):
    threshold_ms = _env_float(env_name)
    if threshold_ms is not None:
      self.assertLessEqual(
        summary["mean_ms"],
        threshold_ms,
        f"{label} mean latency exceeded {env_name}={threshold_ms}ms",
      )
    return

  def test_profile_transformers_torch_pipeline(self):
    model_name = os.getenv("EE_HF_PROFILE_TORCH_MODEL_NAME")
    if not model_name:
      self.skipTest("Set EE_HF_PROFILE_TORCH_MODEL_NAME to profile the PyTorch/Transformers runtime.")

    try:
      from transformers import pipeline
    except ImportError as exc:
      self.skipTest(f"transformers is not installed: {exc}")

    task = os.getenv("EE_HF_PROFILE_TORCH_TASK")
    if task is None and model_name == "openai/privacy-filter":
      task = "token-classification"
    if task is None:
      task = "text-classification"
    if task.strip().lower() in {"", "none", "null"}:
      task = None
    device = _env_int("EE_HF_PROFILE_TORCH_DEVICE", -1)
    trust_remote_code = os.getenv("EE_HF_PROFILE_TORCH_TRUST_REMOTE_CODE") == "1"

    load_started = time.perf_counter()
    classifier = pipeline(
      task=task,
      model=model_name,
      tokenizer=os.getenv("EE_HF_PROFILE_TORCH_TOKENIZER_NAME") or model_name,
      device=device,
      trust_remote_code=trust_remote_code,
      token=os.getenv("EE_HF_TOKEN") or os.getenv("HF_TOKEN"),
    )
    if getattr(classifier, "framework", None) is None:
      classifier.framework = "pt"
    load_seconds = time.perf_counter() - load_started

    for warmup_text in self.warmup_texts:
      classifier(warmup_text)

    stage_latencies = {"pipeline_total": []}
    result = None
    for text in self.profile_texts:
      started = time.perf_counter()
      result = classifier(text)
      stage_latencies["pipeline_total"].append(time.perf_counter() - started)

    self.assertIsNotNone(result)
    summaries = _print_profile_summary(
      "torch",
      load_seconds,
      stage_latencies,
      input_count=len(set(self.profile_texts)),
      seed=self.seed,
    )
    self._assert_optional_threshold(
      label="torch.pipeline_total",
      summary=summaries["pipeline_total"],
      env_name="EE_HF_PROFILE_TORCH_MAX_MEAN_MS",
    )
    return

  def test_profile_onnx_runtime_pipeline(self):
    model_name = os.getenv("EE_HF_PROFILE_ONNX_MODEL_NAME")
    if not model_name:
      self.skipTest("Set EE_HF_PROFILE_ONNX_MODEL_NAME to profile the ONNX Runtime path.")

    try:
      import onnxruntime as ort
      from huggingface_hub import snapshot_download
      from transformers import AutoTokenizer
    except ImportError as exc:
      self.skipTest(f"ONNX profiling dependencies are not installed: {exc}")

    model_file = os.getenv("EE_HF_PROFILE_ONNX_MODEL_FILE", "onnx/model.onnx")
    trust_remote_code = os.getenv("EE_HF_PROFILE_ONNX_TRUST_REMOTE_CODE") == "1"
    providers = _comma_list_env(
      "EE_HF_PROFILE_ONNX_PROVIDERS",
      ["CPUExecutionProvider"],
    )

    with tempfile.TemporaryDirectory(prefix="hf_onnx_profile_") as tmpdir:
      snapshot_dir = snapshot_download(
        repo_id=model_name,
        revision=os.getenv("EE_HF_PROFILE_ONNX_REVISION") or None,
        token=os.getenv("EE_HF_TOKEN") or os.getenv("HF_TOKEN"),
        cache_dir=os.getenv("EE_HF_PROFILE_CACHE_DIR") or None,
        allow_patterns=_onnx_allow_patterns(model_file=model_file),
        repo_type="model",
      )
      materialized_model = _materialize_onnx_for_runtime(
        snapshot_dir=snapshot_dir,
        model_file=model_file,
        tmpdir=tmpdir,
      )

      load_started = time.perf_counter()
      tokenizer = AutoTokenizer.from_pretrained(
        snapshot_dir,
        trust_remote_code=trust_remote_code,
      )
      session = ort.InferenceSession(materialized_model, providers=providers)
      decoder = _build_onnx_decoder(model_name=model_name, snapshot_dir=snapshot_dir)
      load_seconds = time.perf_counter() - load_started

      tokenize_kwargs = {
        "return_tensors": "np",
        "truncation": True,
      }
      if decoder is not None:
        tokenize_kwargs["return_offsets_mapping"] = True
      max_length = os.getenv("EE_HF_PROFILE_ONNX_MAX_LENGTH")
      if max_length:
        tokenize_kwargs["max_length"] = int(max_length)
      output_names = [output.name for output in session.get_outputs()]

      for warmup_text in self.warmup_texts:
        _run_onnx_once(
          tokenizer=tokenizer,
          session=session,
          output_names=output_names,
          tokenize_kwargs=tokenize_kwargs,
          text=warmup_text,
          decoder=decoder,
        )

      stage_latencies = {
        "pipeline_total": [],
        "tokenize": [],
        "prepare_inputs": [],
        "session_run": [],
        "decode": [],
      }
      result = None
      for text in self.profile_texts:
        result = _run_onnx_once(
          tokenizer=tokenizer,
          session=session,
          output_names=output_names,
          tokenize_kwargs=tokenize_kwargs,
          text=text,
          decoder=decoder,
        )
        for stage_name in stage_latencies:
          stage_latencies[stage_name].append(result[stage_name])

    self.assertIsNotNone(result)
    self.assertIsNotNone(result["decoded"])
    summaries = _print_profile_summary(
      "onnx",
      load_seconds,
      stage_latencies,
      input_count=len(set(self.profile_texts)),
      seed=self.seed,
    )
    self._assert_optional_threshold(
      label="onnx.pipeline_total",
      summary=summaries["pipeline_total"],
      env_name="EE_HF_PROFILE_ONNX_MAX_MEAN_MS",
    )
    return


if __name__ == "__main__":
  unittest.main()
