"""
Blockchain attestation mixin for RedMesh pentester API.

Handles obfuscation of scan metadata (IPs, CIDs, execution IDs) and
submission of attestations to the Ratio1 blockchain via the bc client.
"""

import ipaddress
from urllib.parse import urlparse

from ..constants import RUN_MODE_SINGLEPASS, RUN_MODE_CONTINUOUS_MONITORING
from ..services.config import get_attestation_config
from ..services.resilience import run_bounded_retry


class _AttestationMixin:
  """Blockchain attestation methods for PentesterApi01Plugin."""

  @staticmethod
  def _resolve_attestation_report_cid(workers: dict, preferred_cid=None) -> str | None:
    if isinstance(preferred_cid, str) and preferred_cid.strip():
      return preferred_cid.strip()
    if not isinstance(workers, dict):
      return None

    report_cids = [
      worker.get("report_cid", "").strip()
      for worker in workers.values()
      if isinstance(worker, dict) and isinstance(worker.get("report_cid"), str) and worker.get("report_cid").strip()
    ]
    if len(report_cids) == 1:
      return report_cids[0]
    return None

  def _attestation_get_tenant_private_key(self):
    private_key = get_attestation_config(self)["PRIVATE_KEY"]
    if private_key:
      private_key = private_key.strip()
    if not private_key:
      return None
    return private_key

  @staticmethod
  def _attestation_pack_cid_obfuscated(report_cid) -> str:
    if not isinstance(report_cid, str) or len(report_cid.strip()) == 0:
      return "0x" + ("00" * 10)
    cid = report_cid.strip()
    if len(cid) >= 10:
      masked = cid[:5] + cid[-5:]
    else:
      masked = cid.ljust(10, "_")
    safe = "".join(ch if 32 <= ord(ch) <= 126 else "_" for ch in masked)[:10]
    data = safe.encode("ascii", errors="ignore")
    if len(data) < 10:
      data = data + (b"_" * (10 - len(data)))
    return "0x" + data[:10].hex()

  @staticmethod
  def _attestation_extract_host(target):
    if not isinstance(target, str):
      return None
    target = target.strip()
    if not target:
      return None
    if "://" in target:
      parsed = urlparse(target)
      if parsed.hostname:
        return parsed.hostname
    host = target.split("/", 1)[0]
    if host.count(":") == 1 and "." in host:
      host = host.split(":", 1)[0]
    return host

  def _attestation_pack_ip_obfuscated(self, target) -> str:
    host = self._attestation_extract_host(target)
    if not host:
      return "0x0000"
    if ".." in host:
      parts = host.split("..")
      if len(parts) == 2 and all(part.isdigit() for part in parts):
        first_octet = int(parts[0])
        last_octet = int(parts[1])
        if 0 <= first_octet <= 255 and 0 <= last_octet <= 255:
          return f"0x{first_octet:02x}{last_octet:02x}"
    try:
      ip_obj = ipaddress.ip_address(host)
    except Exception:
      return "0x0000"
    if ip_obj.version != 4:
      return "0x0000"
    octets = host.split(".")
    first_octet = int(octets[0])
    last_octet = int(octets[-1])
    return f"0x{first_octet:02x}{last_octet:02x}"

  def _attestation_pack_node_ips_obfuscated(self, node_ips) -> tuple[list[str], str]:
    """
    Pack participating-node IPs as:
      - list form for local readability: ["0x0a03", "0x0a04"]
      - concatenated bytes for compact attestations: "0x0a030a04"

    Each node contributes exactly one bytes2 value. Missing or non-IPv4
    addresses are represented as 0x0000 so the packed value still
    preserves participant count/order.
    """
    if not isinstance(node_ips, (list, tuple)):
      node_ips = []
    obfuscated = [self._attestation_pack_ip_obfuscated(ip) for ip in node_ips]
    packed = "0x" + "".join(ip[2:] for ip in obfuscated if isinstance(ip, str) and ip.startswith("0x"))
    return obfuscated, packed

  @staticmethod
  def _attestation_pack_execution_id(job_id) -> str:
    if not isinstance(job_id, str):
      raise ValueError("job_id must be a string")
    job_id = job_id.strip()
    if len(job_id) != 8:
      raise ValueError("job_id must be exactly 8 characters")
    try:
      data = job_id.encode("ascii")
    except UnicodeEncodeError as exc:
      raise ValueError("job_id must contain only ASCII characters") from exc
    return "0x" + data.hex()

  def _attestation_get_worker_eth_addresses(self, workers: dict) -> list[str]:
    if not isinstance(workers, dict):
      return []
    eth_addresses = []
    for node_addr in workers.keys():
      eth_addr = self.bc.node_addr_to_eth_addr(node_addr)
      if not isinstance(eth_addr, str) or not eth_addr.startswith("0x"):
        raise ValueError(f"Unable to convert worker node to EVM address: {node_addr}")
      eth_addresses.append(eth_addr)
    eth_addresses.sort()
    return eth_addresses

  def _attestation_pack_node_hashes(self, workers: dict) -> str:
    eth_addresses = self._attestation_get_worker_eth_addresses(workers)
    if len(eth_addresses) == 0:
      return "0x" + ("00" * 32)
    digest = self.bc.eth_hash_message(types=["address[]"], values=[eth_addresses], as_hex=True)
    if isinstance(digest, str) and digest.startswith("0x"):
      return digest
    return "0x" + str(digest)

  def _submit_redmesh_test_attestation(
    self,
    job_id: str,
    job_specs: dict,
    workers: dict,
    vulnerability_score=0,
    node_ips=None,
    report_cid=None,
  ):
    self.P(f"[ATTESTATION] Test attestation requested for job {job_id} (score={vulnerability_score})")
    attestation_cfg = get_attestation_config(self)
    if not attestation_cfg["ENABLED"]:
      self.P("[ATTESTATION] Attestation is disabled via config. Skipping.", color='y')
      return None
    tenant_private_key = self._attestation_get_tenant_private_key()
    if tenant_private_key is None:
      self.P(
        "[ATTESTATION] Tenant private key is missing. "
        "Expected env var 'R1EN_ATTESTATION_PRIVATE_KEY'. Skipping.",
        color='y'
      )
      return None

    run_mode = str(job_specs.get("run_mode", RUN_MODE_SINGLEPASS)).upper()
    test_mode = 1 if run_mode == RUN_MODE_CONTINUOUS_MONITORING else 0
    node_count = len(workers) if isinstance(workers, dict) else 0
    target = job_specs.get("target")
    execution_id = self._attestation_pack_execution_id(job_id)
    report_cid = self._resolve_attestation_report_cid(workers, preferred_cid=report_cid)
    node_eth_address = self.bc.eth_address
    ip_obfuscated = self._attestation_pack_ip_obfuscated(target)
    cid_obfuscated = self._attestation_pack_cid_obfuscated(report_cid)

    self.P(
      f"[ATTESTATION] Submitting test attestation: job={job_id}, mode={'CONTINUOUS' if test_mode else 'SINGLEPASS'}, "
      f"nodes={node_count}, score={vulnerability_score}, target={ip_obfuscated}, "
      f"cid={cid_obfuscated}, sender={node_eth_address}"
    )
    retries = max(int(attestation_cfg["RETRIES"] or 1), 1)
    tx_hash = run_bounded_retry(
      self,
      "submit_redmesh_test_attestation",
      retries,
      lambda: self.bc.submit_attestation(
        function_name="submitRedmeshTestAttestation",
        function_args=[
          test_mode,
          node_count,
          vulnerability_score,
          execution_id,
          ip_obfuscated,
          cid_obfuscated,
        ],
        signature_types=["bytes32", "uint8", "uint16", "uint8", "bytes8", "bytes2", "bytes10"],
        signature_values=[
          self.REDMESH_ATTESTATION_DOMAIN,
          test_mode,
          node_count,
          vulnerability_score,
          execution_id,
          ip_obfuscated,
          cid_obfuscated,
        ],
        tx_private_key=tenant_private_key,
      ),
    )
    if not tx_hash:
      self.P(f"[ATTESTATION] Test attestation failed after {retries} attempts.", color='y')
      return None

    # Obfuscate all participating node IPs for attestation metadata.
    obfuscated_node_ips, node_ips_obfuscated_packed = (
      self._attestation_pack_node_ips_obfuscated(node_ips)
    )

    result = {
      "job_id": job_id,
      "tx_hash": tx_hash,
      "test_mode": "C" if test_mode == 1 else "S",
      "node_count": node_count,
      "vulnerability_score": vulnerability_score,
      "execution_id": execution_id,
      "report_cid": report_cid,
      "node_eth_address": node_eth_address,
      "node_ips_obfuscated": obfuscated_node_ips,
      "node_ips_obfuscated_packed": node_ips_obfuscated_packed,
    }
    self.P(
      "Submitted RedMesh test attestation for "
      f"{job_id} (tx: {tx_hash}, node: {node_eth_address}, score: {vulnerability_score})",
      color='g'
    )
    return result

  def _submit_redmesh_job_start_attestation(self, job_id: str, job_specs: dict, workers: dict):
    self.P(f"[ATTESTATION] Job-start attestation requested for job {job_id}")
    attestation_cfg = get_attestation_config(self)
    if not attestation_cfg["ENABLED"]:
      self.P("[ATTESTATION] Attestation is disabled via config. Skipping.", color='y')
      return None
    tenant_private_key = self._attestation_get_tenant_private_key()
    if tenant_private_key is None:
      self.P(
        "[ATTESTATION] Tenant private key is missing. "
        "Expected env var 'R1EN_ATTESTATION_PRIVATE_KEY'. Skipping.",
        color='y'
      )
      return None

    run_mode = str(job_specs.get("run_mode", RUN_MODE_SINGLEPASS)).upper()
    test_mode = 1 if run_mode == RUN_MODE_CONTINUOUS_MONITORING else 0
    node_count = len(workers) if isinstance(workers, dict) else 0
    target = job_specs.get("target")
    execution_id = self._attestation_pack_execution_id(job_id)
    node_eth_address = self.bc.eth_address
    ip_obfuscated = self._attestation_pack_ip_obfuscated(target)
    node_hashes = self._attestation_pack_node_hashes(workers)

    worker_addrs = list(workers.keys()) if isinstance(workers, dict) else []
    self.P(
      f"[ATTESTATION] Submitting job-start attestation: job={job_id}, mode={'CONTINUOUS' if test_mode else 'SINGLEPASS'}, "
      f"nodes={node_count}, target={ip_obfuscated}, node_hashes={node_hashes}, "
      f"workers={worker_addrs}, sender={node_eth_address}"
    )
    retries = max(int(attestation_cfg["RETRIES"] or 1), 1)
    tx_hash = run_bounded_retry(
      self,
      "submit_redmesh_job_start_attestation",
      retries,
      lambda: self.bc.submit_attestation(
        function_name="submitRedmeshJobStartAttestation",
        function_args=[
          test_mode,
          node_count,
          execution_id,
          node_hashes,
          ip_obfuscated,
        ],
        signature_types=["bytes32", "uint8", "uint16", "bytes8", "bytes32", "bytes2"],
        signature_values=[
          self.REDMESH_ATTESTATION_DOMAIN,
          test_mode,
          node_count,
          execution_id,
          node_hashes,
          ip_obfuscated,
        ],
        tx_private_key=tenant_private_key,
      ),
    )
    if not tx_hash:
      self.P(f"[ATTESTATION] Job-start attestation failed after {retries} attempts.", color='y')
      return None

    result = {
      "job_id": job_id,
      "tx_hash": tx_hash,
      "test_mode": "C" if test_mode == 1 else "S",
      "node_count": node_count,
      "execution_id": execution_id,
      "node_hashes": node_hashes,
      "ip_obfuscated": ip_obfuscated,
      "node_eth_address": node_eth_address,
    }
    self.P(
      "Submitted RedMesh job-start attestation for "
      f"{job_id} (tx: {tx_hash}, node: {node_eth_address}, node_count: {node_count})",
      color='g'
    )
    return result
