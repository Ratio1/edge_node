import os
import ipaddress
import socket
import struct
import json
from functools import lru_cache
from typing import Optional, Iterable

try:
  import requests
except Exception:
  requests = None


class _GeoLocatorMixin:
  
  
  def _inet_ntoa_le(self, hex_str: str) -> str:
    """Convert little-endian hex IPv4 (from /proc/net/route) to dotted string."""
    return socket.inet_ntoa(struct.pack("<L", int(hex_str, 16)))


  def _read_text(self, path: str) -> Optional[str]:
    try:
      with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().strip()
    except Exception:
      return None
        
    
  def _is_public_ip(self, ip: str) -> bool:
    """Return True if IP is valid and public (not private/reserved/etc.)."""
    try:
      obj = ipaddress.ip_address(ip)
    except ValueError:
      return False
    return not (
      obj.is_private
      or obj.is_loopback
      or obj.is_reserved
      or obj.is_link_local
      or obj.is_multicast
    )
    
  @lru_cache(maxsize=128)
  def get_docker_host_ip(self, timeout: float = 0.25) -> Optional[str]:
    """
    Return the Docker host IP reachable from this container.

    The function tries, in order:
    A. Resolve 'host.docker.internal' (supported on Docker Desktop and Docker 20.10+ with host-gateway).
    B. Parse the container's default gateway from /proc/net/route (works on bridge networks; usually 172.17.0.1).
    C. Fall back to the local source address used to reach the Internet (works in --network host).

    Parameters
    ----------
    timeout : float
      DNS resolution timeout in seconds (best-effort).

    Returns
    -------
    Optional[str]
      IPv4 address string, or None if not determinable.

    Notes
    -----
    - On Linux bridge networking, the host is typically reachable at the container's default gateway.
    - On Docker Desktop and newer engines, 'host.docker.internal' often maps to the gateway automatically.
    - In host networking mode, the returned address is the host's outward-facing IP.
    """
    # A) Try special DNS name
    try:
      # Prefer AF_INET
      addrinfo = socket.getaddrinfo("host.docker.internal", None, socket.AF_INET, socket.SOCK_STREAM)
      if addrinfo:
        addr = addrinfo[0][4][0]
        self.P("Container host IP detected via host.docker.internal as: {}".format(addr))
        return addr
    except Exception:
      pass

    # B) Parse default gateway from /proc/net/route
    try:
      with open("/proc/net/route", "r", encoding="utf-8") as f:
        for line in f.read().strip().splitlines()[1:]:
          fields = line.split()
          if len(fields) >= 3:
            dest_hex, gateway_hex, flags_hex = fields[1], fields[2], fields[3]
            # default route
            if dest_hex == "00000000":
              flags = int(flags_hex, 16)
              if flags & 0x2:  # RTF_GATEWAY
                addr = self._inet_ntoa_le(gateway_hex)
                self.P("Container host IP detected via /proc/net/route as: {}".format(addr))
                return addr
    except Exception:
      pass

    # C) Fallback: source address used to reach the Internet (host net or unusual setups)
    addr = None
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      try:
        s.settimeout(timeout)
        s.connect(("1.1.1.1", 53))
        addr = s.getsockname()[0]
      finally:
        s.close()
    except Exception:
      return None

    self.P("Container host IP detected via fallback '1.1.1.1' as: {}".format(addr))
    return addr

    
  def get_local_ip(self):
    """ Returns the IP of the current host running this script """
    return socket.gethostbyname(socket.gethostname())


  def get_public_ip(
    self, endpoints: Optional[Iterable[str]] = None,
    use_stun: bool = True,
    timeout: float = 3.0
  ) -> Optional[str]:
    """
    Discover the current machine's public (egress) IP.

    Parameters
    ----------
    endpoints : Optional[Iterable[str]]
      HTTP endpoints that return the caller's IP as plain text or JSON.
      If None, a sensible default list is used.
    use_stun : bool, optional
      If True, try STUN as a fallback (requires `pystun3`).
    timeout : float, optional
      Per-request timeout in seconds.

    Returns
    -------
    Optional[str]
      The public IPv4/IPv6 string if discovered, else None.

    Notes
    -----
    - The HTTP method requires outbound internet access and `requests`.
    - STUN fallback can work even if some HTTP endpoints are blocked, but
      still requires outbound UDP and a STUN server reachable from your network.
    - If you're on a VPN/proxy, this will report the VPN/proxy's egress IP.
    """
    eps = list(endpoints or [
      "https://api.ipify.org?format=json",     # {"ip": "..."}
      "https://ifconfig.me/ip",                # plain text
      "https://icanhazip.com",                 # plain text
      "https://ipapi.co/ip",                   # plain text
    ])

    # HTTP attempts
    if requests is not None:
      for url in eps:
        try:
          r = requests.get(url, timeout=timeout)
          if not r.ok:
            continue
          text = r.text.strip()
          # Handle JSON shape from api.ipify.org
          if text.startswith("{"):
            data = r.json()
            cand = (data.get("ip") or "").strip()
          else:
            cand = text
          if self._is_public_ip(cand):
            return cand
        except Exception:
          continue

    # STUN fallback (IPv4)
    if use_stun:
      try:
        # pip install pystun3
        import stun
        nat_type, external_ip, external_port = stun.get_ip_info(
          stun_host="stun.l.google.com",
          stun_port=19302,
          source_port=0
        )
        if external_ip and self._is_public_ip(external_ip):
          return external_ip
      except Exception:
        pass

    return None


  def _local_mmdb_country(
    self, ip: str, mmdb_path: Optional[str], return_iso: bool
  ) -> Optional[str]:
    """Try to resolve via a local MaxMind GeoLite2-Country database."""
    try:
      import geoip2.database
    except Exception:
      return None
    path = mmdb_path or os.getenv("GEOLITE2_COUNTRY_DB", "./GeoLite2-Country.mmdb")
    if not os.path.exists(path):
      return None
    try:
      with geoip2.database.Reader(path) as reader:
        resp = reader.country(ip)
        return resp.country.iso_code if return_iso else resp.country.name
    except Exception:
      return None


  def _http_country(self, ip: str, return_iso: bool, full_data=True):
    """Try public APIs (ipapi.co first; then ipinfo.io if token provided)."""
    if requests is None:
      return None
    try:
      r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
      if r.ok:
        data = r.json()
        self.P("IP geolocation data retrieved successfully:\n{}".format(json.dumps(data, indent=2)))
        if full_data:
          return data
        if return_iso and data.get("country"):
          return data.get("country")
        if not return_iso and data.get("country_name"):
          return data.get("country_name")
    except Exception:
      pass

    token = os.getenv("IPINFO_TOKEN")
    if token:
      try:
        r = requests.get(f"https://ipinfo.io/{ip}/json?token={token}", timeout=3)
        if r.ok:
          data = r.json()
          code = data.get("country")
          if code:
            return code if return_iso else code  # ipinfo returns ISO only
      except Exception:
        pass
    return None


  @lru_cache(maxsize=4096)
  def geolocate_ip(
    self, ip: Optional[str] = None, *,
    prefer_local: bool = True,
    return_iso: bool = False,
    mmdb_path: Optional[str] = None,
    discover_when_private: bool = True
  ) -> Optional[str]:
    """
    Determine the country for an IP address. If the IP is private/LAN, optionally
    discover the public egress IP and geolocate that instead.

    Parameters
    ----------
    ip : Optional[str], optional
      IP address (IPv4/IPv6). If None, the function will attempt to discover
      the public IP and geolocate it.
    prefer_local : bool, optional
      If True, try a local GeoLite2-Country database first. Otherwise use HTTP first.
    return_iso : bool, optional
      If True, return ISO 3166-1 alpha-2 code (e.g., 'US'); else country name.
    mmdb_path : Optional[str], optional
      Path to GeoLite2-Country.mmdb (or via $GEOLITE2_COUNTRY_DB).
    discover_when_private : bool, optional
      If True and `ip` is private/non-public, attempt to discover public IP
      and geolocate that.

    Returns
    -------
    Optional[str]
      Country name (or ISO code), or None if unknown/unavailable.

    Examples
    --------
    >>> geolocate_ip("192.168.1.10", return_iso=True)  # LAN IP, discover egress
    'RO'
    >>> geolocate_ip()  # auto-discover public IP
    'United States'
    """
    target_ip = ip

    if not target_ip:
      local_ip = self.get_local_ip()
      self.P("Local IP detected as: {}".format(local_ip))
      docker_host = self.get_docker_host_ip()
      self.P("Container host IP detected as: {}".format(docker_host))
      target_ip = self.get_public_ip()
      if not target_ip:
        return None

      self.P("Public IP detected as: {}".format(target_ip))

    if not self._is_public_ip(target_ip):
      if discover_when_private:
        pub = self.get_public_ip()
        if not pub:
          return None
        target_ip = pub
      else:
        return None

    self.P("Geolocating IP: {}".format(target_ip))
    res = None
    if False:
      backends = (
        (self._local_mmdb_country, self._http_country)
        if prefer_local else
        (self._http_country, self._local_mmdb_country)
      )
      for fn in backends:
        if fn is self._local_mmdb_country:
          res = fn(ip=target_ip, mmdb_path=mmdb_path, return_iso=return_iso)
        else:
          res = fn(ip=target_ip, return_iso=return_iso)
        if res:
          break
    else:
      res = self._http_country(ip=target_ip, return_iso=return_iso)
    # endif      
    return res

  
  @lru_cache(maxsize=64)
  def check_if_host_is_datacenter(self, timeout: float = 0.35, try_asn_fallback: bool = True) -> Optional[str]:
    """
    Detect the cloud/datacenter provider hosting the current VM/host.

    Strategy (short timeouts, safe to call from containers):
    A. Probe well-known instance metadata endpoints (link-local IPs).
    B. Inspect DMI strings (/sys/class/dmi/id) for vendor/product hints.
    C. (Optional) ASN/org fallback from the public egress IP via a geolocation API.

    Parameters
    ----------
    timeout : float
      Per-request HTTP timeout in seconds.
    try_asn_fallback : bool
      If True and metadata/DMI checks fail, use ASN/org lookup to infer a provider.

    Returns
    -------
    Optional[str]
      A normalized provider name (e.g., 'aws', 'azure', 'gcp', 'digitalocean',
      'hetzner', 'oci', 'alibaba', 'openstack', 'ovh', 'scaleway', 'hostinger'),
      or None if undetectable.

    Notes
    -----
    - Metadata servers are only reachable from inside the VM on link-local IPs:
      AWS/Azure/GCP/OpenStack/DO/Hetzner/OCI use 169.254.169.254;
      Alibaba uses 100.100.100.200.
    - AWS may require IMDSv2 token; we try v2 then v1.
    - DMI strings are heuristic; cloud images often set sys_vendor/product_name.
    - ASN/org fallback may misclassify resold capacity or bare-metal colo.
    """
    # --- A) Metadata probes (fast, authoritative) ---
    if requests is not None:
      try:
        # AWS IMDSv2 -> IMDSv1
        try:
          t = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            timeout=timeout,
          )
          if t.ok and t.text:
            r = requests.get(
              "http://169.254.169.254/latest/meta-data/instance-id",
              headers={"X-aws-ec2-metadata-token": t.text},
              timeout=timeout,
            )
            if r.ok:
              return "aws"
        except Exception:
          pass
        try:
          r = requests.get("http://169.254.169.254/latest/meta-data/", timeout=timeout)
          if r.ok:
            return "aws"
        except Exception:
          pass

        # Azure
        try:
          r = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"},
            timeout=timeout,
          )
          if r.ok:
            return "azure"
        except Exception:
          pass

        # GCP
        try:
          r = requests.get(
            "http://169.254.169.254/computeMetadata/v1/project/project-id",
            headers={"Metadata-Flavor": "Google"},
            timeout=timeout,
          )
          if r.ok and r.headers.get("Metadata-Flavor", "").lower() == "google":
            return "gcp"
        except Exception:
          pass

        # DigitalOcean
        try:
          r = requests.get("http://169.254.169.254/metadata/v1.json", timeout=timeout)
          if r.ok and "droplet" in r.text.lower():
            return "digitalocean"
        except Exception:
          pass

        # Hetzner Cloud
        try:
          r = requests.get("http://169.254.169.254/hetzner/v1/metadata", timeout=timeout)
          if r.ok:
            return "hetzner"
        except Exception:
          pass

        # Oracle Cloud (OCI) v2 -> v1
        for url in ("http://169.254.169.254/opc/v2/instance/", "http://169.254.169.254/opc/v1/instance/"):
          try:
            r = requests.get(url, timeout=timeout)
            if r.ok:
              return "oci"
          except Exception:
            pass

        # Alibaba Cloud
        try:
          r = requests.get("http://100.100.100.200/latest/meta-data/instance-id", timeout=timeout)
          if r.ok:
            return "alibaba"
        except Exception:
          pass

        # OpenStack (generic)
        try:
          r = requests.get("http://169.254.169.254/openstack/latest/meta_data.json", timeout=timeout)
          if r.ok:
            return "openstack"
        except Exception:
          pass

      except Exception:
        pass

    # --- B) DMI heuristics (best-effort) ---
    dmi = " ".join(
      filter(
        None,
        [
          self._read_text("/sys/class/dmi/id/sys_vendor"),
          self._read_text("/sys/class/dmi/id/product_name"),
          self._read_text("/sys/class/dmi/id/bios_vendor"),
          self._read_text("/sys/class/dmi/id/bios_version"),
        ],
      )
    ).lower()

    if dmi:
      checks = [
        ("aws", ("amazon", "ec2")),
        ("gcp", ("google", "compute engine")),
        ("azure", ("microsoft", "hyper-v")),
        ("digitalocean", ("digitalocean",)),
        ("hetzner", ("hetzner",)),
        ("oci", ("oracle", "oci")),
        ("alibaba", ("alibaba", "aliyun")),
        ("openstack", ("openstack",)),
        ("ovh", ("ovh",)),
        ("scaleway", ("scaleway",)),
        ("hostinger", ("hostinger",)),
      ]
      for name, needles in checks:
        if any(k in dmi for k in needles):
          return name

    # --- C) ASN/org fallback (optional, external) ---
    if try_asn_fallback and requests is not None:
      try:
        # get public egress IP
        ip = None
        for ep in ("https://ipapi.co/ip", "https://ifconfig.me/ip", "https://icanhazip.com"):
          try:
            r = requests.get(ep, timeout=timeout)
            if r.ok:
              ip = r.text.strip()
              break
          except Exception:
            continue

        if ip:
          # ipapi: 'org' string usually contains provider/ASN
          r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=timeout)
          if r.ok:
            data = r.json()
            org = (data.get("org") or data.get("asn") or "").lower()
            mapping = {
              "amazon": "aws",
              "aws": "aws",
              "google": "gcp",
              "microsoft": "azure",
              "azure": "azure",
              "digitalocean": "digitalocean",
              "hetzner": "hetzner",
              "ovh": "ovh",
              "scaleway": "scaleway",
              "hostinger": "hostinger",
              "oracle": "oci",
              "alibaba": "alibaba",
            }
            for key, val in mapping.items():
              if key in org:
                return val
      except Exception:
        pass

    return None
  



if __name__ == "__main__":
  from ratio1 import Logger
  l = Logger("IPTEST", base_folder=".", app_folder="_local_cache")
  eng = _GeoLocatorMixin()
  eng.P = lambda x: l.P(x)
  
  l.P("=== Testing geolocate_ip() ===")
  l.P(eng.geolocate_ip(return_iso=True))