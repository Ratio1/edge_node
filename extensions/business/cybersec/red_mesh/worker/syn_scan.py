"""
Half-open (SYN) TCP port probing for the blackbox scanner.

The default port-discovery path completes a full TCP handshake with
``connect_ex`` (see ``pentest_worker._scan_ports_step``). A SYN probe instead
sends a lone SYN, classifies the reply, and tears the attempt down with a RST
so the three-way handshake never completes and the target's service never sees
an accepted connection.

This needs a raw socket, which requires ``CAP_NET_RAW`` (or root) on the node.
Callers must gate on :func:`raw_socket_available` before probing; when the
capability is missing a SYN job is refused at launch rather than downgraded
silently, so an operator who asked for a half-open scan is never given a
full-handshake scan without being told.

The packet-crafting and classification helpers are pure functions so they can
be unit-tested without privilege; only :func:`syn_probe` and
:func:`raw_socket_available` touch a raw socket.
"""

import random
import select
import socket
import struct
import time

# TCP control-bit flags.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

# Probe classification results, mirroring nmap's vocabulary.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"


def raw_socket_available():
  """
  Return True when a raw TCP socket can be opened on this node.

  A raw socket needs ``CAP_NET_RAW`` or root. The check opens and immediately
  closes one; any ``PermissionError``/``OSError`` means the capability is
  absent and SYN mode is unavailable here.
  """
  try:
    probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  except (PermissionError, OSError):
    return False
  probe.close()
  return True


def _checksum(data):
  """Internet checksum (RFC 1071) over a byte string, big-endian pairs."""
  if len(data) % 2:
    data += b"\x00"
  total = 0
  for i in range(0, len(data), 2):
    total += (data[i] << 8) + data[i + 1]
  total = (total >> 16) + (total & 0xFFFF)
  total += total >> 16
  return (~total) & 0xFFFF


def build_syn_segment(src_ip, dst_ip, src_port, dst_port, seq):
  """
  Build a TCP SYN segment (no IP header) with a correct checksum.

  The checksum is computed over the TCP pseudo-header, so the caller must pass
  the source IP the kernel will actually put on the wire (see
  :func:`local_source_ip`). The kernel adds the IP header when the segment is
  sent with ``IP_HDRINCL`` off.
  """
  data_offset = 5 << 4                      # 5 32-bit words, no options
  window = 5840
  blank = struct.pack(
    "!HHLLBBHHH",
    src_port, dst_port, seq, 0,
    data_offset, SYN, window, 0, 0,
  )
  pseudo = struct.pack(
    "!4s4sBBH",
    socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    0, socket.IPPROTO_TCP, len(blank),
  )
  checksum = _checksum(pseudo + blank)
  return struct.pack(
    "!HHLLBBHHH",
    src_port, dst_port, seq, 0,
    data_offset, SYN, window, checksum, 0,
  )


def classify_flags(flags):
  """
  Map a reply segment's TCP flags to a probe result.

  SYN+ACK is an open port, RST (with or without ACK) is closed. Anything else
  is inconclusive and returns None so the caller keeps waiting until timeout.
  """
  if flags & RST:
    return CLOSED
  if (flags & SYN) and (flags & ACK):
    return OPEN
  return None


def parse_reply(packet, expect_src_ip, expect_sport, expect_dport):
  """
  Parse a raw IP+TCP packet and return (flags, seq, ack) when it is the reply
  to our probe, else None.

  A raw ``IPPROTO_TCP`` socket delivers packets including their IP header. The
  reply we want travels from the probed target:port back to our ephemeral
  source port, so it matches when its source is ``expect_src_ip``, its TCP
  source port is the probed port (``expect_sport``), and its TCP destination
  port is our source port (``expect_dport``).
  """
  if len(packet) < 20:
    return None
  ihl = (packet[0] & 0x0F) * 4
  if ihl < 20 or len(packet) < ihl + 20:
    return None
  src_ip = socket.inet_ntoa(packet[12:16])
  if src_ip != expect_src_ip:
    return None
  tcp = packet[ihl:ihl + 20]
  sport, dport, seq, ack, offset_flags = struct.unpack("!HHLLH", tcp[:14])
  if sport != expect_sport or dport != expect_dport:
    return None
  flags = offset_flags & 0x3F
  return flags, seq, ack


def local_source_ip(target_ip):
  """
  Return the local source IP the kernel would use to reach ``target_ip``.

  Uses a connected UDP socket, which assigns a route without sending anything,
  so the TCP checksum can be computed against the real source address.
  """
  probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    probe.connect((target_ip, 9))
    return probe.getsockname()[0]
  finally:
    probe.close()


def _send_rst(send_sock, src_ip, dst_ip, src_port, dst_port, seq, ack):
  """Tear down a half-open attempt so the handshake never completes."""
  data_offset = 5 << 4
  blank = struct.pack(
    "!HHLLBBHHH",
    src_port, dst_port, seq, ack,
    data_offset, RST, 0, 0, 0,
  )
  pseudo = struct.pack(
    "!4s4sBBH",
    socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    0, socket.IPPROTO_TCP, len(blank),
  )
  checksum = _checksum(pseudo + blank)
  segment = struct.pack(
    "!HHLLBBHHH",
    src_port, dst_port, seq, ack,
    data_offset, RST, 0, checksum, 0,
  )
  try:
    send_sock.sendto(segment, (dst_ip, 0))
  except OSError:
    pass


def syn_probe(target_ip, port, timeout, src_ip=None, src_port=None, seq=None):
  """
  Send one SYN to ``target_ip:port`` and classify the reply.

  Returns :data:`OPEN`, :data:`CLOSED`, or :data:`FILTERED`. On SYN+ACK a RST
  is sent back so the connection is never established. The caller is
  responsible for having confirmed :func:`raw_socket_available` first.
  """
  if src_port is None:
    src_port = random.randint(1025, 65534)
  if seq is None:
    seq = random.randint(0, 0xFFFFFFFF)
  if src_ip is None:
    src_ip = local_source_ip(target_ip)

  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  try:
    segment = build_syn_segment(src_ip, target_ip, src_port, port, seq)
    sock.sendto(segment, (target_ip, 0))

    end = time.monotonic() + timeout
    while True:
      remaining = end - time.monotonic()
      if remaining <= 0:
        return FILTERED
      ready, _, _ = select.select([sock], [], [], remaining)
      if not ready:
        return FILTERED
      packet, _ = sock.recvfrom(65535)
      parsed = parse_reply(packet, target_ip, port, src_port)
      if parsed is None:
        continue
      flags, rseq, rack = parsed
      result = classify_flags(flags)
      if result == OPEN:
        # RST the half-open connection: their SEQ+1 becomes our ACK.
        _send_rst(sock, src_ip, target_ip, src_port, port, rack, (rseq + 1) & 0xFFFFFFFF)
        return OPEN
      if result == CLOSED:
        return CLOSED
      # Inconclusive segment (e.g. stray) — keep waiting until deadline.
  finally:
    sock.close()
