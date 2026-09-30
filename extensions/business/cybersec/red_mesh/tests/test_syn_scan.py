"""Tests for the half-open (SYN) TCP probe used by the blackbox scanner."""

import socket
import struct
import threading
import unittest

from extensions.business.cybersec.red_mesh.worker import syn_scan


def _tcp_reply(src_ip, sport, dport, flags, seq=0, ack=0):
  """Craft a raw IP+TCP packet as a raw socket would deliver it."""
  ip = struct.pack(
    "!BBHHHBBH4s4s",
    0x45, 0, 40, 0, 0, 64, socket.IPPROTO_TCP, 0,
    socket.inet_aton(src_ip), socket.inet_aton("10.0.0.1"),
  )
  tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags, 0, 0, 0)
  return ip + tcp


class SynClassificationTests(unittest.TestCase):
  def test_syn_ack_is_open(self):
    self.assertEqual(syn_scan.classify_flags(syn_scan.SYN | syn_scan.ACK), syn_scan.OPEN)

  def test_rst_is_closed(self):
    self.assertEqual(syn_scan.classify_flags(syn_scan.RST | syn_scan.ACK), syn_scan.CLOSED)
    self.assertEqual(syn_scan.classify_flags(syn_scan.RST), syn_scan.CLOSED)

  def test_rst_wins_over_syn_ack_bits(self):
    # A reset takes precedence: a closed port never counts as open.
    self.assertEqual(
      syn_scan.classify_flags(syn_scan.SYN | syn_scan.ACK | syn_scan.RST),
      syn_scan.CLOSED,
    )

  def test_bare_ack_is_inconclusive(self):
    self.assertIsNone(syn_scan.classify_flags(syn_scan.ACK))


class SynChecksumTests(unittest.TestCase):
  def test_segment_checksum_verifies(self):
    segment = syn_scan.build_syn_segment("10.0.0.1", "10.0.0.2", 40000, 80, 12345)
    pseudo = struct.pack(
      "!4s4sBBH",
      socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"),
      0, socket.IPPROTO_TCP, len(segment),
    )
    # Summing a valid segment with its pseudo-header yields zero.
    self.assertEqual(syn_scan._checksum(pseudo + segment), 0)

  def test_segment_carries_syn_flag(self):
    segment = syn_scan.build_syn_segment("10.0.0.1", "10.0.0.2", 40000, 80, 1)
    flags = segment[13]
    self.assertTrue(flags & syn_scan.SYN)
    self.assertFalse(flags & syn_scan.ACK)


class SynReplyParsingTests(unittest.TestCase):
  def test_matching_reply_parses(self):
    pkt = _tcp_reply("10.0.0.9", sport=80, dport=40000, flags=syn_scan.SYN | syn_scan.ACK, seq=7)
    parsed = syn_scan.parse_reply(pkt, "10.0.0.9", 80, 40000)
    self.assertIsNotNone(parsed)
    flags, seq, _ack = parsed
    self.assertEqual(syn_scan.classify_flags(flags), syn_scan.OPEN)
    self.assertEqual(seq, 7)

  def test_wrong_source_ip_ignored(self):
    pkt = _tcp_reply("10.0.0.9", 80, 40000, syn_scan.SYN | syn_scan.ACK)
    self.assertIsNone(syn_scan.parse_reply(pkt, "10.0.0.10", 80, 40000))

  def test_wrong_port_ignored(self):
    pkt = _tcp_reply("10.0.0.9", 81, 40000, syn_scan.SYN | syn_scan.ACK)
    self.assertIsNone(syn_scan.parse_reply(pkt, "10.0.0.9", 80, 40000))

  def test_short_packet_ignored(self):
    self.assertIsNone(syn_scan.parse_reply(b"\x45" + b"\x00" * 10, "10.0.0.9", 80, 40000))


@unittest.skipUnless(syn_scan.raw_socket_available(),
                     "raw socket (CAP_NET_RAW) required for live SYN probe")
class SynProbeLiveTests(unittest.TestCase):
  """Exercise the real probe against a loopback listener."""

  def test_open_port_classified_open_without_completing_handshake(self):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted = []

    def _accept():
      listener.settimeout(1.0)
      try:
        conn, _ = listener.accept()
        accepted.append(conn)
      except socket.timeout:
        pass

    t = threading.Thread(target=_accept)
    t.start()
    try:
      result = syn_scan.syn_probe("127.0.0.1", port, timeout=1.0, src_ip="127.0.0.1")
      self.assertEqual(result, syn_scan.OPEN)
    finally:
      t.join()
      for conn in accepted:
        conn.close()
      listener.close()
    # The handshake was answered with RST, so no connection should be established.
    self.assertEqual(accepted, [])

  def test_closed_port_classified_closed(self):
    # Bind then close to obtain a port nothing listens on.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    result = syn_scan.syn_probe("127.0.0.1", port, timeout=1.0, src_ip="127.0.0.1")
    self.assertEqual(result, syn_scan.CLOSED)


if __name__ == "__main__":
  unittest.main()
