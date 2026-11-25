"""RM-271 phase 2: SMB1 share enumeration against recorded replies (vulhub Samba 4.6.3, anonymous)."""
import struct
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.tests.test_rm198_detection_checks import _ScriptedSock, _worker
from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker

# Reply bytes after the 4-byte NetBIOS header, captured live from the owned lab target (no secrets in them).

_NEGOTIATE = bytes.fromhex(
  "ff534d4272000000008803c0000000000000000000000000000000000000000011000003320001000441000000000100"
  "23000000fdf38000c019c913c07cdd0100000836002b904e000b91654457004f0052004b00470052004f005500500000"
  "003800380030004200340043003000340039003500410043000000"
)

_SESSION = bytes.fromhex(
  "ff534d427300000000880380000000000000000000000000000000004925000003ff0000000100450000570069006e00"
  "64006f0077007300200036002e0031000000530061006d0062006100200034002e0036002e003300000057004f005200"
  "4b00470052004f00550050000000"
)

_TREE_IPC = bytes.fromhex(
  "ff534d4275000000008803800000000000000000000000008c8400004925000003ff0000000100070049504300000000"
)

_NT_CREATE = bytes.fromhex(
  "ff534d42a2000000008803800000000000000000000000008c840000492500002aff000000002d8f0100000000000000"
  "000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000"
  "0200ff0500000000000000000000000000000000000000000000000000ff011f009b0112000000"
)

_WRITE_ACK_BIND = bytes.fromhex(
  "ff534d422f000000008803800000000000000000000000008c8400004925000006ff00000048000000000000000000"
)

_READ_BIND_ACK = bytes.fromhex(
  "ff534d422e000000008803800000000000000000000000008c840000492500000cff00000000000000000044003c0000"
  "00000000000000000045000005000c03100000004400000001000000b810b810f05300000d005c504950455c73727673"
  "766300000100000000000000045d888aeb1cc9119fe808002b10486002000000"
)

_WRITE_ACK_ENUM = bytes.fromhex(
  "ff534d422f000000008803800000000000000000000000008c8400004925000006ff00000060000000000000000000"
)

_READ_ENUM = bytes.fromhex(
  "ff534d422e000000008803800000000000000000000000008c840000492500000cff000000000000000000fc003c0000"
  "000000000000000000fd00000500020310000000fc00000002000000e40000000000000001000000010000000c000200"
  "0200000010000200020000001400020000000000180002001c0002000300008020000200080000000000000008000000"
  "6d0079007300680061007200650000000100000000000000010000000000000005000000000000000500000049005000"
  "430024000000000029000000000000002900000049005000430020005300650072007600690063006500200028005300"
  "61006d006200610020005300650072007600650072002000560065007200730069006f006e00200034002e0036002e00"
  "330029000000000002000000240002000000000000000000"
)

_TREE_MYSHARE = bytes.fromhex(
  "ff534d42750000000088038000000000000000000000000019470000b67e000007ff0000000100ff011f00000000000d00413a004e005400460053000000"
)

_REPLIES = [_NEGOTIATE, _SESSION, _TREE_IPC, _NT_CREATE, _WRITE_ACK_BIND, _READ_BIND_ACK, _WRITE_ACK_ENUM, _READ_ENUM]
_CMDS = [0x72, 0x73, 0x75, 0xA2, 0x2F, 0x2E, 0x2F, 0x2E]
_READ_BIND_STEP, _READ_ENUM_STEP = 5, 7
_EXPECTED = [{"name": "myshare", "type": 0, "comment": ""},
             {"name": "IPC$", "type": 0x80000003, "comment": "IPC Service (Samba Server Version 4.6.3)"}]


def _nb(reply):
  return b"\x00" + struct.pack(">I", len(reply))[1:] + reply


def _enum(replies):
  sock = _ScriptedSock([_nb(r) for r in replies])
  with patch("socket.socket", return_value=sock):
    return _worker()._smb_enum_shares("10.0.0.1", 445), sock


def _data(reply):
  """(offset, length) of the DCE/RPC bytes inside a Read AndX reply."""
  length, offset = struct.unpack_from("<HH", reply, 43)
  return offset, length


def _patched(index, pos=None, value=None, data_pos=None, status=None, cmd=None, cut=None):
  replies = [bytearray(r) for r in _REPLIES]
  r = replies[index]
  if data_pos is not None:
    r[_data(r)[0] + data_pos] = value
  if pos is not None:
    r[pos] = value
  if status is not None:
    struct.pack_into("<I", r, 5, status)
  if cmd is not None:
    r[4] = cmd
  if cut is not None:
    del r[cut:]
  return [bytes(x) for x in replies]


class TestSmb1ShareEnumeration(unittest.TestCase):
  def test_recorded_session_lists_shares(self):
    shares, sock = _enum(_REPLIES)
    self.assertEqual(shares, _EXPECTED)
    self.assertEqual([p[8] for p in sock.sent], _CMDS)  # 4 NetBIOS bytes, then the command at byte 4

  def test_every_request_header_and_framing(self):
    _, sock = _enum(_REPLIES)
    for pkt in sock.sent:
      smb = pkt[4:]
      self.assertEqual(smb[9], 0x18)
      self.assertEqual(struct.unpack_from("<H", smb, 10)[0], 0xC001)
      self.assertEqual(smb[13:24], b"\x00" * 11)  # PID high and security fields stay zero
    tree, nt_create, write_bind, read_bind, write_enum = (sock.sent[i][4:] for i in (2, 3, 4, 5, 6))
    # Tree Connect AndX: wc 4 with the Flags word (AndX 4 bytes, Flags, PasswordLength), byte count matches
    self.assertEqual((tree[32], struct.unpack_from("<HH", tree, 33 + 4)), (4, (0, 1)))
    self.assertEqual(struct.unpack_from("<H", tree, 41)[0], len(tree) - 43)
    # NT Create AndX: wc 24, byte count includes one pad byte before the Unicode pipe name
    count = struct.unpack_from("<H", nt_create, 32 + 1 + 48)[0]
    self.assertEqual((nt_create[32], count, nt_create[83:84]), (24, len(nt_create) - 83, b"\x00"))
    self.assertEqual(nt_create[84:], "\\srvsvc".encode("utf-16-le") + b"\x00\x00")
    # Write AndX: DataOffset points at the PDU and the DCE frag_length equals the PDU length (16-byte header)
    for write in (write_bind, write_enum):
      data_len, data_off = struct.unpack_from("<HH", write, 33 + 20)  # words 10 (DataLength), 11 (DataOffset)
      pdu = write[data_off:]
      self.assertEqual(len(pdu), data_len)
      self.assertEqual(struct.unpack_from("<H", pdu, 8)[0], len(pdu))
    # Read AndX: MinCount 0 (a pipe read has no minimum)
    self.assertEqual(struct.unpack_from("<HH", read_bind, 33 + 10), (4280, 0))  # words 5 and 6: Max, Min
    # NetShareEnumAll: the resume handle is a non-null referent followed by its value
    self.assertEqual(write_enum[-8:], struct.pack("<II", 0x00020008, 0))

  def test_session_setup_words_are_the_non_extended_layout(self):
    _, sock = _enum(_REPLIES)
    sess = sock.sent[1][4:]
    self.assertEqual(sess[32], 13)  # wc 13 = 26 word bytes, then ByteCount
    self.assertEqual(struct.unpack_from("<H", sess, 33 + 26)[0], 1)
    self.assertEqual(len(sess), 32 + 1 + 26 + 2 + 1)
    # MaxBuffer, MaxMpx, Vc, SessionKey, OEM len, Unicode len, Reserved, Capabilities at words 2-3, 4, 5, 6-7, 8, 9, 10-11, 12
    self.assertEqual(struct.unpack_from("<HHHIHHII", sess, 33 + 4), (65535, 1, 0, 0, 0, 0, 0, 0xD4))

  def test_uid_tid_fid_from_replies_are_echoed_into_later_requests(self):
    uid = struct.unpack_from("<H", _SESSION, 28)[0]
    tid = struct.unpack_from("<H", _TREE_IPC, 24)[0]
    fid = struct.unpack_from("<H", _NT_CREATE, 38)[0]
    self.assertTrue(uid and tid and fid)  # recorded values are distinct from the zero defaults
    _, sock = _enum(_REPLIES)
    sent = [p[4:] for p in sock.sent]
    ids = [(struct.unpack_from("<H", r, 24)[0], struct.unpack_from("<H", r, 28)[0]) for r in sent]
    self.assertEqual(ids[2], (0, uid))          # Tree Connect: UID only
    self.assertEqual(ids[3:], [(tid, uid)] * 5)  # NT Create, Write, Read, Write, Read
    for r in sent[4:]:
      self.assertEqual(struct.unpack_from("<H", r, 33 + 4)[0], fid)  # FID is word 2 of Write and Read AndX

  def test_truncated_reply_at_every_step_gives_empty_list(self):
    for step in range(len(_REPLIES)):
      for cut in (0, 4, 20, 32) + ((45, len(_REPLIES[step]) - 1) if step in (_READ_BIND_STEP, _READ_ENUM_STEP) else ()):
        with self.subTest(step=step, cut=cut):
          self.assertEqual(_enum(_patched(step, cut=cut))[0], [])

  def test_missing_replies_give_empty_list(self):
    for have in range(len(_REPLIES)):
      with self.subTest(have=have):
        self.assertEqual(_enum(_REPLIES[:have])[0], [])

  def test_error_status_or_wrong_command_at_every_step_gives_empty_list(self):
    for step in range(len(_REPLIES)):
      with self.subTest(step=step, case="status"):
        self.assertEqual(_enum(_patched(step, status=0xC0000022))[0], [])
      with self.subTest(step=step, case="command"):
        self.assertEqual(_enum(_patched(step, cmd=0x25))[0], [])

  def test_read_more_data_status_is_incomplete(self):
    self.assertEqual(_enum(_patched(_READ_ENUM_STEP, status=0x80000005))[0], [])

  def test_bad_read_andx_framing_gives_empty_list(self):
    self.assertEqual(_enum(_patched(_READ_ENUM_STEP, pos=32, value=11))[0], [])  # word count must be 12
    self.assertEqual(_enum(_patched(_READ_ENUM_STEP, pos=45, value=0xFF))[0], [])  # DataOffset beyond the frame

  def test_bind_nak_and_wrong_packet_types_are_rejected(self):
    self.assertEqual(_enum(_patched(_READ_BIND_STEP, data_pos=2, value=13))[0], [])  # bind_nak
    self.assertEqual(_enum(_patched(_READ_ENUM_STEP, data_pos=2, value=3))[0], [])   # fault
    self.assertEqual(_enum(_patched(_READ_ENUM_STEP, data_pos=3, value=1))[0], [])   # not the last fragment

  def test_bind_ack_without_accepted_context_is_rejected(self):
    offset, _ = _data(_READ_BIND_ACK)
    result_pos = _READ_BIND_ACK.index(b"\x00\x00\x00\x00\x04\x5d\x88\x8a", offset)  # result 0, reason 0, NDR uuid
    self.assertEqual(_enum(_patched(_READ_BIND_STEP, pos=result_pos, value=2))[0], [])  # provider rejection

  def test_frag_length_beyond_the_data_is_rejected(self):
    self.assertEqual(_enum(_patched(_READ_ENUM_STEP, data_pos=8, value=0xFF))[0], [])

  def test_oversized_frame_gives_empty_list(self):
    big = b"\x00" + struct.pack(">I", 70000)[1:]
    sock = _ScriptedSock([big])
    with patch("socket.socket", return_value=sock):
      self.assertEqual(_worker()._smb_enum_shares("10.0.0.1", 445), [])


def _stub():
  offset, length = _data(_READ_ENUM)
  return _READ_ENUM[offset + 24:offset + length]


def _ndr_string(text):
  raw = text.encode("utf-16-le") + b"\x00\x00"
  return struct.pack("<III", len(raw) // 2, 0, len(raw) // 2) + raw + b"\x00" * (-len(raw) % 4)


def _built_stub(entries, comment_ptr=1, trailer=struct.pack("<III", 2, 0, 0), max_count=None):
  """A NetShareEnumAll level-1 response; `entries` is [(name, type, comment or None)]."""
  stub = struct.pack("<6I", 1, 1, 0x20000, len(entries), 0x20004, len(entries) if max_count is None else max_count)
  for name, stype, comment in entries:
    stub += struct.pack("<III", 0x20008, stype, 0x2000C if comment is not None else 0)
  for name, stype, comment in entries:
    stub += _ndr_string(name) + (_ndr_string(comment) if comment is not None else b"")
  return stub + trailer


class TestNetShareEnumAllParser(unittest.TestCase):
  parse = staticmethod(PentestLocalWorker._parse_netshareenumall_response)

  def test_recorded_stub_parses(self):
    self.assertEqual(self.parse(_stub()), _EXPECTED)

  def test_built_stub_with_null_comment_pointer_has_no_deferred_comment(self):
    stub = _built_stub([("pub", 0, None), ("docs", 0, "Docs")])
    self.assertEqual(self.parse(stub), [{"name": "pub", "type": 0, "comment": ""},
                                        {"name": "docs", "type": 0, "comment": "Docs"}])

  def test_share_text_is_capped_and_control_characters_dropped(self):
    noisy = "ev\x00il\u202e\u200fna\x1bme\x85" + "x" * 300
    stub = _built_stub([(noisy, 0, "c\u2066m\u2069t\x07" + "y" * 300)])
    (share,) = self.parse(stub)
    self.assertEqual(share["name"], ("evilname" + "x" * 300)[:256])
    self.assertEqual(share["comment"], ("cmt" + "y" * 300)[:256])

  def test_any_truncation_rejects_the_whole_reply(self):
    stub = _stub()
    for size in range(len(stub)):
      with self.subTest(size=size):
        self.assertEqual(self.parse(stub[:size]), [])

  def test_inconsistent_replies_are_rejected(self):
    cases = {
      "null name pointer": _stub()[:24] + struct.pack("<I", 0) + _stub()[28:],
      "max_count below entries": _built_stub([("a", 0, "")], max_count=0),
      "non-zero string offset": _built_stub([("a", 0, "")]).replace(struct.pack("<III", 2, 0, 2), struct.pack("<III", 2, 1, 2), 1),
      "actual count past the buffer": _built_stub([("a", 0, "")]).replace(struct.pack("<III", 2, 0, 2), struct.pack("<III", 99, 0, 99), 1),
      "no terminator": _built_stub([("a", 0, "")]).replace("a\x00".encode("utf-16-le"), "ab".encode("utf-16-le"), 1),
      "non-zero WERROR": _built_stub([("a", 0, "")], trailer=struct.pack("<III", 1, 0, 5)),
      "WERROR missing": _built_stub([("a", 0, "")], trailer=struct.pack("<II", 1, 0)),
      "TotalEntries below entries read": _built_stub([("a", 0, ""), ("b", 0, "")], trailer=struct.pack("<III", 1, 0, 0)),
      "zero entries": _built_stub([]),
      "wrong level": struct.pack("<I", 2) + _stub()[4:],
      "empty name": _built_stub([("", 0, "")]),
    }
    for label, stub in cases.items():
      with self.subTest(label):
        self.assertEqual(self.parse(stub), [])


class TestTreeConnectMaskRecorded(unittest.TestCase):
  def test_recorded_tree_connect_mask_for_the_writable_share(self):
    mask, reason = PentestLocalWorker._smb_tree_max_access(_TREE_MYSHARE)
    self.assertEqual((mask, reason), (0x001F01FF, None))
    self.assertTrue(mask & PentestLocalWorker._SMB_WRITE_RIGHTS)


class TestAdminShareListing(unittest.TestCase):
  """A null-session list that names admin shares is disclosure (MEDIUM), not proof of access (T-Pot Dionaea, RM-271)."""

  def test_listed_admin_shares_are_medium_and_say_access_was_not_tested(self):
    w = _worker(ports=(445,))
    smb_resp = bytearray(128)
    smb_resp[0:4] = b"\xffSMB"
    smb_resp[32] = 17
    sock = MagicMock()
    sock.recv.side_effect = [b"\x00\x00\x00\x80", bytes(smb_resp)]
    shares = [{"name": "ADMIN$", "type": 0, "comment": ""}, {"name": "C$", "type": 0, "comment": ""}]
    with patch.object(w, "_smb_enum_shares", return_value=shares), \
         patch.object(w, "_smb_try_null_session", return_value=None), \
         patch("socket.socket", return_value=sock):
      result = w._service_info_smb("10.0.0.1", 445)
    hit = [f for f in result["findings"] if f["title"].startswith("SMB admin shares listed via null session")]
    self.assertEqual(len(hit), 1)
    self.assertEqual(hit[0]["severity"], "MEDIUM")
    self.assertIn("not tested", hit[0]["description"])
