import errno
import socket
import unittest

from extensions.business.cybersec.red_mesh.worker.pentest_worker import classify_connect_result


class TestClassifyConnectResult(unittest.TestCase):

  def test_errno_mapping(self):
    cases = {
      errno.ETIMEDOUT: "timeout",
      errno.EAGAIN: "timeout",
      errno.EWOULDBLOCK: "timeout",
      errno.ECONNREFUSED: "refused",
      errno.ECONNRESET: "reset",
      errno.EHOSTUNREACH: "error",
      errno.ENETUNREACH: "error",
      errno.EINPROGRESS: "error",
      errno.EPERM: "error",
    }
    for code, expected in cases.items():
      with self.subTest(errno=code):
        self.assertEqual(classify_connect_result(code), expected)

  def test_closed_local_port_is_refused(self):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens on port now
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
      result = sock.connect_ex(("127.0.0.1", port))
    finally:
      sock.close()
    self.assertEqual(classify_connect_result(result), "refused")


if __name__ == '__main__':
  unittest.main()
