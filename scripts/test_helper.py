"""Integration checks for the actual runner. All commands use --echo; no scanning."""
import base64
import json
import pathlib
import socket
import subprocess
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / ".build/debug/ScanHelper"
TOKEN = "0123456789abcdef" * 4


def payload(target="192.0.2.1"):
    config = dict(targets=target, ports="80,443", exclusions="", interface="", rate=100, seed=42)
    return base64.b64encode(json.dumps(config).encode()).decode()


class RunnerTests(unittest.TestCase):
    def launch(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(5)
        process = subprocess.Popen(
            [str(HELPER), str(server.getsockname()[1]), TOKEN, payload(), "validate"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(server.close)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        client, _ = server.accept()
        client.settimeout(5)
        self.addCleanup(client.close)
        return process, client

    def test_fragmented_handshake_streams_real_masscan_output(self):
        process, client = self.launch()
        reader = client.makefile("rb")
        self.addCleanup(reader.close)
        hello = json.loads(reader.readline())
        self.assertEqual(hello, {"kind": "hello", "text": TOKEN})
        for byte in [b"g", b"o", b"\n"]:
            client.sendall(byte)
            time.sleep(0.03)
        events = [json.loads(line) for line in reader]
        self.assertEqual(events[-1]["kind"], "exit")
        self.assertEqual(events[-1]["code"], 0)
        output = b"".join(base64.b64decode(e["text"]) for e in events if e["kind"] == "stdout")
        self.assertIn(b"range = 192.0.2.1", output)
        self.assertIn(b"ports = 80,443", output)
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_disconnect_before_go_never_starts_scanner(self):
        process, client = self.launch()
        client.recv(4096)
        client.close()
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"App cancelled", stderr)

    def test_invalid_handshake_never_starts_scanner(self):
        process, client = self.launch()
        client.recv(4096)
        client.sendall(b"bad")
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"Invalid app handshake", stderr)

    def test_argument_injection_is_rejected_before_connect(self):
        result = subprocess.run([str(HELPER), "1", TOKEN, payload("--offline"), "validate"],
                                capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Invalid IPv4 target", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
