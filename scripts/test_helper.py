"""Actual persistent runner checks. All jobs use --echo; no scanning."""
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


def config(target="192.0.2.1"):
    return dict(targets=target, ports="80,443", exclusions="", interface="", rate=100, seed=42)


class RunnerTests(unittest.TestCase):
    def launch(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(5)
        process = subprocess.Popen(
            [str(HELPER), str(server.getsockname()[1]), TOKEN, "validate-session"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(server.close)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        self.addCleanup(cleanup)
        client, _ = server.accept()
        client.settimeout(5)
        self.addCleanup(client.close)
        return process, client

    def authorize(self, client):
        reader = client.makefile("rb")
        self.addCleanup(reader.close)
        self.assertEqual(json.loads(reader.readline()), {"kind": "hello", "text": TOKEN})
        for byte in [b"g", b"o", b"\n"]:
            client.sendall(byte)
            time.sleep(0.01)
        ready = json.loads(reader.readline())
        self.assertEqual(ready["kind"], "ready")
        return reader, ready["code"]

    def job(self, client, reader, target="192.0.2.1"):
        client.sendall(json.dumps(dict(kind="run", config=config(target))).encode() + b"\n")
        events = []
        while True:
            event = json.loads(reader.readline())
            events.append(event)
            if event["kind"] == "exit":
                return events

    def test_fragmented_handshake_and_two_jobs_keep_same_runner(self):
        process, client = self.launch()
        reader, pid = self.authorize(client)
        self.assertEqual(pid, process.pid)
        for target in ["192.0.2.1", "192.0.2.2"]:
            events = self.job(client, reader, target)
            self.assertEqual(events[-1]["code"], 0)
            output = b"".join(base64.b64decode(e["text"]) for e in events if e["kind"] == "stdout")
            self.assertIn(f"range = {target}".encode(), output)
            self.assertIn(b"ports = 80,443", output)
            self.assertIsNone(process.poll())
        client.sendall(b'{"kind":"quit"}\n')
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_disconnect_before_go_never_starts_scanner(self):
        process, client = self.launch()
        client.recv(4096)
        client.close()
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"App cancelled", stderr)

    def test_idle_disconnect_revokes_runner(self):
        process, client = self.launch()
        reader, _ = self.authorize(client)
        reader.close()
        client.close()
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_invalid_handshake_never_starts_scanner(self):
        process, client = self.launch()
        client.recv(4096)
        client.sendall(b"bad")
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"Invalid app handshake", stderr)

    def test_argument_injection_is_rejected_and_session_recovers(self):
        process, client = self.launch()
        reader, _ = self.authorize(client)
        events = self.job(client, reader, "--offline")
        self.assertEqual([e["kind"] for e in events], ["error", "exit"])
        self.assertIn("Invalid IPv4 target", events[0]["text"])
        self.assertEqual(self.job(client, reader)[-1]["code"], 0)

    def test_oversized_command_closes_runner(self):
        process, client = self.launch()
        self.authorize(client)
        client.sendall(b"x" * 131073)
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"Oversized runner command", stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
