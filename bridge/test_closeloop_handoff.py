import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bridge.closeloop_handoff import completed_campaign, post_handoff


BRIDGE = Path(__file__).with_name("closeloop_handoff.py")
TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "closeloop/contracts/examples/FIND-002.akash.handoff.json"
)


class _MockCloseLoopHandler(BaseHTTPRequestHandler):
    request_data = {}
    response_status = 202
    response_body = {
        "job_id": "mock-job-123",
        "finding_id": "ignored-by-client",
        "result_url": "/api/jobs/mock-job-123/result",
    }
    response_headers = {}
    redirect_followed = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        type(self).request_data = {
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "content_type": self.headers.get("Content-Type"),
            "body": json.loads(self.rfile.read(length)),
        }
        body = json.dumps(type(self).response_body).encode()
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in type(self).response_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).redirect_followed = True
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format, *_args):
        pass


class CloseLoopBridgeTest(unittest.TestCase):
    def setUp(self):
        _MockCloseLoopHandler.request_data = {}
        _MockCloseLoopHandler.response_status = 202
        _MockCloseLoopHandler.response_body = {
            "job_id": "mock-job-123",
            "finding_id": "ignored-by-client",
            "result_url": "/api/jobs/mock-job-123/result",
        }
        _MockCloseLoopHandler.response_headers = {}
        _MockCloseLoopHandler.redirect_followed = False
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _MockCloseLoopHandler
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    @property
    def server_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def test_cli_posts_fresh_contract_handoff_without_printing_secrets(self):
        secret = "top-secret-ingest-token"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "campaign.jsonl"
            events.write_text(
                "\n".join(
                    (
                        json.dumps(
                            {
                                "timestamp": "2026-10-09T22:00:00+00:00",
                                "action_id": "inventory",
                                "status": "passed",
                                "evidence": "evidence/inventory.json",
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-10-09T22:01:00+00:00",
                                "action_id": "report",
                                "status": "passed",
                                "evidence": "evidence/final-report.json",
                            }
                        ),
                    )
                )
                + "\n"
            )
            env_file = root / ".env"
            env_file.write_text(
                "\n".join(
                    (
                        f"CLOSELOOP_INGEST_TOKEN={secret}",
                        "AKASH_LAB_DSEQ=7654321",
                        "AKASH_LAB_SERVICE=lab-api",
                        "LAB_BASE_URL=https://lab.example.invalid/",
                    )
                )
                + "\n"
            )
            output = root / "handoff.json"
            child_env = os.environ.copy()
            for name in (
                "CLOSELOOP_INGEST_TOKEN",
                "AKASH_LAB_DSEQ",
                "AKASH_LAB_SERVICE",
                "LAB_BASE_URL",
            ):
                child_env.pop(name, None)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(BRIDGE),
                    "--events",
                    str(events),
                    "--template",
                    str(TEMPLATE),
                    "--env-file",
                    str(env_file),
                    "--closeloop-url",
                    self.server_url,
                    "--out",
                    str(output),
                ],
                cwd=BRIDGE.parents[1],
                env=child_env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, completed.stdout)
            self.assertNotIn(secret, completed.stderr)
            self.assertIn("job_id=mock-job-123", completed.stdout)

            request = _MockCloseLoopHandler.request_data
            self.assertEqual(request["path"], "/api/handoffs")
            self.assertEqual(
                request["authorization"], f"Bearer {secret}"
            )
            self.assertEqual(request["content_type"], "application/json")

            handoff = request["body"]
            self.assertRegex(
                handoff["finding_id"], r"^FIND-CYBER-E2E-[0-9a-f]{32}$"
            )
            self.assertEqual(handoff, json.loads(output.read_text()))
            self.assertEqual(handoff["akash"]["dseq"], "7654321")
            self.assertEqual(
                handoff["akash"]["base_url"],
                "https://lab.example.invalid",
            )
            self.assertEqual(
                handoff["evidence"]["artifacts"][0],
                "evidence/final-report.json",
            )
            self.assertEqual(
                handoff["handoff"]["source"]["status"], "passed"
            )

    def test_campaign_requires_a_passed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "campaign.jsonl"
            events.write_text(
                '{"action_id":"report","status":"failed"}\n'
            )
            with self.assertRaisesRegex(
                ValueError, "campaign has no passed report event"
            ):
                completed_campaign(events)

    def test_http_error_does_not_expose_response_body(self):
        secret = "reflected-secret-value"
        _MockCloseLoopHandler.response_status = 401
        _MockCloseLoopHandler.response_body = {"error": secret}

        with self.assertRaises(RuntimeError) as raised:
            post_handoff(self.server_url, "request-token", {"test": True})

        self.assertEqual(str(raised.exception), "CloseLoop HTTP 401")
        self.assertNotIn(secret, str(raised.exception))

    def test_redirect_is_not_followed_with_bearer_token(self):
        _MockCloseLoopHandler.response_status = 302
        _MockCloseLoopHandler.response_headers = {
            "Location": f"{self.server_url}/should-not-be-requested"
        }

        with self.assertRaisesRegex(RuntimeError, "CloseLoop HTTP 302"):
            post_handoff(self.server_url, "request-token", {"test": True})

        self.assertFalse(_MockCloseLoopHandler.redirect_followed)


if __name__ == "__main__":
    unittest.main()
