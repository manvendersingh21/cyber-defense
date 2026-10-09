#!/usr/bin/env python3
"""Bridge a completed Cyber Defense campaign into a CloseLoop handoff."""

import argparse
import json
import os
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep bearer credentials on the explicitly configured endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_URL_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def load_env(path: Path) -> None:
    """Load simple KEY=VALUE entries without logging secret values."""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        os.environ.setdefault(key, value.strip().strip("\"'"))


def completed_campaign(events_path: Path) -> dict:
    events = [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line.strip()
    ]
    report = next(
        (
            event
            for event in reversed(events)
            if event.get("action_id") == "report"
            and event.get("status") == "passed"
        ),
        None,
    )
    if report is None:
        raise ValueError("campaign has no passed report event")
    return report


def build_handoff(template_path: Path, report_event: dict) -> dict:
    handoff = json.loads(template_path.read_text())
    now = datetime.now(timezone.utc)
    finding_id = f"FIND-CYBER-E2E-{uuid.uuid4().hex}"
    handoff["finding_id"] = finding_id
    handoff["title"] = (
        "Cyber Defense found workload policy exposure to protected canary data"
    )
    handoff["evidence"]["artifacts"] = [
        report_event.get("evidence") or "evidence/final-report.json",
        "cyber-defense/campaign-events.jsonl",
    ]
    handoff["handoff"]["created_at"] = now.isoformat().replace("+00:00", "Z")
    handoff["handoff"]["source"] = {
        "system": "cyber-defense",
        "campaign": "synthetic-k8s-assessment",
        "action_id": report_event["action_id"],
        "status": report_event["status"],
    }
    handoff["akash"]["dseq"] = os.environ["AKASH_LAB_DSEQ"]
    handoff["akash"]["service"] = os.environ.get(
        "AKASH_LAB_SERVICE", "lab-api"
    )
    handoff["akash"]["base_url"] = os.environ["LAB_BASE_URL"].rstrip("/")
    return handoff


def post_handoff(url: str, token: str, handoff: dict) -> dict:
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/handoffs",
        data=json.dumps(handoff).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "cyber-defense-closeloop-bridge",
        },
        method="POST",
    )
    try:
        with _URL_OPENER.open(request, timeout=30) as response:
            if response.status not in (200, 202):
                raise RuntimeError(
                    f"CloseLoop returned unexpected HTTP {response.status}"
                )
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # Do not surface a response body: an upstream might reflect credentials
        # or other sensitive request data in an error.
        status = error.code
        error.close()
        raise RuntimeError(f"CloseLoop HTTP {status}") from None
    except urllib.error.URLError:
        # Avoid including the requested URL, which may contain user info.
        raise RuntimeError("CloseLoop request failed") from None
    except json.JSONDecodeError:
        raise RuntimeError("CloseLoop returned invalid JSON") from None

    if not isinstance(result, dict):
        raise RuntimeError("CloseLoop returned an invalid response")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send one completed Cyber Defense campaign finding to CloseLoop"
    )
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--closeloop-url", default="http://127.0.0.1:3000")
    parser.add_argument(
        "--out", type=Path, default=Path("/tmp/cyber-defense-handoff.json")
    )
    args = parser.parse_args()

    load_env(args.env_file)
    for name in (
        "CLOSELOOP_INGEST_TOKEN",
        "AKASH_LAB_DSEQ",
        "LAB_BASE_URL",
    ):
        if not os.environ.get(name):
            raise ValueError(f"{name} missing")

    report_event = completed_campaign(args.events)
    handoff = build_handoff(args.template, report_event)
    args.out.write_text(json.dumps(handoff, indent=2) + "\n")
    result = post_handoff(
        args.closeloop_url, os.environ["CLOSELOOP_INGEST_TOKEN"], handoff
    )
    job_id = result.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        # Never echo the response: it is controlled by the remote service and
        # might contain sensitive data.
        raise RuntimeError("CloseLoop did not return a valid job_id")

    print(f"finding_id={handoff['finding_id']}")
    print(f"job_id={job_id}")
    print(f"handoff_saved={args.out}")


if __name__ == "__main__":
    main()
