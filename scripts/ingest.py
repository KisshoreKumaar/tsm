#!/usr/bin/env python3
"""Ingest JSON or JSON Lines events into a running AEGIS API.

The token is read from AEGIS_INGEST_TOKEN or from the named identity in .env (default: ingest-bot). It is sent only
in the Authorization header. Each chunk is an atomic batch: an invalid event stores nothing from that chunk.

  python scripts/ingest.py events.jsonl
  python scripts/ingest.py events.json --url http://127.0.0.1:8000 --identity analyst --chunk 200
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.core.config import read_env_file  # noqa: E402

MAX_FILE_BYTES = 64 * 1024 * 1024


def load_events(path: Path) -> list[dict[str, Any]]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise SystemExit(f"{path} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise SystemExit(f"{path} is empty")
    if text[0] in "[{":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            events = parsed
        elif isinstance(parsed, dict):
            events = parsed["events"] if isinstance(parsed.get("events"), list) else [parsed]
        else:
            events = _lines(text)
    else:
        events = _lines(text)
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise SystemExit(f"Item {index + 1} is not a JSON object")
    return events


def _lines(text: str) -> list[Any]:
    events = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                raise SystemExit(f"Line {number} is not valid JSON") from None
    return events


def resolve_token(identity: str) -> str:
    token = os.environ.get("AEGIS_INGEST_TOKEN", "")
    if token:
        return token
    values = read_env_file(REPO / ".env")
    if identity == "local-admin":
        return values.get("AEGIS_API_TOKEN", "")
    try:
        identities = json.loads(values.get("AEGIS_IDENTITIES", "[]") or "[]")
    except json.JSONDecodeError:
        identities = []
    for item in identities if isinstance(identities, list) else []:
        if isinstance(item, dict) and item.get("name") == identity:
            return str(item.get("token", ""))
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path)
    parser.add_argument("--url", default=os.environ.get("AEGIS_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--identity", default="ingest-bot")
    parser.add_argument("--chunk", type=int, default=500)
    args = parser.parse_args()
    if not 1 <= args.chunk <= 5000:
        raise SystemExit("--chunk must be between 1 and 5000")
    token = resolve_token(args.identity)
    if not token:
        raise SystemExit("No token: set AEGIS_INGEST_TOKEN or run `make init-env` and pass --identity")
    events = load_events(args.path)
    stored = duplicates = 0
    incidents: set[str] = set()
    with httpx.Client(base_url=args.url.rstrip("/"), timeout=60.0, follow_redirects=False) as client:
        for start in range(0, len(events), args.chunk):
            chunk = events[start : start + args.chunk]
            response = client.post(
                "/api/events/batch", json={"events": chunk}, headers={"Authorization": f"Bearer {token}"}
            )
            if response.status_code != 201:
                try:
                    error = response.json().get("error", {})
                except ValueError:
                    error = {"message": response.text[:500]}
                print(f"Chunk starting at event {start + 1} failed ({response.status_code}):", file=sys.stderr)
                print(json.dumps(error, indent=2), file=sys.stderr)
                return 1
            body = response.json()
            stored += body["stored"]
            duplicates += body["duplicates"]
            incidents.update(body["incident_ids"])
    print(f"Stored {stored} event(s), {duplicates} duplicate(s); incidents touched: {len(incidents)}")
    for incident_id in sorted(incidents):
        print(f"  {incident_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
