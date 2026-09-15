#!/usr/bin/env python3
"""AEGIS operator commands (local use only).

  init-env       Generate .env with random tokens and keys (refuses to overwrite without --force)
  token          Print the token for a named identity from .env (default: local-admin)
  identities     List configured identity names and roles (no tokens)
  verify-audit   Verify the audit hash chain; exits 1 when invalid
  checkpoint     Print the audit chain head for external retention
  backup         Consistent SQLite backup (refuses to overwrite)
  demo           Load a synthetic scenario into the local database
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.core.config import Settings, environment_with_dotenv, read_env_file  # noqa: E402

ENV_PATH = REPO / ".env"
DEMO_IDENTITIES = (
    ("analyst", "analyst"),
    ("analyst-2", "analyst"),
    ("approver", "approver"),
    ("detection-engineer", "detection_engineer"),
    ("viewer", "viewer"),
    ("ingest-bot", "ingest"),
)


def _random_token() -> str:
    return secrets.token_urlsafe(32)


def _settings() -> Settings:
    return Settings.from_env(environment_with_dotenv(ENV_PATH))


def _existing_db(settings: Settings) -> Path:
    path = Path(settings.db_path)
    if not path.exists():
        raise SystemExit(f"No database at {path}; start the API once to create it.")
    return path


def cmd_init_env(args: argparse.Namespace) -> int:
    if ENV_PATH.exists() and not args.force:
        print(f"{ENV_PATH} already exists. Use --force to replace it (its audit key would be lost).", file=sys.stderr)
        return 1
    identities = [{"name": name, "role": role, "token": _random_token()} for name, role in DEMO_IDENTITIES]
    generated = {
        "AEGIS_API_TOKEN": _random_token(),
        "AEGIS_AUDIT_KEY": secrets.token_urlsafe(48),
        "AEGIS_SECRET_KEY": secrets.token_urlsafe(48),
        "AEGIS_IDENTITIES": json.dumps(identities, separators=(",", ":")),
    }
    lines: list[str] = []
    for line in (REPO / ".env.example").read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0].strip()
        if not line.startswith("#") and "=" in line and key in generated:
            lines.append(f"{key}={generated.pop(key)}")
        else:
            lines.append(line)
    lines.extend(f"{key}={value}" for key, value in generated.items())
    descriptor = os.open(ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(ENV_PATH, 0o600)
    names = ", ".join(["local-admin", *(name for name, _ in DEMO_IDENTITIES)])
    print(f"Wrote {ENV_PATH} (mode 600) with identities: {names}")
    print("Show a token with: make token NAME=local-admin")
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    values = read_env_file(ENV_PATH)
    token = ""
    if args.name == "local-admin":
        token = values.get("AEGIS_API_TOKEN", "")
    else:
        try:
            identities = json.loads(values.get("AEGIS_IDENTITIES", "[]") or "[]")
        except json.JSONDecodeError:
            identities = []
        for identity in identities if isinstance(identities, list) else []:
            if isinstance(identity, dict) and identity.get("name") == args.name:
                token = str(identity.get("token", ""))
    if not token:
        print(f"No token found for {args.name!r} in {ENV_PATH}", file=sys.stderr)
        return 1
    print(token)
    return 0


def cmd_identities(_: argparse.Namespace) -> int:
    for identity in _settings().identities:
        print(f"{identity.name}\t{identity.role}")
    return 0


def cmd_verify_audit(_: argparse.Namespace) -> int:
    from app.core.audit import AuditLog
    from app.core.db import Database

    settings = _settings()
    result = AuditLog(settings.audit_key).verify(Database(_existing_db(settings)))
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def cmd_checkpoint(_: argparse.Namespace) -> int:
    from app.core.audit import AuditLog
    from app.core.db import Database

    settings = _settings()
    result = AuditLog(settings.audit_key).checkpoint(Database(_existing_db(settings)))
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def cmd_backup(args: argparse.Namespace) -> int:
    from app.core.db import Database

    settings = _settings()
    Database(_existing_db(settings)).backup(args.output)
    print(f"Backup written to {args.output}. Store the audit key separately and securely.")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    try:
        from app.demo.cli import load_scenario  # type: ignore[import-not-found]
    except ImportError:
        print("Demo scenarios are not available in this build yet.", file=sys.stderr)
        return 1
    return int(load_scenario(_settings(), args.scenario))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-env")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init_env)
    token = sub.add_parser("token")
    token.add_argument("--name", default="local-admin")
    token.set_defaults(func=cmd_token)
    sub.add_parser("identities").set_defaults(func=cmd_identities)
    sub.add_parser("verify-audit").set_defaults(func=cmd_verify_audit)
    sub.add_parser("checkpoint").set_defaults(func=cmd_checkpoint)
    backup = sub.add_parser("backup")
    backup.add_argument("--output", required=True)
    backup.set_defaults(func=cmd_backup)
    demo = sub.add_parser("demo")
    demo.add_argument("--scenario", default="attack-chain")
    demo.set_defaults(func=cmd_demo)
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
