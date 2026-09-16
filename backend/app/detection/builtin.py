"""Built-in detection rules. Pure functions of the (sorted) component events; no log content is executed."""

from __future__ import annotations

import copy
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from app.detection.base import (
    Detection,
    Event,
    build_detection,
    group_events,
    make_group_key,
    sliding_window_hits,
)
from app.ingest.normalize import process_basename


@dataclass(frozen=True)
class RuleInfo:
    id: str
    name: str
    version: int
    techniques: tuple[str, ...]
    severity: str
    confidence: int
    stage: str
    description: str

    TUNABLE: ClassVar[tuple[str, ...]] = ()
    THRESHOLD: ClassVar[int] = 0
    WINDOW_SECONDS: ClassVar[int] = 0

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        raise NotImplementedError

    def parameters(self) -> dict[str, int]:
        if not self.TUNABLE:
            return {}
        return {"threshold": self.THRESHOLD, "window_seconds": self.WINDOW_SECONDS}

    def with_parameters(self, threshold: int | None = None, window_seconds: int | None = None) -> RuleInfo:
        """A copy with approved tuning applied (A5). Only rules declaring TUNABLE accept parameters."""
        if not self.TUNABLE:
            raise ValueError(f"Rule {self.id} has no tunable parameters")
        clone = copy.copy(self)
        if threshold is not None:
            object.__setattr__(clone, "THRESHOLD", int(threshold))
        if window_seconds is not None:
            object.__setattr__(clone, "WINDOW_SECONDS", int(window_seconds))
        return clone


def duration_text(seconds: int) -> str:
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute{'' if minutes == 1 else 's'}"
    return f"{seconds} seconds"


class BruteForceRule(RuleInfo):
    TUNABLE = ("threshold", "window_seconds")
    THRESHOLD = 5
    WINDOW_SECONDS = 600

    def __init__(self) -> None:
        super().__init__(
            id="AUTH-001",
            name="Repeated authentication failures",
            version=1,
            techniques=("T1110",),
            severity="MEDIUM",
            confidence=70,
            stage="Credential Access",
            description="At least 5 failed logins within a 10-minute sliding window for the same asset, user, "
            "source and source IP.",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        failures = [e for e in events if e.kind == "auth_failure"]
        detections = []
        for _, group in group_events(failures, lambda e: (e.asset, e.username, e.source, e.source_ip or "")):
            hits = sliding_window_hits(group, self.WINDOW_SECONDS, lambda w: len(w) >= self.THRESHOLD)
            if not hits:
                continue
            sample = group[0]
            ip = sample.source_ip or "an unknown IP"
            detections.append(
                build_detection(
                    self,
                    hits.values(),
                    make_group_key(asset=sample.asset, user=sample.username, source=sample.source, ip=sample.source_ip),
                    f"{len(hits)} failed logins for {sample.username} on {sample.asset} from {ip} "
                    f"within {duration_text(self.WINDOW_SECONDS)}",
                    {
                        "failures": len(hits),
                        "source_ip": sample.source_ip,
                        "threshold": self.THRESHOLD,
                        "window_seconds": self.WINDOW_SECONDS,
                    },
                )
            )
        return detections


class SuccessAfterFailuresRule(RuleInfo):
    TUNABLE = ("threshold", "window_seconds")
    THRESHOLD = 5
    WINDOW_SECONDS = 600

    def __init__(self) -> None:
        super().__init__(
            id="AUTH-002",
            name="Successful login after repeated failures",
            version=1,
            techniques=("T1078",),
            severity="HIGH",
            confidence=80,
            stage="Initial Access",
            description="A successful login preceded by at least 5 failures in the previous 10 minutes for the same "
            "asset, user, source and source IP.",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        auth = [e for e in events if e.kind in ("auth_failure", "auth_success")]
        detections = []
        for _, group in group_events(auth, lambda e: (e.asset, e.username, e.source, e.source_ip or "")):
            failures = [e for e in group if e.kind == "auth_failure"]
            evidence: dict[str, Event] = {}
            successes = 0
            for success in (e for e in group if e.kind == "auth_success"):
                prior = [
                    f
                    for f in failures
                    if f.ts <= success.ts and (success.ts - f.ts).total_seconds() <= self.WINDOW_SECONDS
                ]
                if len(prior) >= self.THRESHOLD:
                    successes += 1
                    evidence[success.id] = success
                    evidence.update({f.id: f for f in prior})
            if not successes:
                continue
            sample = group[0]
            detections.append(
                build_detection(
                    self,
                    evidence.values(),
                    make_group_key(asset=sample.asset, user=sample.username, source=sample.source, ip=sample.source_ip),
                    f"Successful login for {sample.username} on {sample.asset} after {len(evidence) - successes} "
                    f"failures from {sample.source_ip or 'an unknown IP'}",
                    {"successes": successes, "failures": len(evidence) - successes, "source_ip": sample.source_ip},
                )
            )
        return detections


_ENCODED_COMMAND = "encodedcommand"
_POWERSHELL = frozenset({"powershell", "pwsh"})
_PARAMETER_PREFIXES = ("-", "/", "–", "—", "―")  # PowerShell also accepts en/em dashes
_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')


def encoded_flag(token: str) -> str | None:
    """Return the flag if `token` is -e, -ec or any prefix of -EncodedCommand (with - or /)."""
    stripped = token.strip("\"'")
    if len(stripped) < 2 or not stripped.startswith(_PARAMETER_PREFIXES):
        return None
    name = stripped[1:].lower()
    if name == "ec" or _ENCODED_COMMAND.startswith(name):
        return stripped
    return None


def find_encoded_powershell(process_name: str | None, command_line: str | None) -> str | None:
    if not command_line:
        return None
    in_powershell = process_basename(process_name) in _POWERSHELL
    for token in _TOKEN_RE.findall(command_line):
        if process_basename(token) in _POWERSHELL:
            in_powershell = True
            continue
        if in_powershell:
            flag = encoded_flag(token)
            if flag:
                return flag
    return None


class EncodedPowerShellRule(RuleInfo):
    def __init__(self) -> None:
        super().__init__(
            id="PROC-001",
            name="Encoded PowerShell command",
            version=1,
            techniques=("T1059.001",),
            severity="HIGH",
            confidence=75,
            stage="Execution",
            description="PowerShell (powershell/pwsh, with or without .exe or a path) started with -e, -ec or any "
            "prefix of -EncodedCommand, using - or /. The encoded payload is never decoded or run.",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        matches: list[tuple[Event, str]] = []
        for event in events:
            if event.kind not in ("process_start", "suspicious_process"):
                continue
            flag = find_encoded_powershell(event.process_name, event.command_line)
            if flag:
                matches.append((event, flag))
        detections = []
        for _, group in group_events((e for e, _ in matches), lambda e: (e.asset, e.username)):
            flags = sorted({flag for e, flag in matches if e in group})
            sample = group[0]
            detections.append(
                build_detection(
                    self,
                    group,
                    make_group_key(asset=sample.asset, user=sample.username),
                    f"Encoded PowerShell ({', '.join(flags)}) run by {sample.username} on {sample.asset}"
                    + (f" ({len(group)} times)" if len(group) > 1 else ""),
                    {"flags": flags, "executions": len(group), "process": process_basename(sample.process_name)},
                )
            )
        return detections


class NetworkDiscoveryRule(RuleInfo):
    TUNABLE = ("threshold", "window_seconds")
    THRESHOLD = 10
    WINDOW_SECONDS = 300

    def __init__(self) -> None:
        super().__init__(
            id="NET-001",
            name="Possible network service discovery",
            version=1,
            techniques=("T1046",),
            severity="MEDIUM",
            confidence=65,
            stage="Discovery",
            description="At least 10 distinct destination IP:port pairs within 5 minutes for the same asset and user.",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        connections = [
            e for e in events if e.kind == "network_connection" and e.destination_ip and e.destination_port is not None
        ]
        detections = []
        for _, group in group_events(connections, lambda e: (e.asset, e.username)):

            def distinct(window: Sequence[Event]) -> bool:
                return len({(e.destination_ip, e.destination_port) for e in window}) >= self.THRESHOLD

            hits = sliding_window_hits(group, self.WINDOW_SECONDS, distinct)
            if not hits:
                continue
            targets = sorted({(e.destination_ip or "", e.destination_port or 0) for e in hits.values()})
            sources = sorted({e.source_ip for e in hits.values() if e.source_ip})
            sample = group[0]
            detections.append(
                build_detection(
                    self,
                    hits.values(),
                    make_group_key(asset=sample.asset, user=sample.username),
                    f"{len(targets)} distinct destination IP:port pairs contacted from {sample.asset} by "
                    f"{sample.username} within {duration_text(self.WINDOW_SECONDS)}",
                    {
                        "distinct_targets": len(targets),
                        "sample_targets": [f"{ip}:{port}" for ip, port in targets[:10]],
                        "ports": sorted({port for _, port in targets})[:20],
                        "source_ips": sources,
                        "threshold": self.THRESHOLD,
                        "window_seconds": self.WINDOW_SECONDS,
                    },
                )
            )
        return detections


class MassFileChangeRule(RuleInfo):
    TUNABLE = ("threshold", "window_seconds")
    THRESHOLD = 50
    WINDOW_SECONDS = 120

    def __init__(self) -> None:
        super().__init__(
            id="FILE-001",
            name="Mass file changes (possible ransomware)",
            version=1,
            techniques=("T1486",),
            severity="CRITICAL",
            confidence=80,
            stage="Impact",
            description="At least 50 file changes within 2 minutes on one asset.",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        changes = [e for e in events if e.kind == "file_change"]
        detections = []
        for _, group in group_events(changes, lambda e: e.asset):
            hits = sliding_window_hits(group, self.WINDOW_SECONDS, lambda w: len(w) >= self.THRESHOLD)
            if not hits:
                continue
            sample = group[0]
            paths = sorted({e.file_path or "" for e in hits.values()})
            detections.append(
                build_detection(
                    self,
                    hits.values(),
                    make_group_key(asset=sample.asset),
                    f"{len(hits)} file changes on {sample.asset} within {duration_text(self.WINDOW_SECONDS)}",
                    {
                        "changes": len(hits),
                        "sample_paths": paths[:5],
                        "threshold": self.THRESHOLD,
                        "window_seconds": self.WINDOW_SECONDS,
                    },
                )
            )
        return detections


class LogClearedRule(RuleInfo):
    def __init__(self, stage: str) -> None:
        super().__init__(
            id="LOG-001",
            name="Security log cleared",
            version=1,
            techniques=("T1685.005",),
            severity="HIGH",
            confidence=85,
            stage=stage,
            description="A security or audit log was cleared (ATT&CK T1685.005, formerly T1070.001).",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        cleared = [e for e in events if e.kind == "log_cleared"]
        return [
            build_detection(
                self,
                group,
                make_group_key(asset=group[0].asset, user=group[0].username),
                f"Security log cleared on {group[0].asset} by {group[0].username}"
                + (f" ({len(group)} times)" if len(group) > 1 else ""),
                {"clears": len(group)},
            )
            for _, group in group_events(cleared, lambda e: (e.asset, e.username))
        ]


class AccountChangeRule(RuleInfo):
    def __init__(self) -> None:
        super().__init__(
            id="ACCT-001",
            name="Account created or privileges changed",
            version=1,
            techniques=("T1136", "T1098"),
            severity="MEDIUM",
            confidence=60,
            stage="Persistence",
            description="A new user account was created (T1136) or account privileges changed (T1098).",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        detections = []
        for kind, technique, label in (
            ("user_created", "T1136", "New account created"),
            ("privilege_change", "T1098", "Account privileges changed"),
        ):
            matching = [e for e in events if e.kind == kind]
            for _, group in group_events(matching, lambda e: (e.asset, e.username)):
                sample = group[0]
                detections.append(
                    build_detection(
                        self,
                        group,
                        make_group_key(asset=sample.asset, user=sample.username, kind=kind),
                        f"{label} on {sample.asset} by {sample.username}"
                        + (f" ({len(group)} events)" if len(group) > 1 else ""),
                        {"kind": kind, "events": len(group)},
                        techniques=(technique,),
                    )
                )
        return detections


class PromptInjectionRule(RuleInfo):
    def __init__(self) -> None:
        super().__init__(
            id="INJ-001",
            name="Instruction-like text aimed at AI in event fields",
            version=1,
            techniques=(),
            severity="MEDIUM",
            confidence=90,
            stage="AI manipulation attempt",
            description="Event fields contain text that tries to instruct an AI assistant. The content is treated "
            "strictly as data and is never followed.",
        )

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        suspicious = [e for e in events if e.injection_suspected]
        detections = []
        for _, group in group_events(suspicious, lambda e: (e.asset, e.username)):
            patterns = sorted({name for e in group for name in e.injection_matches})
            sample = group[0]
            detections.append(
                build_detection(
                    self,
                    group,
                    make_group_key(asset=sample.asset, user=sample.username),
                    f"{len(group)} event(s) on {sample.asset} contain instruction-like text aimed at AI "
                    "(treated as data only)",
                    {"patterns": patterns, "events": len(group)},
                )
            )
        return detections


class SourceAlertRule(RuleInfo):
    def __init__(self, rule_id: str, kind: str, name: str, label: str) -> None:
        super().__init__(
            id=rule_id,
            name=name,
            version=1,
            techniques=(),
            severity="HIGH",
            confidence=50,
            stage="Source-reported alert",
            description=f"{label}. AEGIS does not verify the upstream verdict and never invents an ATT&CK mapping.",
        )
        self._kind = kind
        self._label = label

    def evaluate(self, events: Sequence[Event]) -> list[Detection]:
        matching = [e for e in events if e.kind == self._kind]
        return [
            build_detection(
                self,
                group,
                make_group_key(asset=group[0].asset, user=group[0].username),
                f"{self._label} on {group[0].asset} ({len(group)} report(s); unverified)",
                {"reports": len(group), "sources": sorted({e.source for e in group})},
            )
            for _, group in group_events(matching, lambda e: (e.asset, e.username))
        ]


def builtin_rules(log_cleared_stage: str) -> list[RuleInfo]:
    return [
        BruteForceRule(),
        SuccessAfterFailuresRule(),
        EncodedPowerShellRule(),
        NetworkDiscoveryRule(),
        MassFileChangeRule(),
        LogClearedRule(log_cleared_stage),
        AccountChangeRule(),
        PromptInjectionRule(),
        SourceAlertRule(
            "SOURCE-001",
            "suspicious_process",
            "Upstream suspicious process alert",
            "Upstream tool reported a suspicious process",
        ),
        SourceAlertRule(
            "SOURCE-002",
            "malicious_indicator",
            "Upstream malicious indicator alert",
            "Upstream tool reported a malicious indicator",
        ),
    ]
