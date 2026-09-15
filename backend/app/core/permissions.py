"""Permission names and the role → permission matrix. Every API route declares exactly one of these."""

from __future__ import annotations

READ = "read"
INGEST = "ingest"
INVESTIGATE = "investigate"
AI_USE = "ai.use"
RESPOND_RECOMMEND = "respond.recommend"
RESPOND_APPROVE = "respond.approve"
RESPOND_EXECUTE = "respond.execute"
RULES_DRAFT = "rules.draft"
RULES_APPROVE = "rules.approve"
TUNING_DRAFT = "tuning.draft"
TUNING_APPROVE = "tuning.approve"
REPORTS_DRAFT = "reports.draft"
REPORTS_FINALIZE = "reports.finalize"
SETTINGS_MANAGE = "settings.manage"
LLM_CONFIGURE = "llm.configure"
AUDIT_EXPORT = "audit.export"

# Pseudo-permissions used by route guards.
AUTHENTICATED = "*authenticated"  # any valid identity, including the ingest role
PUBLIC = "*public"  # no credentials (health check only)

PERMISSIONS: frozenset[str] = frozenset(
    {
        READ,
        INGEST,
        INVESTIGATE,
        AI_USE,
        RESPOND_RECOMMEND,
        RESPOND_APPROVE,
        RESPOND_EXECUTE,
        RULES_DRAFT,
        RULES_APPROVE,
        TUNING_DRAFT,
        TUNING_APPROVE,
        REPORTS_DRAFT,
        REPORTS_FINALIZE,
        SETTINGS_MANAGE,
        LLM_CONFIGURE,
        AUDIT_EXPORT,
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({READ}),
    "ingest": frozenset({INGEST}),
    "analyst": frozenset({READ, INGEST, INVESTIGATE, AI_USE, RESPOND_RECOMMEND, REPORTS_DRAFT, TUNING_DRAFT}),
    "detection_engineer": frozenset({READ, AI_USE, RULES_DRAFT, TUNING_DRAFT}),
    "approver": frozenset({READ, RESPOND_APPROVE, RESPOND_EXECUTE, RULES_APPROVE, TUNING_APPROVE, REPORTS_FINALIZE}),
    "admin": PERMISSIONS,
}

ROLES: tuple[str, ...] = tuple(ROLE_PERMISSIONS)
