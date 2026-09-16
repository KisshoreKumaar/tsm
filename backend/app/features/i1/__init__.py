"""I1: CERT-In incident report drafts with provenance, deadline tracking and a human-only submission workflow."""

from app.core.features import FeatureSpec, JobKind, NavItem
from app.features.i1.router import router
from app.features.i1.service import REPORT_AUDIT_ACTIONS, agent_tools, run_narrative_job, setup

FEATURE = FeatureSpec(
    id="i1",
    name="CERT-In reports",
    description="Draft CERT-In incident reports from evidence, with deadlines, provenance and human approval",
    depends_on=("core", "f2"),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    jobs={"report.cert_in_narrative": JobKind(run_narrative_job, lane="ai")},
    audit_actions=REPORT_AUDIT_ACTIONS,
    nav=(NavItem(path="/compliance", label="Compliance", section="Compliance", order=10),),
)
