"""X2: agent console — investigates across every enabled module and drafts proposals that a human applies."""

from app.core.features import FeatureSpec, JobKind, NavItem
from app.features.x2.router import router
from app.features.x2.service import agent_tools, run_agent_job, setup

FEATURE = FeatureSpec(
    id="x2",
    name="Agent console",
    description="Workspace agent with read tools across modules; proposed changes require human approval",
    depends_on=("core", "x1", "f3"),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    jobs={"agent.run": JobKind(run_agent_job, lane="ai")},
    audit_actions=frozenset(
        {"agent.proposal_created", "agent.proposal_applied", "agent.proposal_dismissed", "agent.proposal_stale"}
    ),
    nav=(NavItem(path="/agent/proposals", label="Agent proposals", section="AI", order=10),),
)
