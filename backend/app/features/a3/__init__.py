"""A3: AI detection engineer — custom DSL rules with backtests, a human-approved lifecycle and Sigma export."""

from app.core.features import FeatureSpec, JobKind, NavItem
from app.features.a3.router import router
from app.features.a3.service import RULE_AUDIT_ACTIONS, agent_tools, run_draft_job, setup

FEATURE = FeatureSpec(
    id="a3",
    name="Detection engineering",
    description="Draft, backtest, approve and activate custom detection rules",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    jobs={"rules.draft": JobKind(run_draft_job, lane="ai")},
    audit_actions=RULE_AUDIT_ACTIONS,
    nav=(NavItem(path="/detection-engineering", label="Detection engineering", section="Detection", order=20),),
)
