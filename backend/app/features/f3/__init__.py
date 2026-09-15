"""F3: AI analyst — grounded Q&A per incident or campaign, quick and deep (read-only tool) modes."""

from app.core.features import FeatureSpec, JobKind
from app.features.f3.router import router
from app.features.f3.service import agent_tools, run_deep_job, run_quick_job, setup

FEATURE = FeatureSpec(
    id="f3",
    name="AI analyst",
    description="Ask grounded questions about incidents and campaigns; answers cite evidence and never change state",
    depends_on=("core", "x1"),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    jobs={"analyst.quick": JobKind(run_quick_job, lane="ai"), "analyst.deep": JobKind(run_deep_job, lane="ai")},
    audit_actions=frozenset({"chat.created", "chat.message_posted"}),
)
