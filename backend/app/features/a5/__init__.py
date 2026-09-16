"""A5: learning from false positives — analytics, simulated tuning suggestions, approved suppressions with expiry."""

from app.core.features import FeatureSpec, JobKind, NavItem
from app.features.a5.router import router
from app.features.a5.service import (
    TUNING_AUDIT_ACTIONS,
    agent_tools,
    run_expire_job,
    run_generate_job,
    run_rank_job,
    setup,
)

FEATURE = FeatureSpec(
    id="a5",
    name="False-positive learning",
    description="False-positive analytics and human-approved, simulated, reversible tuning",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    jobs={
        "tuning.generate": JobKind(run_generate_job),
        "tuning.suppression_expire": JobKind(run_expire_job),
        "tuning.rank": JobKind(run_rank_job, lane="ai"),
    },
    audit_actions=TUNING_AUDIT_ACTIONS,
    nav=(NavItem(path="/tuning", label="Tuning", section="Detection", order=30),),
)
