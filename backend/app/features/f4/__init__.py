"""F4: attack prediction — likely next attacker steps with a watchlist that detects when a prediction comes true."""

from app.core.features import FeatureSpec, JobKind, NavItem
from app.features.f4.router import router
from app.features.f4.service import agent_tools, run_expire_job, run_explain_job, setup

FEATURE = FeatureSpec(
    id="f4",
    name="Attack prediction",
    description="Likely next attacker steps from a curated ATT&CK transition model, watched until observed or expired",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    jobs={
        "prediction.expire": JobKind(run_expire_job),
        "prediction.explain": JobKind(run_explain_job, lane="ai"),
    },
    audit_actions=frozenset(
        {
            "prediction.created",
            "prediction.observed",
            "prediction.expired",
            "prediction.withdrawn",
            "prediction.explained",
        }
    ),
    nav=(NavItem(path="/predictions", label="Prediction watchlist", section="Investigation", order=30),),
)
