"""F2: alert story — deterministic, chronological, cited narratives, with validated AI polish when an LLM is enabled."""

from app.core.features import FeatureSpec, JobKind
from app.features.f2.router import router
from app.features.f2.service import run_polish_job, setup

FEATURE = FeatureSpec(
    id="f2",
    name="Alert story",
    description="Chronological, cited incident and campaign stories in analyst and executive formats",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    jobs={"story.polish": JobKind(run_polish_job, lane="ai")},
    audit_actions=frozenset({"story.generated"}),
)
