"""F2: alert story — deterministic, chronological, cited narratives (AI polish arrives with the AI layer)."""

from app.core.features import FeatureSpec
from app.features.f2.router import router
from app.features.f2.service import setup

FEATURE = FeatureSpec(
    id="f2",
    name="Alert story",
    description="Chronological, cited incident and campaign stories in analyst and executive formats",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    audit_actions=frozenset({"story.generated"}),
)
