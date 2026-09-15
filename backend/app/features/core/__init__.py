"""CORE: platform routes (health, identity, audit, jobs, live stream). Always enabled."""

from app.core.features import FeatureSpec, NavItem
from app.features.core.router import router

FEATURE = FeatureSpec(
    id="core",
    name="Core platform",
    description="Identity, audit chain, jobs and live updates",
    always_on=True,
    router=router,
    nav=(NavItem(path="/overview", label="Overview", section="Operations", order=10),),
)
