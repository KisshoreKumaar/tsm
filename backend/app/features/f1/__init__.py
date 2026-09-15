"""F1: alert correlation — campaigns, explained links, entity pivots and the correlation graph."""

from app.core.features import FeatureSpec, NavItem
from app.features.f1.router import router
from app.features.f1.service import setup

FEATURE = FeatureSpec(
    id="f1",
    name="Alert correlation",
    description="Campaigns of related incidents with explained links and a correlation graph",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    audit_actions=frozenset({"campaign.created", "campaign.updated", "campaign.merged", "campaign.dissolved"}),
    nav=(
        NavItem(path="/campaigns", label="Campaigns", section="Investigation", order=10),
        NavItem(path="/graph", label="Correlation graph", section="Investigation", order=20),
    ),
)
