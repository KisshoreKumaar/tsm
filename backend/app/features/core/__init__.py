"""CORE: ingestion, detection, incidents, simulated response, audit, demo scenarios. Always enabled."""

from app.core.features import FeatureSpec, JobKind, NavItem
from app.features.core.router import router
from app.features.core.setup import CORE_AUDIT_ACTIONS, release_demo_step, setup

FEATURE = FeatureSpec(
    id="core",
    name="Core platform",
    description="Ingestion, detection, incidents, simulated response and audit",
    always_on=True,
    router=router,
    jobs={"demo.release": JobKind(release_demo_step)},
    audit_actions=CORE_AUDIT_ACTIONS,
    on_startup=setup,
    nav=(
        NavItem(path="/overview", label="Overview", section="Operations", order=10),
        NavItem(path="/incidents", label="Incidents", section="Operations", order=20),
        NavItem(path="/events", label="Events", section="Operations", order=30),
        NavItem(path="/responses", label="Responses", section="Operations", order=40),
        NavItem(path="/demo", label="Demo scenarios", section="Operations", order=90),
        NavItem(path="/rules", label="Detection rules", section="Detection", order=10),
        NavItem(path="/audit", label="Audit trail", section="Governance", order=10),
    ),
)
