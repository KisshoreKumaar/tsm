"""X1: LLM provider settings (UI API-key field), AI runtime, AI status and job streams."""

from app.core.features import FeatureSpec, NavItem
from app.core.permissions import LLM_CONFIGURE
from app.features.x1.router import router
from app.features.x1.service import agent_tools, setup

FEATURE = FeatureSpec(
    id="x1",
    name="AI providers",
    description="Configure LLM providers and API keys; AI runtime with validation, caching and fallback",
    depends_on=("core",),
    router=router,
    on_startup=setup,
    agent_tools=agent_tools,
    audit_actions=frozenset(
        {
            "ai.call",
            "llm.provider_created",
            "llm.provider_updated",
            "llm.provider_deleted",
            "llm.provider_key_set",
            "llm.provider_key_removed",
            "llm.provider_tested",
            "llm.active_changed",
        }
    ),
    nav=(
        NavItem(path="/ai/status", label="AI status", section="AI", order=90),
        NavItem(
            path="/settings/ai-providers", label="AI providers", section="Settings", permission=LLM_CONFIGURE, order=10
        ),
    ),
)
