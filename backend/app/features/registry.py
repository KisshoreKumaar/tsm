"""Every feature available to this build, in dependency-friendly order. Flags select a subset."""

from __future__ import annotations

from app.core.features import FeatureSpec
from app.features.core import FEATURE as CORE
from app.features.f1 import FEATURE as F1
from app.features.f2 import FEATURE as F2

ALL_FEATURES: tuple[FeatureSpec, ...] = (CORE, F1, F2)
