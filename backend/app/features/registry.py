"""Every feature available to this build, in dependency-friendly order. Flags select a subset."""

from __future__ import annotations

from app.core.features import FeatureSpec
from app.features.core import FEATURE as CORE

ALL_FEATURES: tuple[FeatureSpec, ...] = (CORE,)
