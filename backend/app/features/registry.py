"""Every feature available to this build, in dependency-friendly order. Flags select a subset."""

from __future__ import annotations

from app.core.features import FeatureSpec
from app.features.a3 import FEATURE as A3
from app.features.a5 import FEATURE as A5
from app.features.core import FEATURE as CORE
from app.features.f1 import FEATURE as F1
from app.features.f2 import FEATURE as F2
from app.features.f3 import FEATURE as F3
from app.features.f4 import FEATURE as F4
from app.features.x1 import FEATURE as X1
from app.features.x2 import FEATURE as X2

ALL_FEATURES: tuple[FeatureSpec, ...] = (CORE, F1, F2, F4, A3, A5, X1, F3, X2)
