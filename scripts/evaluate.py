#!/usr/bin/env python3
"""Scenario evaluation: runs every synthetic scenario and compares expected with actual outcomes.

Exits non-zero on any regression. Scenarios are registered from Phase 1 onward.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))


def main() -> int:
    try:
        from app.evaluation import run_evaluation  # type: ignore[import-not-found]
    except ImportError:
        print("AEGIS evaluation: no scenarios registered yet (Phase 1 adds them). Nothing to compare.")
        return 0
    return int(run_evaluation())


if __name__ == "__main__":
    raise SystemExit(main())
