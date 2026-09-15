from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.features import FeatureConfigError, FeatureSpec, resolve_features
from app.features.core import FEATURE as CORE
from app.main import create_app
from tests.support import EXAMPLE_FEATURE, auth, make_settings


def test_all_features_enabled_by_default() -> None:
    enabled = resolve_features([CORE, EXAMPLE_FEATURE], None)
    assert enabled.ids == {"core", "example"}


def test_unknown_feature_id_is_rejected() -> None:
    with pytest.raises(FeatureConfigError, match="Unknown feature"):
        resolve_features([CORE], frozenset({"nope"}))


def test_missing_dependency_is_rejected() -> None:
    base = FeatureSpec(id="base", name="Base")
    child = FeatureSpec(id="child", name="Child", depends_on=("base",))
    with pytest.raises(FeatureConfigError, match="requires base"):
        resolve_features([base, child], frozenset({"child"}))


def test_always_on_features_are_included() -> None:
    enabled = resolve_features([CORE, EXAMPLE_FEATURE], frozenset({"example"}))
    assert "core" in enabled


def test_dependencies_are_ordered_first() -> None:
    child = FeatureSpec(id="child", name="Child", depends_on=("base",))
    base = FeatureSpec(id="base", name="Base")
    enabled = resolve_features([child, base], None)
    assert [spec.id for spec in enabled.specs] == ["base", "child"]


def test_circular_dependency_is_rejected() -> None:
    a = FeatureSpec(id="a", name="A", depends_on=("b",))
    b = FeatureSpec(id="b", name="B", depends_on=("a",))
    with pytest.raises(FeatureConfigError, match="Circular"):
        resolve_features([a, b], None)


def test_disabled_feature_routes_return_404(tmp_path: Path) -> None:
    disabled = create_app(
        make_settings(tmp_path / "off", features=frozenset({"core"})), features=(CORE, EXAMPLE_FEATURE)
    )
    enabled = create_app(make_settings(tmp_path / "on"), features=(CORE, EXAMPLE_FEATURE))
    with TestClient(disabled) as off, TestClient(enabled) as on:
        assert off.get("/api/example/ping", headers=auth("analyst")).status_code == 404
        assert on.get("/api/example/ping", headers=auth("analyst")).status_code == 200
        manifest_ids = {f["id"] for f in off.get("/api/me", headers=auth("analyst")).json()["features"]}
        assert manifest_ids == {"core"}


def test_manifest_hides_nav_items_without_permission(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path), features=(CORE, EXAMPLE_FEATURE))
    with TestClient(app) as client:
        ingest_nav = [n for f in client.get("/api/me", headers=auth("ingest")).json()["features"] for n in f["nav"]]
        viewer_nav = [n for f in client.get("/api/me", headers=auth("viewer")).json()["features"] for n in f["nav"]]
    assert ingest_nav == []
    assert {"/overview", "/incidents", "/example"} <= {n["path"] for n in viewer_nav}
