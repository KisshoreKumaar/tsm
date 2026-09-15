# Adding a feature

Follow every step; the tests enforce most of them.

1. **Register the scope.** Add a row and an acceptance section to `docs/FEATURES.md` (ID, phase, status `planned`).
   Record non-obvious choices in `docs/DECISIONS.md`.
2. **Create the package** `backend/app/features/<id>/` with:
   - `__init__.py` exporting `FEATURE = FeatureSpec(...)`
   - `router.py` (use `app.core.routing.api_router()`), `service.py` (domain orchestration), `models.py`
     (Pydantic request/response models with `extra="forbid"`), `tests/__init__.py` and tests.
   Put reusable deterministic logic in the domain packages (`ingest/`, `detection/`, `correlation/`, …).
3. **Declare the spec.** In `FeatureSpec` set `id` (short, lowercase), `name`, `description`, `depends_on`, `router`,
   `jobs` (`{"<id>.<kind>": JobKind(handler, lane)}`), `audit_actions`, `agent_tools` (X2 read tools and proposal
   types) and `nav` entries (`NavItem(path, label, section, permission, order)`).
4. **Register it** in `backend/app/features/registry.py` after its dependencies. The flag is the feature id in
   `AEGIS_FEATURES`; `all` enables everything.
5. **Migration.** If you need tables, add the next `backend/migrations/NNNN_<id>_<what>.sql`. Never edit an applied
   migration.
6. **Permissions.** Every route depends on exactly one guard: `require(<permission>)` or `public()`. If you need a new
   permission, add it to `app/core/permissions.py`, assign roles, and update the permission matrix in `docs/DECISIONS.md`.
   `tests/core/test_rbac_matrix.py` covers new routes automatically.
7. **Audit.** Every state change calls `ctx.audit.append(session, action, actor, body, subject=...)` in the same
   write session. Declare each action name in `audit_actions`. Never include secrets.
8. **Jobs and live updates.** Enqueue with `ctx.jobs.enqueue(session, ...)`; use lane `ai` for LLM work. Publish
   ids-only live updates with `session.after_commit(lambda: ctx.bus.publish(...))`.
9. **AI tasks** (if any) live in `backend/app/ai/tasks/<task>.py` with a versioned prompt in `app/ai/prompts/`,
   an input builder with a token budget, a Pydantic output schema, citation validation and a deterministic fallback.
   Test with `FakeProvider` only.
10. **Agent tools (X2).** Register read tools with size-capped results. Proposal types must name the target action and
    permission; human-only actions (approve, execute, activate, finalize, settings) are never proposable.
11. **Frontend.** Add `frontend/src/features/<id>/` (pages, components, api helpers) and an entry in
    `frontend/src/featureManifest.ts` whose `id` matches the backend feature id. Navigation comes from the server manifest.
12. **Tests.** Unit tests for domain logic, API tests for routes (including 403 for missing permission), audit
    assertions for state changes, component tests for approval/citation UI. Run `make test lint eval`.
13. **Docs.** Update `docs/FEATURES.md` status, `docs/API.md` (Phase 7+), and `CLAUDE.md` if conventions changed. Commit.
