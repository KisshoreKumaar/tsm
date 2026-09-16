SHELL := /bin/bash
ROOT := $(CURDIR)
PY := $(ROOT)/.venv/bin/python
NPM := npm

.PHONY: help setup init-env token dev api web test test-backend test-frontend lint lint-backend lint-frontend \
	format eval demo seed build backup verify-audit checkpoint docker-build docker-up docker-down

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

setup: ## Create the venv and install pinned backend and frontend dependencies
	test -x $(PY) || python3 -m venv .venv
	$(PY) -m pip install -r backend/requirements-dev.txt
	cd frontend && $(NPM) ci

init-env: ## Generate .env with random tokens and keys
	$(PY) scripts/manage.py init-env

token: ## Print a token from .env (NAME=local-admin by default)
	@$(PY) scripts/manage.py token --name $(or $(NAME),local-admin)

api: ## Run the API on 127.0.0.1:8000
	cd backend && $(PY) -m uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8000

web: ## Run the Vite dev server on 127.0.0.1:5173
	cd frontend && $(NPM) run dev

dev: ## Run API and web together
	trap 'kill 0' EXIT; $(MAKE) api & $(MAKE) web & wait

test: test-backend test-frontend ## Run all tests

test-backend:
	cd backend && $(PY) -m pytest -q

test-frontend:
	cd frontend && $(NPM) test

lint: lint-backend lint-frontend ## Lint and type-check everything

lint-backend:
	cd backend && $(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy app

lint-frontend:
	cd frontend && $(NPM) run typecheck

format: ## Auto-format backend code
	cd backend && $(PY) -m ruff format . && $(PY) -m ruff check --fix .

eval: ## Run scenario evaluation (non-zero exit on regression)
	$(PY) scripts/evaluate.py

demo: ## Load a demo scenario into the local database (SCENARIO=attack-chain)
	$(PY) scripts/manage.py demo --scenario $(or $(SCENARIO),attack-chain)

seed: ## Fill the local database with synthetic walkthrough data
	$(PY) scripts/seed.py

build: ## Build the frontend for production
	cd frontend && $(NPM) run build

docker-build: ## Build the API and web images (unverified: never built on the dev machine)
	docker compose build

docker-up: ## Run the stack on http://127.0.0.1:8080 (needs .env)
	docker compose up -d

docker-down: ## Stop the stack
	docker compose down

backup: ## Consistent SQLite backup into backups/
	$(PY) scripts/manage.py backup --output backups/aegis-$$(date +%Y%m%d-%H%M%S).db

verify-audit: ## Verify the audit hash chain
	$(PY) scripts/manage.py verify-audit

checkpoint: ## Print the audit chain head for external retention
	$(PY) scripts/manage.py checkpoint
