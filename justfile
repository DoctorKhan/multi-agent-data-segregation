set shell := ['/bin/zsh', '-eu', '-o', 'pipefail', '-c']

# Environment and dependency maintenance.
help: ## Show available commands
	@just --list

install: ## Create/refresh the uv environment and install dependencies
	uv sync

lock: ## Update the dependency lockfile
	uv lock

lock-check: ## Verify that uv.lock matches pyproject.toml
	uv lock --check

# Educational entry points. Only demo-openrouter can make network model calls.
repetitions *args: ## Repeat both deterministic policies (default: 500 times)
	uv run segregation-repetitions {{args}}

test *args: ## Run unit tests (pass optional pytest arguments after --)
	uv run pytest -q {{args}}

demo: ## Run the deterministic, offline vulnerability demonstration
	uv run segregation-demo

demo-openrouter: ## Explicitly run against OpenRouter (may incur charges)
	uv run segregation-demo --openrouter

reproduce-vulnerability: ## Run only the documented intentional vulnerability test
	uv run pytest -q -m intentional_vulnerability

# Quality gates used locally and mirrored by GitHub Actions.
fmt: ## Format Python files with Ruff
	uv run ruff format .

lint: ## Lint Python files with Ruff
	uv run ruff check .

typecheck: ## Run strict static type checking
	uv run pyright

check: lock-check lint typecheck test ## Verify lockfile, style, types, and behavior

# Remove only generated local artifacts; source and lockfiles remain untouched.
clean: ## Remove the project environment and generated caches
	rm -rf .venv .pytest_cache .ruff_cache build dist src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	@echo 'clean'
