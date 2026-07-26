set shell := ['/bin/zsh', '-eu', '-o', 'pipefail', '-c']

default:
    @just --list

# --- Dependencies ---

install: install-py install-web ## Install Python lab + browser demo dependencies

install-py: ## Create/refresh the uv environment
    uv sync

install-web: ## Install browser demo dependencies (pnpm)
    pnpm install

lock: ## Update the dependency lockfile
    uv lock

lock-check: ## Verify that uv.lock matches pyproject.toml
    uv lock --check

# --- Python lab ---

repetitions *args: ## Repeat both deterministic policies (default: 500 times)
    uv run segregation-repetitions {{args}}

test *args: ## Run Python unit tests (pass optional pytest arguments after --)
    uv run pytest -q {{args}}

demo: ## Run the deterministic, offline vulnerability demonstration
    uv run segregation-demo

demo-ogi: ## Run the OGI provenance + outbound email validation scenario
    uv run segregation-demo-ogi

demo-openrouter: ## Explicitly run against OpenRouter (may incur charges)
    uv run segregation-demo --openrouter

reproduce-vulnerability: ## Run only the documented intentional vulnerability test
    uv run pytest -q -m intentional_vulnerability

fmt: ## Format Python files with Ruff
    uv run ruff format .

lint: ## Lint Python files with Ruff
    uv run ruff check .

typecheck: ## Run strict static type checking
    uv run pyright

check: lock-check lint typecheck test ## Verify lockfile, style, types, and Python behavior

# --- Browser demo (GitHub Pages) ---

dev: ## Vite dev server — http://127.0.0.1:5174
    pnpm run dev -- --host 127.0.0.1 --strictPort

build: ## Production build → dist/
    pnpm run build

preview: build ## Build then serve production preview
    pnpm run preview -- --host 127.0.0.1 --strictPort

web-check: ## Type-check the browser demo
    pnpm run check

web-test: ## Browser demo unit tests
    pnpm test

verify: web-check web-test build ## Pre-push gate for browser demo

verify-all: check verify ## Full repo gate (Python lab + browser demo)

# --- Maintenance ---

clean: ## Remove generated local artifacts; source and lockfiles remain untouched
    rm -rf .venv .pytest_cache .ruff_cache build dist src/*.egg-info node_modules/.vite
    find . -type d -name __pycache__ -prune -exec rm -rf {} +
    @echo 'clean'
