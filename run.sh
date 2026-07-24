#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

cmd="${1:-help}"
shift || true

case "$cmd" in
  help)
    cat <<'EOF'
Usage: ./run.sh <command>

  install   Install dependencies (pnpm)
  dev       Start Vite dev server for the live demo
  build     Production build to dist/
  preview   Build and serve production preview
  check     Type-check the browser demo
  test      Run browser demo unit tests
  verify    check + test + build
  clean     Remove build output and caches
EOF
    ;;
  install) pnpm install "$@" ;;
  dev) pnpm run dev -- --host 127.0.0.1 --strictPort "$@" ;;
  build) pnpm run build "$@" ;;
  preview) pnpm run build && pnpm run preview -- --host 127.0.0.1 --strictPort "$@" ;;
  check) pnpm run check "$@" ;;
  test) pnpm test "$@" ;;
  verify) pnpm run check && pnpm test && pnpm run build ;;
  clean) rm -rf dist node_modules/.vite ;;
  *) echo "Unknown command: $cmd" >&2; exit 1 ;;
esac
