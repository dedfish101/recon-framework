#!/usr/bin/env bash
# =============================================================================
# entrypoint.sh — container entrypoint for the Recon Framework
#
# Modes:
#   (default)              -> launches the interactive Textual TUI
#   headless <domain>      -> runs the pipeline without a TUI, prints to stdout
#
# TARGET_DOMAIN / OUTPUT_DIR / SCAN_MODE env vars (or CLI args) configure
# the run. SUBFINDER_CHAOS_KEY / SUBFINDER_GITHUB_TOKEN / SUBFINDER_C99_KEY /
# SUBFINDER_DNSDUMPSTER_KEY, if set, are written into subfinder's own
# provider-config.yaml below — subfinder reads that file automatically and
# skips any source with no key configured, so this is safe to leave unset.
# =============================================================================
set -euo pipefail

mkdir -p "${OUTPUT_DIR:-/output}"

if [[ -n "${SUBFINDER_CHAOS_KEY:-}${SUBFINDER_GITHUB_TOKEN:-}${SUBFINDER_C99_KEY:-}${SUBFINDER_DNSDUMPSTER_KEY:-}" ]]; then
    mkdir -p "$HOME/.config/subfinder"
    {
        [[ -n "${SUBFINDER_CHAOS_KEY:-}" ]] && echo "chaos: [\"${SUBFINDER_CHAOS_KEY}\"]"
        [[ -n "${SUBFINDER_GITHUB_TOKEN:-}" ]] && echo "github: [\"${SUBFINDER_GITHUB_TOKEN}\"]"
        [[ -n "${SUBFINDER_C99_KEY:-}" ]] && echo "c99: [\"${SUBFINDER_C99_KEY}\"]"
        [[ -n "${SUBFINDER_DNSDUMPSTER_KEY:-}" ]] && echo "dnsdumpster: [\"${SUBFINDER_DNSDUMPSTER_KEY}\"]"
    } > "$HOME/.config/subfinder/provider-config.yaml"
fi

if [[ "${1:-}" == "headless" ]]; then
    shift
    exec python3 /app/recon_engine.py "$@" --output "${OUTPUT_DIR:-/output}"
else
    exec python3 /app/recon_tui.py "$@"
fi
