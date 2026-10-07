# Full-Spectrum Recon Framework

A containerized, single-domain reconnaissance pipeline with a live
Terminal User Interface (TUI), built on industry-standard open-source
tooling: `assetfinder`, `subfinder`, `bbot`, `httpx`, `whatweb`, `gau`,
`waybackurls`, `naabu`, `nmap`, `tlsx`, `nuclei`, and `gowitness`.

> **Authorized use only.** This framework actively scans and fingerprints
> live infrastructure, port-scans it, and runs vulnerability templates
> against it. Only point it at domains and IPs you own or have explicit
> written authorization to test (e.g. an in-scope bug bounty program).
> Unauthorized scanning may be illegal in your jurisdiction.
>
> Port scanning and certificate recon (Stages 6-7) are deliberately kept
> **bounded to the exact IPs behind hosts already confirmed live** for the
> target domain — never a broader ASN/CIDR sweep. Stage 5's ASN/org lookups
> are informational only and are never auto-scanned; see
> [Network recon](#network-recon-bgp-asn-port-scanning-certificate-recon-stages-57)
> for why.

---

## Project structure

```
recon-framework/
├── Dockerfile          # Debian-slim base + Go/Python toolchains + all tools
├── requirements.txt    # Python deps for the TUI/engine
├── recon_engine.py     # Async pipeline: 10 discovery stages + 2 deep-mode stages
├── recon_tui.py        # Textual dashboard UI
├── entrypoint.sh        # Container entrypoint (TUI, headless mode, subfinder key config)
├── vuln_version_db.json # Editable tech -> fixed-version/advisory DB (Stage 9)
└── README.md
```

## Pipeline stages

Every scan runs a **single domain** through the pipeline below. Stages
1–10 ("Discovery") always run; stages 11–12 ("Deep Analysis") only run in
**deep mode** — a heavier, single-priority-target pass, not meant for
wildcard sweeps. See [Scan modes](#scan-modes-quick-vs-deep) below for
how to select it. Certificate recon (Stage 7) runs *before* vulnscan/
tech-audit/attack-surface (8–10) so that any new in-scope subdomains it
discovers get picked up by those stages automatically, in the same run.

| # | Stage                        | Tools                         | Output files |
|---|-------------------------------|--------------------------------|---------------|
| 1 | Subdomain Discovery            | assetfinder, subfinder, bbot | `subdomains.txt` |
| 2 | Probing & Fingerprinting       | httpx, whatweb                | `live_targets.json`, `tech_stack.json` |
| 3 | URL / Archive Scraping         | gau, waybackurls               | `all_urls.txt`, `js_files.txt`, `sensitive_urls.json` |
| 4 | Visual Recon                   | gowitness (headless Chromium) | `screenshots/*.png` |
| 5 | BGP / ASN Lookup                | ipwhois (RDAP), Wikidata — informational only | `asn_info.json`, `related_organizations.json` |
| 6 | Port Scanning                   | naabu, nmap — live-host IPs only | `open_ports.txt` |
| 7 | Certificate Recon               | tlsx (SAN/CN)                  | `cert_findings.json` |
| 8 | Vulnerability Scanning         | nuclei (tag-scoped by tech)   | `vulnerabilities.json` |
| 9 | JS & Tech Audit                 | retire.js, local version DB   | `tech_audit.json` |
| 10 | Attack Surface Categorization   | param/path/extension pattern matching | `categorized_urls/` (see below) |

**Deep mode only** (stages 11–12, appended after stage 10):

| # | Stage                     | Tools                      | Output files |
|---|----------------------------|------------------------------|---------------|
| 11 | Deep JS / API Intelligence  | endpoint regex, gitleaks    | `deep_analysis/js_endpoints.json`, `deep_analysis/secrets_findings.json` |
| 12 | Deep Parameter Map          | full param-name inventory   | `deep_analysis/parameter_inventory.json` |

Every stage is fault-isolated: if a tool times out or exits non-zero, the
error is logged to `errors` in `summary.json` and the pipeline continues
using whatever partial data the earlier tools produced. Raw, per-tool
output is preserved under `raw/` for auditing.

## Scan modes: quick vs. deep

| Mode | Stages | Meant for |
|---|---|---|
| `quick` (default) | 1–10 | Fast baseline pass, safe to run against a wildcard's whole subdomain set |
| `deep` | 1–12 | One priority target you want to dig into further — extra JS endpoint/secret extraction and a full query-parameter inventory |

How to select it:

- **In the TUI**, type the domain at the prompt with an optional second
  word: `example.com` (quick) or `example.com deep`.
- **Headless / CLI**: `python3 recon_engine.py example.com --mode deep`
  (or via Docker: `... headless example.com --mode deep`).
- **Env var**: set `SCAN_MODE=deep` alongside `TARGET_DOMAIN` when
  launching the TUI non-interactively.

## Network recon: BGP/ASN, port scanning, certificate recon (Stages 5-7)

These three stages widen discovery beyond DNS/HTTP, but their scope is
deliberately constrained:

- **Stage 5 (BGP/ASN Lookup)** is 100% informational. For every unique IP
  behind a Stage 2 live target, it runs an RDAP lookup (via the `ipwhois`
  package) for ASN/CIDR/org name, then a best-effort Wikidata lookup for
  parent-organization/subsidiary relationships and their official
  websites. **Nothing this stage finds is ever merged into the scan's
  subdomain set or scanned automatically** — a discovered sibling domain
  or ASN is a lead for a human to follow up on with its own, separately
  authorized engagement, not something this run pivots into. Output:
  `asn_info.json`, `related_organizations.json`.
- **Stage 6 (Port Scanning)** targets *only* the exact IPs behind Stage
  2's confirmed live targets — never the CIDR blocks Stage 5 identified.
  Scanning a whole ASN is usually scanning infrastructure that isn't the
  target at all (shared-hosting ASNs like AWS or Cloudflare host
  thousands of unrelated tenants on the same block) and is almost never
  actually in scope for a bug-bounty engagement. `naabu` does a fast
  top-1000-port SYN sweep first; `nmap -sV --open` then runs version
  detection scoped to whatever naabu found open, which is far faster than
  nmap re-probing 1000 ports itself. If naabu is unavailable, nmap falls
  back to doing the full top-1000 sweep alone. Output: `open_ports.txt`,
  `raw/nmap_ports.{nmap,xml,gnmap}`.
- **Stage 7 (Certificate Recon)** runs `tlsx -san -cn` against those same
  live-host IPs on whatever ports Stage 6 found open (falling back to
  `:443` if Stage 6 found nothing). Discovered SAN/CN hostnames are
  filtered to the **same apex domain** before being added to
  `subdomains.txt` — a shared/CDN certificate's SAN list can legitimately
  include unrelated customer domains, and those must never be silently
  pulled into scope. In-scope new hostnames get one incremental `httpx`
  probe so they appear in `live_targets.json` for *this* run, which is
  what lets Stages 8–10 (running immediately after) pick them up
  automatically — full URL-scraping treatment of a newly discovered host
  is left for a deliberate follow-up run. Output: `cert_findings.json`.

**naabu and nmap's default scan mode needs `CAP_NET_RAW`** — add
`--cap-add=NET_RAW` to your `docker run` command (see the examples
below). Without it, Stage 6 will log a permission error and continue with
whatever partial data it has, same as any other best-effort tool failure
in this pipeline — it won't crash the run.

**Subfinder provider credentials** (used by Stage 1, and unrelated to
Stages 5-7 above but configured the same way — via env vars, never baked
into the image): set any of `SUBFINDER_CHAOS_KEY`, `SUBFINDER_GITHUB_TOKEN`,
`SUBFINDER_C99_KEY`, `SUBFINDER_DNSDUMPSTER_KEY` at `docker run` time and
`entrypoint.sh` writes them into subfinder's own
`~/.config/subfinder/provider-config.yaml` before the pipeline starts.
Sources with no key configured are skipped by subfinder itself — safe to
leave any or all of these unset.

## Attack surface categorization (Stage 10)

Every URL collected in Stage 3 is triaged into likely-vulnerability-class
buckets along **three independent axes**, since each catches URLs the
others miss — a param-only view misses a bare `/admin/` with no query
string; a path-only view misses `?redirect=`. This is 100% local pattern
matching: no requests are made, no payloads are injected, and it's a
starting point for manual review, not a confirmed finding.

| Axis | Categories | Written to |
|---|---|---|
| **By query parameter** | `sqli`, `xss`, `ssrf`, `sensitive` | `categorized_urls/<category>.txt` |
| **By URL path**          | `admin_panels`, `api_endpoints`, `auth_endpoints`, `file_uploads`, `internal_tools`, `vcs_exposure` | `categorized_urls/by_path/<category>.txt` |
| **By file extension**    | `config_files`, `backup_files`, `archive_files`, `database_files`, `log_files` | `categorized_urls/by_extension/<category>.txt` |

A separate, narrower filter runs in **Stage 3**: `sensitive_urls.json`
flags query params that look like identifiers, auth tokens, secrets, or
session IDs (`identifiers`/`tokens`/`auth_secrets`/`session`) — useful
for spotting IDOR/leak candidates as soon as URLs are collected, before
Stage 10's broader triage runs.

A URL can land in multiple categories on the same axis (e.g.
`?id=1&token=abc` matches both `sqli` and `sensitive`). All three
pattern maps live in `recon_engine.py` — see
[Extending the framework](#extending-the-framework) to add more
categories.

## Image size

The Dockerfile is a **multi-stage build**: a `builder` stage compiles every
tool with the full Go toolchain, `build-essential`, and Ruby's `-dev`
headers, and a separate `runtime` stage copies in only the compiled,
stripped binaries plus the shared libraries they need at execution time.
None of the Go module cache, build cache, compilers, or headers make it
into the final image.

Expect roughly **1.5–2.5 GB** for the final `runtime` image — chromium is
the single largest piece (~350–450 MB) since it's a full browser, not a
small binary. If you built an earlier single-stage version of this
Dockerfile, that image was carrying its entire build toolchain permanently
(~10+ GB in Go's module/build cache alone, largely from nuclei's
dependency tree pulling in AWS SDK, Azure SDK, and a few other heavy
libraries). Remove it and reclaim the space:

```bash
docker image rm recon-framework:latest   # or the old image ID
docker builder prune                     # clears cached build layers too
```

Nuclei's vulnerability templates are deliberately **not** baked into the
image — they change daily, and shipping a stale copy in a security tool is
a liability. Instead, nuclei fetches them into `~/nuclei-templates` inside
the container on first run (a few seconds, a few dozen MB). If you want
that fetch to persist across container runs instead of repeating every
time, mount a volume for it:

```bash
docker run -it --rm \
  --cap-add=NET_RAW \
  -v "$(pwd)/output:/output" \
  -v recon-nuclei-templates:/root/nuclei-templates \
  recon-framework:latest example.com
```

(`--cap-add=NET_RAW` is required for Stage 6's naabu/nmap SYN scans — see
[Network recon](#network-recon-bgp-asn-port-scanning-certificate-recon-stages-57).)

---

## 1. Build the image

```bash
git clone <this-repo> recon-framework
cd recon-framework
docker build -t recon-framework:latest .
```

The build compiles all Go-based tools from source and installs WhatWeb via
Ruby/bundler, so the first build takes several minutes. Subsequent builds
are cached by Docker layer.

## 2. Run it (interactive TUI, output on your host)

Mount a host directory to `/output` so scan results survive after the
container exits:

```bash
docker run -it --rm \
  --cap-add=NET_RAW \
  -v "$(pwd)/output:/output" \
  --name recon \
  recon-framework:latest example.com
```

- `--cap-add=NET_RAW` lets Stage 6 (naabu/nmap) run its default fast SYN
  scan. Omitting it doesn't crash the run — that stage just logs a
  permission error and continues with whatever partial data it has, same
  as any other best-effort tool failure — but you'll get better port
  coverage with it.
- `-it` gives you the interactive TUI.
- `-v $(pwd)/output:/output` persists every artifact (subdomains,
  screenshots, JSON reports) to `./output/example.com/` on your host.
- If you omit the domain argument, the TUI will prompt you for one on
  the dashboard itself — type `example.com` for a quick scan, or
  `example.com deep` for the deep-mode single-target pass (see
  [Scan modes](#scan-modes-quick-vs-deep)).
- To pass the domain (and optionally mode) as CLI args instead of typing
  them at the prompt:

  ```bash
  docker run -it --rm \
    --cap-add=NET_RAW \
    -v "$(pwd)/output:/output" \
    --name recon \
    recon-framework:latest example.com deep
  ```

### Keybindings inside the TUI

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| `r` | Restart the scan (only when idle) |

---

## 3. Run it detached, then attach later

The TUI runs fine as the container's foreground process even when you
start the container detached — you're just not watching it live until
you reconnect:

```bash
# Start detached
docker run -d \
  --cap-add=NET_RAW \
  -v "$(pwd)/output:/output" \
  --name recon \
  recon-framework:latest example.com

# ... come back later and reattach to the live TUI ...
docker attach recon
```

**Detaching without killing the process:** once attached, press
`Ctrl+P` then `Ctrl+Q` (the standard Docker detach sequence) to leave the
TUI running in the background and return to your host shell. Plain
`Ctrl+C` will send SIGINT to the TUI and stop it — use the detach
sequence instead if you want it to keep running.

Alternatively, open a second window onto the same running container
without disturbing the primary TTY:

```bash
docker exec -it recon bash
# then inspect /output directly, tail logs, etc.
```

---

## 4. Headless / scripted mode (no TUI)

For CI pipelines or scheduled scans where you just want the artifacts:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  -v "$(pwd)/output:/output" \
  recon-framework:latest headless example.com --mode deep
```

This prints structured progress lines to stdout and exits when the
pipeline finishes — no interactive terminal required. Drop `--mode deep`
for the default quick (stages 1–10) run.

---

## 5. Output layout

```
output/
└── example.com/
    ├── subdomains.txt
    ├── live_targets.json
    ├── active_targets.json
    ├── forbidden_403.json
    ├── unreachable_targets.json       # only written if any DNS/timeout failures occurred
    ├── tech_stack.json
    ├── all_urls.txt
    ├── js_files.txt
    ├── sensitive_urls.json
    ├── asn_info.json                   # informational only, Stage 5 — never auto-scanned
    ├── related_organizations.json      # informational only, Stage 5 — never auto-scanned
    ├── open_ports.txt                  # ip:port lines, Stage 6
    ├── cert_findings.json              # Stage 7
    ├── nuclei_targets.txt
    ├── vulnerabilities.json
    ├── tech_audit.json
    ├── categorized_urls/
    │   ├── sqli.txt
    │   ├── xss.txt
    │   ├── ssrf.txt
    │   ├── sensitive.txt
    │   ├── by_path/
    │   │   ├── admin_panels.txt
    │   │   ├── api_endpoints.txt
    │   │   ├── auth_endpoints.txt
    │   │   ├── file_uploads.txt
    │   │   ├── internal_tools.txt
    │   │   └── vcs_exposure.txt
    │   └── by_extension/
    │       ├── config_files.txt
    │       ├── backup_files.txt
    │       ├── archive_files.txt
    │       ├── database_files.txt
    │       └── log_files.txt
    ├── deep_analysis/                 # only present after a mode="deep" run
    │   ├── js_endpoints.json
    │   ├── secrets_findings.json
    │   └── parameter_inventory.json
    ├── summary.json
    ├── live_urls_for_screenshots.txt
    ├── screenshots/
    │   └── *.png
    └── raw/
        ├── assetfinder.txt
        ├── subfinder.txt
        ├── bbot/scan/subdomains.txt   # bbot writes its own results file, not captured stdout
        ├── httpx.jsonl
        ├── live_urls.txt
        ├── whatweb.json
        ├── gau.txt
        ├── waybackurls.txt
        ├── port_scan_targets.txt
        ├── naabu.jsonl
        ├── nmap_ports.{nmap,xml,gnmap}
        ├── cert_targets.txt
        ├── tlsx.jsonl
        ├── cert_new_hosts.txt         # only written if cert recon found new in-scope subdomains
        ├── httpx_cert_incremental.jsonl
        ├── nuclei.jsonl
        ├── js_cache/*.js              # bounded local cache of downloaded JS assets
        ├── retire.json
        └── gitleaks.json              # only present after a mode="deep" run
```

`summary.json` is the single source of truth for a run — final counts per
stage plus every error/timeout encountered along the way.

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `TARGET_DOMAIN` | — | Alternative to passing the domain as a CLI arg |
| `SCAN_MODE` | `quick` | `quick` or `deep` — alternative to appending `deep` after the domain (TUI) or passing `--mode deep` (headless) |
| `OUTPUT_DIR` | `/output` | Where results are written inside the container |
| `SUBFINDER_CHAOS_KEY` | — | Subfinder's Chaos source API key |
| `SUBFINDER_GITHUB_TOKEN` | — | Subfinder's GitHub source token |
| `SUBFINDER_C99_KEY` | — | Subfinder's C99 source API key |
| `SUBFINDER_DNSDUMPSTER_KEY` | — | Subfinder's DNSDumpster source API key |

All four `SUBFINDER_*` vars are optional — leave any unset and subfinder
skips that source. See
[Network recon](#network-recon-bgp-asn-port-scanning-certificate-recon-stages-57)
for how they're wired in.

Per-tool timeouts are defined in `ReconEngine.TIMEOUTS` in
`recon_engine.py` — tune these if you're scanning very large attack
surfaces (bbot's passive subdomain-enum modules and nmap's version
detection are usually the slowest stages on a big target).

## Extending the framework

- **Add a tool:** write a new `stageN_*` method on `ReconEngine`, wire it
  into `run_full_pipeline`, and add a matching row to `DISCOVERY_STAGES`
  (or `DEEP_STAGES`, for a deep-mode-only addition) in `recon_tui.py`.
- **Change nuclei scope:** edit `tag_map` in `stage8_vulnerability_scan`
  to map more fingerprinted technologies to nuclei tags.
- **Add or refine attack-surface categories:** edit the pattern maps
  used by Stage 10 — `ATTACK_SURFACE_PATTERNS` (query-parameter names),
  `PATH_SURFACE_PATTERNS` (URL path segments), or
  `EXTENSION_SURFACE_PATTERNS` (file extensions) — all three live near
  the top of `recon_engine.py`. Each is a plain `{category: regex}`
  dict; adding a key adds an output file under `categorized_urls/`
  automatically, no other code changes needed.
- **Widen the outdated-tech check:** `vuln_version_db.json` at the
  project root maps `technology -> {fixed_in, advisory}`; replace it
  with a fuller export (e.g. from OSV/NVD) to broaden Stage 9 without
  touching code.
- **Widen or narrow port-scan/cert-recon scope:** both stay bounded to
  Stage 2's live-host IPs by design (see
  [Network recon](#network-recon-bgp-asn-port-scanning-certificate-recon-stages-57)
  for why a broader ASN/CIDR sweep is deliberately not the default). If a
  specific engagement has genuinely authorized a wider scope, that's a
  deliberate edit to `stage6_port_scanning`'s target-list construction,
  not a config flag — keep it a conscious code change, not something a
  stray env var could silently widen.
- **Swap in aquatone instead of gowitness:** replace the command in
  `stage4_visual_recon` — the rest of the pipeline doesn't depend on
  which screenshot tool is used, only on `screenshots/*.png` existing.
