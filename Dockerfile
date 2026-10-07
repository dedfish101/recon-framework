# =============================================================================
# Full-Spectrum Recon Framework — Dockerfile
# Multi-stage build: all compilers, headers, and Go module/build caches live
# only in the discarded "builder" stage. The final image contains just the
# stripped binaries and runtime libraries, which is what actually determines
# image size — a single-stage build was carrying ~10GB of build-only weight
# (full Go toolchain, Go module cache, build-essential, -dev headers, gem
# build artifacts) that a running container never needs.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: builder — compiles every tool, discarded after the final COPY
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

# The official golang image pins GOTOOLCHAIN=local, which blocks Go's
# normal auto-upgrade behavior. Several tools below (subfinder, nuclei)
# require a newer Go than 1.23; with GOTOOLCHAIN=auto, `go install` just
# downloads and uses whatever toolchain each module declares, transparently.
ENV GOTOOLCHAIN=auto

ENV DEBIAN_FRONTEND=noninteractive

# Build-only dependencies: compilers and -dev headers. None of this ships
# in the final image. libpcap-dev is needed to build naabu, which uses
# gopacket/cgo for raw packet capture during its SYN scan.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ruby ruby-dev \
        libyaml-dev zlib1g-dev libssl-dev libreadline-dev libffi-dev libgdbm-dev \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Go-based recon tools, built with -ldflags="-s -w" to strip debug symbols
# and the DWARF table — typically shrinks each binary by 25-40%.
# GOTOOLCHAIN=auto (the default) lets Go transparently download whatever
# newer toolchain a given module requires (e.g. nuclei currently needs
# go>=1.25) without us having to chase version numbers in this Dockerfile.
#
# amass was removed: it was consistently the slowest stage (900s timeout)
# for coverage bbot's passive subdomain-enum modules now provide instead.
RUN go install -ldflags="-s -w" github.com/tomnomnom/assetfinder@latest
RUN go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -ldflags="-s -w" github.com/lc/gau/v2/cmd/gau@latest
RUN go install -ldflags="-s -w" github.com/tomnomnom/waybackurls@latest
RUN go install -ldflags="-s -w" github.com/sensepost/gowitness@latest

# naabu — fast SYN-based port discovery (Stage 6). tlsx — TLS
# certificate SAN/CN scraping (Stage 7).
RUN go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -ldflags="-s -w" github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# gitleaks — offline secret scanner used in --no-git mode against local
# JS file caches (Stage 8 deep analysis). No native deps, pure Go.
RUN go install -ldflags="-s -w" github.com/zricethezav/gitleaks/v8@latest

# WhatWeb (Ruby). Gems land in /var/lib/gems/<ruby-version>/ via --system;
# we copy that whole tree into the runtime stage below.
RUN gem install bundler:2.4.22 && \
    git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && bundle install --system

# Belt-and-suspenders strip pass — a no-op for binaries already stripped by
# -ldflags, but some Go tools (naabu in particular pulls in libpcap via cgo)
# occasionally leave extra symbol data that -ldflags alone doesn't catch.
RUN strip --strip-all /go/bin/* 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2: runtime — slim Debian base + only what's needed to execute
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# Runtime-only libraries (no -dev headers, no compilers, no build tools).
# libyaml-0-2 / libssl3 / etc. are the shared libs WhatWeb's compiled gems
# link against — matching the -dev packages used at build time above.
# nmap is a system package (not a Go tool), used in Stage 6 for -sV
# service/version detection on ports naabu finds open. Its default SYN
# scan needs CAP_NET_RAW at `docker run` time — see README.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 python3-pip \
        ruby \
        nodejs npm \
        libyaml-0-2 libssl3 libreadline8 zlib1g libffi8 libgdbm6 \
        chromium \
        libpcap0.8 \
        nmap \
        jq \
    && rm -rf /var/lib/apt/lists/*

# gau prints a stderr notice on every run if $HOME/.gau.toml doesn't
# exist; _run_tool already isolates stderr from output files/logs (see
# recon_engine.py), but shipping an empty config removes the warning at
# the source too, rather than relying solely on the isolation fix.
RUN mkdir -p /root && touch /root/.gau.toml

# retire.js — static scanner that checks already-fetched JS file content
# against a database of known-vulnerable library signatures. Pure JS, no
# native deps, so it installs directly in the runtime stage. Like nuclei's
# templates above, its vulnerability DB (jsrepository.json) is fetched
# from retire.js's own GitHub repo on first scan rather than baked in, so
# it doesn't go stale — not a request to any scan target.
RUN npm install -g retire && npm cache clean --force

# Stripped Go binaries only — no Go toolchain, no module cache, no build
# cache. This one COPY replaces gigabytes of builder-stage weight.
COPY --from=builder /go/bin/* /usr/local/bin/

# WhatWeb script + its installed gems (must match the runtime Ruby version
# above, which it does since both stages are Debian bookworm).
COPY --from=builder /opt/whatweb /opt/whatweb
COPY --from=builder /var/lib/gems /var/lib/gems
RUN ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb /opt/whatweb/whatweb

# ---------------------------------------------------------------------------
# Python dependencies (TUI + orchestration engine)
# ---------------------------------------------------------------------------
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY recon_engine.py recon_tui.py entrypoint.sh vuln_version_db.json /app/
RUN chmod +x /app/entrypoint.sh

# Nuclei templates are deliberately NOT baked into the image. Vulnerability
# templates change daily; a stale baked-in copy is a liability for a
# security tool. nuclei auto-fetches them into ~/nuclei-templates on first
# run (a few seconds, a few dozen MB) and reuses that cache on subsequent
# runs as long as /root is persisted — see README for how to persist it.
#
# bbot (Stage 1, requirements.txt) behaves the same way: it downloads its
# own wordlists/config into ~/.bbot on first run rather than shipping them
# in the image. Its own Python dependency tree (dnspython, tldextract,
# pydantic, omegaconf, etc.) is a real, unavoidable addition to image size
# and `pip install` time, though — unlike the template caches, that part
# doesn't get smaller on a second run.

# ---------------------------------------------------------------------------
# Output volume — all artifacts land here, mounted from the host
# ---------------------------------------------------------------------------
RUN mkdir -p /output
VOLUME ["/output"]

ENTRYPOINT ["/app/entrypoint.sh"]