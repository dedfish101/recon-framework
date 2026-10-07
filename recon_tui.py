"""
recon_tui.py
============
Interactive Terminal User Interface for the Full-Spectrum Recon Framework,
built on Textual.

Layout:
    ┌─────────────────────────────────────────────────────────┐
    │ Header: target domain + elapsed time                     │
    ├───────────────────────────┬───────────────────────────────┤
    │ Stage pipeline (10 rows,  │  Stats panel                 │
    │ 12 in deep mode; each with│  (subdomains, live, urls,    │
    │ a spinner/state)          │   attack surface, vulns, ...) │
    ├───────────────────────────┴───────────────────────────────┤
    │ Scrolling log view (stdout/stderr of the active tool)    │
    ├─────────────────────────────────────────────────────────┤
    │ Footer: keybindings                                       │
    └─────────────────────────────────────────────────────────┘

Target domain is entered as "example.com" (quick mode, the default) or
"example.com deep" (adds stages 11-12, a heavier single-target JS/API/
secret-scanning pass) — either at the on-screen prompt, or via
TARGET_DOMAIN/SCAN_MODE env vars / CLI args when launched non-interactively.

Run inside the container (see entrypoint.sh); works whether attached
interactively (`docker run -it`) or detached (`docker run -d`) — in the
latter case, `docker attach` or `docker exec -it <id> ...` connects back
to this same running TUI process.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

from recon_engine import ReconEngine, ReconStats

# Discovery stages (1-10) always run, in this order, on every scan.
DISCOVERY_STAGES = [
    ("subdomains", "Subdomain Discovery", "assetfinder · subfinder · bbot"),
    ("probing", "Probing & Fingerprinting", "httpx · whatweb"),
    ("urls", "URL / Archive Scraping", "gau · waybackurls"),
    ("screenshots", "Visual Recon", "gowitness"),
    ("bgp_asn", "BGP / ASN Lookup", "ipwhois · wikidata (informational)"),
    ("port_scan", "Port Scanning", "naabu · nmap"),
    ("cert_recon", "Certificate Recon", "tlsx (SAN/CN)"),
    ("vulnscan", "Vulnerability Scanning", "nuclei"),
    ("tech_audit", "JS & Tech Audit", "retire.js · version DB"),
    ("attack_surface", "Attack Surface Triage", "param · path · extension"),
]

# Deep-analysis stages (11-12) only run when mode="deep" — a heavier,
# single-priority-target pass appended after the discovery stages.
DEEP_STAGES = [
    ("deep_js", "Deep JS / API Intel", "endpoint regex · gitleaks"),
    ("deep_params", "Deep Parameter Map", "full param inventory"),
]

STATUS_ICON = {
    "pending": "○",
    "running": "◐",
    "ok": "●",
    "warn": "▲",
    "error": "✕",
    "done": "●",
}

STATUS_COLOR = {
    "pending": "grey50",
    "running": "yellow",
    "ok": "green",
    "warn": "orange3",
    "error": "red",
    "done": "green",
}


class StageRow(Static):
    """A single pipeline stage row: icon + name + status message."""

    status: reactive[str] = reactive("pending")
    message: reactive[str] = reactive("")

    def __init__(self, key: str, title: str, subtitle: str):
        super().__init__()
        self.key = key
        self.title = title
        self.subtitle = subtitle

    def render(self) -> Text:
        icon = STATUS_ICON.get(self.status, "○")
        color = STATUS_COLOR.get(self.status, "grey50")
        text = Text()
        text.append(f" {icon} ", style=f"bold {color}")
        text.append(f"{self.title:28}", style=f"bold {color}" if self.status == "running" else "white")
        text.append(f" {self.subtitle}\n", style="dim")
        if self.message:
            text.append(f"     └─ {self.message}", style=color)
        return text


class StatsPanel(Static):
    """Right-hand panel showing live-updating recon counters."""

    mode: reactive[str] = reactive("quick")

    subdomains: reactive[int] = reactive(0)
    live: reactive[int] = reactive(0)
    forbidden_403: reactive[int] = reactive(0)
    urls: reactive[int] = reactive(0)
    sensitive_urls: reactive[int] = reactive(0)
    screenshots: reactive[int] = reactive(0)
    vulns: reactive[int] = reactive(0)
    js_vulns: reactive[int] = reactive(0)
    outdated_tech: reactive[int] = reactive(0)
    surface_by_param: reactive[int] = reactive(0)
    surface_by_path: reactive[int] = reactive(0)
    surface_by_ext: reactive[int] = reactive(0)
    asns_found: reactive[int] = reactive(0)
    related_orgs: reactive[int] = reactive(0)
    hosts_with_open_ports: reactive[int] = reactive(0)
    open_ports_found: reactive[int] = reactive(0)
    cert_new_subdomains: reactive[int] = reactive(0)
    js_endpoints: reactive[int] = reactive(0)
    secrets: reactive[int] = reactive(0)
    unique_params: reactive[int] = reactive(0)
    errors: reactive[int] = reactive(0)

    def render(self) -> Text:
        text = Text()
        rows = [
            ("Unique Subdomains", self.subdomains, "cyan"),
            ("Live Targets", self.live, "green"),
            ("  └─ Forbidden (403)", self.forbidden_403, "orange3" if self.forbidden_403 else "white"),
            ("URLs / Endpoints", self.urls, "magenta"),
            ("  └─ Sensitive Params", self.sensitive_urls, "orange3" if self.sensitive_urls else "white"),
            ("Screenshots Taken", self.screenshots, "blue"),
            ("Vulnerabilities Found", self.vulns, "red" if self.vulns else "white"),
            ("JS Library Issues", self.js_vulns, "red" if self.js_vulns else "white"),
            ("Outdated Tech", self.outdated_tech, "orange3" if self.outdated_tech else "white"),
        ]
        text.append(" STATISTICS\n\n", style="bold underline")
        for label, value, color in rows:
            text.append(f" {label:24}", style="white")
            text.append(f"{value:>6}\n", style=f"bold {color}")

        text.append("\n ATTACK SURFACE (by axis)\n\n", style="bold underline")
        for label, value in [
            ("  by parameter", self.surface_by_param),
            ("  by path", self.surface_by_path),
            ("  by extension", self.surface_by_ext),
        ]:
            text.append(f" {label:24}", style="white")
            text.append(f"{value:>6}\n", style="bold yellow" if value else "white")

        text.append("\n NETWORK / CERT RECON\n\n", style="bold underline")
        for label, value, color in [
            ("ASNs Identified", self.asns_found, "cyan"),
            ("Related Orgs (info only)", self.related_orgs, "white"),
            ("Hosts w/ Open Ports", self.hosts_with_open_ports, "cyan"),
            ("Open Ports Found", self.open_ports_found, "cyan"),
            ("New Subdomains (cert)", self.cert_new_subdomains, "yellow" if self.cert_new_subdomains else "white"),
        ]:
            text.append(f" {label:24}", style="white")
            text.append(f"{value:>6}\n", style=f"bold {color}")

        if self.mode == "deep":
            text.append("\n DEEP ANALYSIS\n\n", style="bold underline")
            for label, value, color in [
                ("JS Endpoints Found", self.js_endpoints, "cyan"),
                ("Potential Secrets", self.secrets, "red" if self.secrets else "white"),
                ("Unique Param Names", self.unique_params, "magenta"),
            ]:
                text.append(f" {label:24}", style="white")
                text.append(f"{value:>6}\n", style=f"bold {color}")

        text.append("\n", style="white")
        text.append(f" {'Errors / Warnings':24}", style="white")
        text.append(f"{self.errors:>6}\n", style="bold orange3" if self.errors else "bold white")
        return text


class ReconApp(App):
    """Main Textual application driving the recon pipeline end to end."""

    CSS = """
    Screen {
        background: $surface;
    }
    #body {
        height: 1fr;
    }
    #pipeline {
        width: 2fr;
        border: round $primary;
        padding: 1 2;
        overflow-y: auto;
    }
    #stats {
        width: 1fr;
        border: round $accent;
        padding: 1 2;
        overflow-y: auto;
    }
    #logpanel {
        height: 14;
        border: round $secondary;
    }
    #domain_input_row {
        height: 3;
        padding: 0 1;
    }
    StageRow {
        height: 3;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "restart", "Restart scan"),
        ("ctrl+c", "quit", "Quit"),
    ]

    TITLE = "Full-Spectrum Recon Framework"

    def __init__(self, domain: str | None, output_root: str, mode: str = "quick"):
        super().__init__()
        self.domain = domain
        self.output_root = Path(output_root)
        self.mode = mode if mode in ReconEngine.MODES else "quick"
        self.start_time = time.monotonic()
        self.stage_rows: dict[str, StageRow] = {}
        self._engine: ReconEngine | None = None
        self._run_task: asyncio.Task | None = None

    # ------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        if not self.domain:
            with Horizontal(id="domain_input_row"):
                yield Label("Target: ")
                yield Input(
                    placeholder="example.com  (add 'deep' for a single-target deep scan)",
                    id="domain_input",
                )

        with Horizontal(id="body"):
            with Vertical(id="pipeline"):
                yield Label("RECON PIPELINE", classes="panel-title")
                for key, title, subtitle in self._active_stages():
                    row = StageRow(key, title, subtitle)
                    self.stage_rows[key] = row
                    yield row
            yield StatsPanel(id="stats")

        yield RichLog(id="logpanel", highlight=True, markup=False, wrap=False)
        yield Footer()

    def _active_stages(self) -> list[tuple[str, str, str]]:
        """Discovery stages always show; deep stages only when mode='deep'."""
        return DISCOVERY_STAGES + (DEEP_STAGES if self.mode == "deep" else [])

    async def on_mount(self) -> None:
        self.query_one("#stats", StatsPanel).mode = self.mode
        self.sub_title = f"target: {self.domain or '(awaiting input)'} · mode: {self.mode}"
        if self.domain:
            self._run_task = asyncio.create_task(self._start_pipeline())

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "domain_input" or not event.value.strip():
            return

        # Accepts "example.com" (quick, default) or "example.com deep"
        # (single-target deep scan: stages 11-12 on top of the usual 1-10).
        parts = event.value.strip().split()
        self.domain = parts[0].lower()
        if len(parts) > 1 and parts[1].lower() in ReconEngine.MODES:
            self.mode = parts[1].lower()

        self.sub_title = f"target: {self.domain} · mode: {self.mode}"
        self.query_one("#stats", StatsPanel).mode = self.mode
        event.input.display = False

        if self.mode == "deep":
            pipeline = self.query_one("#pipeline", Vertical)
            for key, title, subtitle in DEEP_STAGES:
                row = StageRow(key, title, subtitle)
                self.stage_rows[key] = row
                pipeline.mount(row)

        self._run_task = asyncio.create_task(self._start_pipeline())

    # ------------------------------------------------------------- engine

    async def _start_pipeline(self) -> None:
        log = self.query_one("#logpanel", RichLog)
        log.write(f"[bold cyan]Starting recon pipeline for {self.domain}[/]")

        self._engine = ReconEngine(
            domain=self.domain,
            output_root=self.output_root,
            on_progress=self._on_progress,
            on_log=self._on_log,
            mode=self.mode,
        )
        stats = await self._engine.run_full_pipeline()
        self._refresh_stats(stats)
        log.write(
            f"[bold green]Pipeline complete.[/] Results saved under "
            f"{self.output_root / self.domain}"
        )

    async def _on_progress(self, stage: str, status: str, message: str) -> None:
        row = self.stage_rows.get(stage)
        if row:
            row.status = status
            row.message = message
        if self._engine:
            self._refresh_stats(self._engine.stats)

    async def _on_log(self, line: str) -> None:
        log = self.query_one("#logpanel", RichLog)
        log.write(line)

    def _refresh_stats(self, stats: ReconStats) -> None:
        panel = self.query_one("#stats", StatsPanel)
        panel.mode = self.mode
        panel.subdomains = stats.subdomains_found
        panel.live = stats.live_targets
        panel.forbidden_403 = stats.forbidden_403_found
        panel.urls = stats.urls_found
        panel.sensitive_urls = stats.sensitive_urls_found
        panel.screenshots = stats.screenshots_taken
        panel.vulns = stats.vulnerabilities_found
        panel.js_vulns = stats.js_vulnerabilities_found
        panel.outdated_tech = stats.outdated_tech_found
        panel.surface_by_param = stats.attack_surface_categorized
        panel.surface_by_path = stats.attack_surface_by_path_categorized
        panel.surface_by_ext = stats.attack_surface_by_extension_categorized
        panel.asns_found = stats.asns_found
        panel.related_orgs = stats.related_organizations_found
        panel.hosts_with_open_ports = stats.hosts_with_open_ports
        panel.open_ports_found = stats.open_ports_found
        panel.cert_new_subdomains = stats.cert_new_subdomains_found
        panel.js_endpoints = stats.js_endpoints_found
        panel.secrets = stats.secrets_found
        panel.unique_params = stats.unique_params_found
        panel.errors = len(stats.errors)

    # ------------------------------------------------------------- actions

    def action_restart(self) -> None:
        if self._run_task and not self._run_task.done():
            return  # don't restart mid-run
        for row in self.stage_rows.values():
            row.status = "pending"
            row.message = ""
        self.query_one("#logpanel", RichLog).clear()
        if self.domain:
            self._run_task = asyncio.create_task(self._start_pipeline())


def main() -> None:
    argv = __import__("sys").argv
    domain = os.environ.get("TARGET_DOMAIN") or (argv[1] if len(argv) > 1 else None)
    mode = os.environ.get("SCAN_MODE") or (argv[2] if len(argv) > 2 else "quick")
    output_root = os.environ.get("OUTPUT_DIR", "/output")
    app = ReconApp(domain=domain, output_root=output_root, mode=mode)
    app.run()


if __name__ == "__main__":
    main()
