# mcp-sbom-guard

CI-ready **verifier** for deployed MCP servers' SBOMs. October 2026 was the worst month yet for Model Context Protocol security — Langflow RCE (CVSS 9.9), fetch-server SSRF, x64dbg no-auth (9.3), SDK OAuth credential theft. Tools like `gkhays/mcp-sbom-server` *generate* SBOMs via MCP; **nobody verifies them against the CVE firehose**. That's this tool: point it at a deployment manifest or a CycloneDX SBOM from your pipeline and it fails CI (exit 2) on known-vulnerable versions.

**News hook (2026-10-18):** October 2026's MCP vulnerability cluster —
- **Langflow RCE (CVE-2026-105697, CVSS 9.9)** — disclosed Oct 5, 2026; executed the `command` field from MCP server configs with no allowlist, wrapped in `bash -c`. Public PoC; ~1,400 live exploit attempts observed. **The 1.9.0 fix was incomplete (bypassed) — 1.10.3 is required.**
- **Official MCP fetch-server SSRF (CVE-2026-104120, CVSS 7.3)** — published Oct 2, 2026; `fetch_url` in the reference `modelcontextprotocol/mcp-server-fetch` package allowed SSRF via the `url` argument.
- **x64dbg MCP no-auth (CVE-2026-107824, CVSS 9.3)** — published Oct 9, 2026; every debugger tool exposed over HTTP with no authentication, listening on all interfaces by default.
- **MCP Python SDK OAuth credential theft (2026-09-29, CVSS 7.5)** — reported by Cycode; the official SDK sent client secrets, authorization codes and PKCE proof keys to attacker-controlled token endpoints. Patched in **1.30.0** (1.x) and **2.2.0** (2.x).

Sources: RelayShield (2026-10-15), AI Cyber Brief (2026-10-15). CVE details are cited from these advisories and were **not independently verified** by Ingenious AI.

## Install

Zero dependencies (Python 3.8+ stdlib only):

```bash
git clone https://github.com/Iceman2050/mcp-sbom-guard.git
cd mcp-sbom-guard
```

## Usage

Verify a deployment manifest:

```bash
python3 mcp_sbom_guard.py scan --manifest fixtures/manifest-vulnerable.json
# [VULN] langflow 1.9.0
#   CVE-2026-105697 (CVSS 9.9) — fixed in: 1.10.3
# ...
# 2 vulnerable, 2 review, 4 total   # exit 2
```

Verify a CycloneDX SBOM straight from your build pipeline:

```bash
python3 mcp_sbom_guard.py scan --sbom sbom.cdx.json --format json
```

Manifest format — a deployment list of your MCP servers:

```json
{"servers": [{"name": "langflow", "version": "1.9.0"}, {"name": "mcp", "version": "1.30.0"}]}
```

Verdicts: **VULNERABLE** (in the feed + version affected — fail the pipeline), **REVIEW** (in the feed but version unknown or no fixed version published — verify upstream), **OK** (not in the bundled feed — *not* a clean bill of health).

Exit codes (CI-failable):

- `0` — no vulnerable components
- `2` — one or more VULNERABLE findings (fail the build)
- `1` — input/config error

## CI example

```yaml
- name: Guard MCP supply chain
  run: |
    python3 mcp_sbom_guard.py scan --manifest deploy/mcp-manifest.json
```

## The bundled feed

`feed.json` carries the October 2026 cluster (5 entries). It **will go stale** — add new advisories there as they land, and pass `--feed` to point at your own. Never treat the feed as a complete vulnerability database.

## What it does NOT do

- It is **not** a live vulnerability scanner or exploit checker — it matches declared versions against a static CVE table, nothing more.
- It does not detect 0-days, prompt injection, or malicious MCP tool behavior at runtime.
- It cannot verify that a "fixed" version is genuinely unexploitable — it trusts the cited advisories.
- An OK verdict means "not in the bundled feed", never "secure".
- It trusts the versions *you declare* — it cannot prove what's actually deployed.

## Tests

```bash
pip install pytest
python -m pytest -v   # 23 tests
```

## Built with

Built by Ingenious AI. Tech stack: Python 3.8+ stdlib only, pytest, GitHub Actions.

**The all-bundle suite deal:** every Ingenious AI security platform, one price —
[Ingenious AI Security Suite](https://iceman2050.github.io/ingeniousai-security-checks-mirror/security-suite.html)

### All 11 Ingenious AI platforms (early access)

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

## License

MIT — see [LICENSE](LICENSE).
