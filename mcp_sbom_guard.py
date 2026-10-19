#!/usr/bin/env python3
"""mcp-sbom-guard — CI-ready verifier for DEPLOYED MCP servers' SBOMs.

October 2026 was the worst month yet for MCP security (Langflow RCE 9.9,
fetch-server SSRF, x64dbg no-auth 9.3, SDK OAuth credential theft). Tools like
gkhays/mcp-sbom-server GENERATE SBOMs via MCP — this tool VERIFIES them:
point it at a deployment manifest or a CycloneDX SBOM from your pipeline and
it matches every declared component against the bundled CVE feed, failing CI
(exit 2) on known-vulnerable versions.

Honest scope: this is version-vs-CVE matching against a BUNDLED, STATIC feed.
It does not find 0-days, does not audit runtime behavior, and an OK verdict
means "not in the bundled feed", never "secure". Third-party CVE details are
cited from the advisories below; they were not independently verified by
Ingenious AI. The feed goes stale — update feed.json from the advisories.

Stdlib only. Python 3.8+.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FEED = os.path.join(HERE, "feed.json")

VERDICT_VULNERABLE = "VULNERABLE"
VERDICT_REVIEW = "REVIEW"
VERDICT_OK = "OK"


def parse_version(s):
    """'1.10.3' -> (1, 10, 3). Non-numeric suffixes are ignored; unknown -> None."""
    if s is None:
        return None
    m = re.match(r"\s*(\d+(?:\.\d+)*)", str(s))
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def normalize_name(name):
    """npm scopes and case are stripped: '@modelcontextprotocol/server-fetch' -> 'server-fetch'."""
    n = str(name).strip().lower()
    if n.startswith("@"):
        n = n.split("/", 1)[-1]
    return n


def load_feed(path=DEFAULT_FEED):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def version_affected(version, entry):
    """Return True if installed version is in the affected range.

    Entry may carry:
      affected_before: version is vulnerable if installed < affected_before
      affected_line:   e.g. "1.x" — vulnerable if installed is in 1.x AND < affected_before
    """
    v = parse_version(version)
    if v is None:
        return None  # unknown — caller decides REVIEW
    limit = parse_version(entry.get("affected_before"))
    if limit is None:
        return None
    if v >= limit:
        return False
    line = entry.get("affected_line")
    if line:
        major = int(line.rstrip(".x"))
        if v[0] != major:
            return False
    return True


def match_component(name, version, feed):
    """Match one (name, version) against the feed. Returns a finding dict."""
    norm = normalize_name(name)
    for entry in feed.get("entries", []):
        aliases = [normalize_name(a) for a in entry.get("aliases", [])]
        if norm not in aliases:
            continue
        affected = version_affected(version, entry)
        if affected is True:
            return {
                "verdict": VERDICT_VULNERABLE,
                "component": name,
                "installed": version,
                "id": entry["id"],
                "cvss": entry.get("cvss"),
                "fixed_in": entry.get("fixed_in"),
                "summary": entry.get("summary", ""),
                "source": entry.get("source", ""),
            }
        if affected is None or entry.get("fixed_in") in (None, "n/a"):
            return {
                "verdict": VERDICT_REVIEW,
                "component": name,
                "installed": version,
                "id": entry["id"],
                "cvss": entry.get("cvss"),
                "fixed_in": entry.get("fixed_in", "n/a"),
                "summary": entry.get("summary", ""),
                "source": entry.get("source", ""),
                "note": "version unknown or no fixed version in feed — verify upstream",
            }
        return {
            "verdict": VERDICT_OK,
            "component": name,
            "installed": version,
            "id": entry["id"],
        }
    return {"verdict": VERDICT_OK, "component": name, "installed": version, "id": None,
            "note": "not in bundled feed — not a clean bill of health"}


def parse_cyclonedx(path):
    """Extract (name, version) from a CycloneDX SBOM (JSON)."""
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or "components" not in doc:
        raise ValueError("not a CycloneDX JSON SBOM (missing 'components')")
    out = []
    for c in doc.get("components", []):
        name = c.get("name")
        if not name:
            continue
        out.append((name, c.get("version")))
    return out


def parse_manifest(path):
    """Extract (name, version) from a deployment manifest.

    Format: {"servers": [{"name": "langflow", "version": "1.9.0"}, ...]}
    Also accepts {"mcpServers": {...}} with {"package": ..., "version": ...} values.
    """
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    out = []
    if isinstance(doc, dict) and isinstance(doc.get("servers"), list):
        for s in doc["servers"]:
            out.append((s.get("name"), s.get("version")))
    elif isinstance(doc, dict) and isinstance(doc.get("mcpServers"), dict):
        for name, cfg in doc["mcpServers"].items():
            cfg = cfg or {}
            out.append((cfg.get("package", name), cfg.get("version")))
    else:
        raise ValueError("manifest must have 'servers' list or 'mcpServers' object")
    return [(n, v) for n, v in out if n]


def scan(components, feed):
    return [match_component(n, v, feed) for n, v in components]


def render_text(findings):
    lines = []
    for f in findings:
        tag = {"VULNERABLE": "[VULN]", "REVIEW": "[REVIEW]", "OK": "[OK]"}[f["verdict"]]
        lines.append("%s %s %s" % (tag, f["component"], f["installed"]))
        if f.get("id") and f["verdict"] != VERDICT_OK:
            lines.append("  %s (CVSS %s) — fixed in: %s" % (f["id"], f.get("cvss"), f.get("fixed_in")))
        if f.get("note"):
            lines.append("  note: %s" % f["note"])
        if f.get("source"):
            lines.append("  source: %s" % f["source"])
    nv = sum(1 for f in findings if f["verdict"] == VERDICT_VULNERABLE)
    nr = sum(1 for f in findings if f["verdict"] == VERDICT_REVIEW)
    lines.append("")
    lines.append("%d vulnerable, %d review, %d total" % (nv, nr, len(findings)))
    return "\n".join(lines)


def cmd_scan(args):
    feed = load_feed(args.feed)
    try:
        if args.manifest:
            components = parse_manifest(args.manifest)
        else:
            components = parse_cyclonedx(args.sbom)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    if not components:
        print("error: no components found to verify", file=sys.stderr)
        return 1
    findings = scan(components, feed)
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        print(render_text(findings))
    if any(f["verdict"] == VERDICT_VULNERABLE for f in findings):
        return 2
    return 0


def cmd_feed(args):
    feed = load_feed(args.feed)
    print("mcp-sbom-guard feed: %d entries (generated %s)" % (
        len(feed.get("entries", [])), feed.get("generated", "?")))
    for e in feed.get("entries", []):
        print("- %s | %s | CVSS %s | fixed in: %s" % (
            e["id"], e.get("summary", "")[:70], e.get("cvss"), e.get("fixed_in")))


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Verify deployed MCP servers' SBOMs against the Oct 2026 MCP CVE feed.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="verify a manifest or CycloneDX SBOM; exit 2 on known-vulnerable")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--manifest", help="deployment manifest JSON (servers list or mcpServers object)")
    src.add_argument("--sbom", help="CycloneDX SBOM JSON file")
    s.add_argument("--feed", default=DEFAULT_FEED, help="CVE feed JSON (default: bundled feed.json)")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("feed", help="list the bundled CVE feed entries")
    f.add_argument("--feed", default=DEFAULT_FEED)
    f.set_defaults(func=cmd_feed)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
