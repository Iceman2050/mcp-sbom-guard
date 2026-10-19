"""Tests for mcp_sbom_guard. All deterministic, stdlib-only, no network."""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MOD = os.path.join(ROOT, "mcp_sbom_guard.py")
FEED = os.path.join(ROOT, "feed.json")
FIX = os.path.join(ROOT, "fixtures")

sys.path.insert(0, ROOT)
import mcp_sbom_guard as g


def run_cli(*args):
    return subprocess.run([sys.executable, MOD, *args], capture_output=True, text=True)


# --- version parsing ---------------------------------------------------------
def test_parse_version_basic():
    assert g.parse_version("1.10.3") == (1, 10, 3)


def test_parse_version_ignores_suffix():
    assert g.parse_version("2.2.0rc1") == (2, 2, 0)


def test_parse_version_none():
    assert g.parse_version(None) is None
    assert g.parse_version("n/a") is None


def test_version_ordering():
    assert g.parse_version("1.10.3") > g.parse_version("1.9.0")


# --- name normalization ------------------------------------------------------
def test_normalize_strips_scope():
    assert g.normalize_name("@modelcontextprotocol/server-fetch") == "server-fetch"


def test_normalize_case():
    assert g.normalize_name("LangFlow") == "langflow"


# --- matching ----------------------------------------------------------------
@pytest.fixture()
def feed():
    return g.load_feed(FEED)


def test_feed_has_five_entries(feed):
    assert len(feed["entries"]) == 5


def test_langflow_vulnerable(feed):
    f = g.match_component("langflow", "1.9.0", feed)
    assert f["verdict"] == "VULNERABLE"
    assert f["id"] == "CVE-2026-105697"
    assert f["fixed_in"] == "1.10.3"


def test_langflow_fixed_ok(feed):
    f = g.match_component("langflow", "1.10.3", feed)
    assert f["verdict"] == "OK"


def test_pysdk_vulnerable(feed):
    f = g.match_component("mcp", "1.29.9", feed)
    assert f["verdict"] == "VULNERABLE"
    assert f["id"] == "MCP-PYSDK-OAUTH-2026-09-29"


def test_pysdk_fixed_ok(feed):
    f = g.match_component("mcp", "1.30.0", feed)
    assert f["verdict"] == "OK"


def test_fetch_server_review(feed):
    # no fixed version published in the cited advisory -> REVIEW, never VULNERABLE-by-guess
    f = g.match_component("server-fetch", "1.0.0", feed)
    assert f["verdict"] == "REVIEW"


def test_unknown_component_ok_with_note(feed):
    f = g.match_component("requests", "2.32.3", feed)
    assert f["verdict"] == "OK"
    assert "not in bundled feed" in f["note"]


def test_unknown_version_review(feed):
    f = g.match_component("langflow", None, feed)
    assert f["verdict"] == "REVIEW"


# --- input parsing -----------------------------------------------------------
def test_parse_manifest_servers():
    comps = g.parse_manifest(os.path.join(FIX, "manifest-vulnerable.json"))
    assert ("langflow", "1.9.0") in comps
    assert len(comps) == 4


def test_parse_cyclonedx():
    comps = g.parse_cyclonedx(os.path.join(FIX, "sbom.cdx.json"))
    assert ("mcp", "1.29.9") in comps
    assert ("requests", "2.32.3") in comps


def test_parse_manifest_bad():
    with pytest.raises(ValueError):
        g.parse_manifest(os.path.join(FIX, "manifest-bad.json"))


# --- CLI / exit codes ---------------------------------------------------------
def test_cli_vulnerable_exits_2():
    r = run_cli("scan", "--manifest", os.path.join(FIX, "manifest-vulnerable.json"))
    assert r.returncode == 2
    assert "[VULN]" in r.stdout
    assert "CVE-2026-105697" in r.stdout


def test_cli_clean_exits_0():
    r = run_cli("scan", "--manifest", os.path.join(FIX, "manifest-clean.json"))
    assert r.returncode == 0
    assert "[VULN]" not in r.stdout


def test_cli_sbom_mode():
    r = run_cli("scan", "--sbom", os.path.join(FIX, "sbom.cdx.json"))
    assert r.returncode == 2  # mcp 1.29.9 is vulnerable
    assert "MCP-PYSDK-OAUTH-2026-09-29" in r.stdout


def test_cli_json_format():
    r = run_cli("scan", "--manifest", os.path.join(FIX, "manifest-clean.json"), "--format", "json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert all(f["verdict"] == "OK" for f in data)


def test_cli_missing_file_exits_1():
    r = run_cli("scan", "--manifest", os.path.join(FIX, "nope.json"))
    assert r.returncode == 1


def test_cli_feed_subcommand():
    r = run_cli("feed")
    assert r.returncode == 0
    assert "CVE-2026-105697" in r.stdout
