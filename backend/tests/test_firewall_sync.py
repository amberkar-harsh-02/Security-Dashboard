"""Tests for deploy/siem_firewall_sync.py, the root-run script that applies blocks to nftables."""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "siem_firewall_sync.py"
spec = importlib.util.spec_from_file_location("siem_firewall_sync", SCRIPT)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def build(entries, extra=""):
    return sync.build_nft_script(entries, NOW, sync.load_never_block(extra))


def test_timed_permanent_and_ipv6():
    script, applied, skipped = build([
        {"ip": "203.0.113.9", "expires_at": "2026-10-20T13:00:00.000Z"},
        {"ip": "198.51.100.23", "expires_at": None},
        {"ip": "2001:db8::5", "expires_at": "2026-10-20T12:15:00Z"},
    ])
    assert (applied, skipped) == (3, 0)
    assert script.splitlines() == [
        "flush set inet siem blocked4",
        "flush set inet siem blocked6",
        "add element inet siem blocked4 { 203.0.113.9 timeout 3600s }",
        "add element inet siem blocked4 { 198.51.100.23 }",
        "add element inet siem blocked6 { 2001:db8::5 timeout 900s }",
    ]


def test_skips_expired_invalid_duplicate_and_protected():
    script, applied, skipped = build(
        [
            {"ip": "203.0.113.9", "expires_at": "2026-10-20T11:00:00Z"},  # expired
            {"ip": "not-an-ip"},
            {"ip": "203.0.113.10; flush ruleset", "expires_at": None},  # never reaches nft
            {"expires_at": None},
            {"ip": "127.0.0.1", "expires_at": None},
            {"ip": "10.0.0.8", "expires_at": None},
            {"ip": "198.51.100.200", "expires_at": None},  # on the extra never-block list
            {"ip": "203.0.113.11", "expires_at": None},
            {"ip": "203.0.113.11", "expires_at": None},  # duplicate
        ],
        extra="# my laptop\n198.51.100.200\n",
    )
    assert applied == 1 and skipped == 8
    assert "flush ruleset" not in script
    assert script.splitlines()[-1] == "add element inet siem blocked4 { 203.0.113.11 }"


def test_empty_list_still_clears_the_sets():
    script, applied, skipped = build([])
    assert script.splitlines() == ["flush set inet siem blocked4", "flush set inet siem blocked6"]
    assert (applied, skipped) == (0, 0)
