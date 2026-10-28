from datetime import UTC, datetime
from pathlib import Path

from rangeforge.harden import (
    CHECKS,
    Snapshot,
    diff_snapshots,
    evaluate,
    load_snapshots,
    save_snapshot,
)

GOOD_WINDOWS = {
    "audit_process_creation": "Success and Failure",
    "cmdline_in_4688": 1,
    "audit_logon": "Success and Failure",
    "audit_account_management": "Success",
    "ps_scriptblock_logging": 1,
    "security_log_max_mb": 512,
    "sysmon_running": True,
    "lsa_runasppl": 1,
    "wdigest_uselogoncredential": 0,
    "lm_compatibility_level": 5,
    "restrict_anonymous_sam": 1,
    "cached_logons_count": 2,
    "local_account_token_filter": 0,
    "smb1_enabled": False,
    "smb_signing_required": True,
    "llmnr_disabled": True,
    "netbios_over_tcpip": 2,
    "powershell_v2_enabled": False,
    "autorun_disabled": True,
    "rdp_enabled": True,
    "rdp_nla_required": True,
    "winrm_basic_auth": False,
    "winrm_unencrypted": False,
    "firewall_domain_on": True,
    "firewall_private_on": True,
    "firewall_public_on": True,
    "defender_realtime": True,
    "defender_signatures_age_days": 1,
    "defender_tamper_protection": True,
    "uac_enabled": True,
    "guest_enabled": False,
    "min_password_length": 14,
    "lockout_threshold": "5",
}


def test_check_ids_unique_and_keys_declared() -> None:
    ids = [c.id for c in CHECKS]
    assert len(ids) == len(set(ids))
    assert all(c.keys for c in CHECKS)


def test_good_windows_posture_passes_everything() -> None:
    findings = evaluate(GOOD_WINDOWS, "windows")
    assert findings and all(f.ok for f in findings), [f.check.id for f in findings if not f.ok]


def test_failures_and_unknowns() -> None:
    posture = dict(GOOD_WINDOWS)
    posture["wdigest_uselogoncredential"] = 1
    posture["smb1_enabled"] = True
    del posture["lsa_runasppl"]
    by_id = {f.check.id: f for f in evaluate(posture, "windows")}
    assert by_id["win.cred.wdigest"].status == "fail"
    assert by_id["win.proto.smb1"].status == "fail"
    assert by_id["win.cred.lsa-ppl"].status == "unknown"
    assert by_id["win.cred.wdigest"].check.severity == "critical"
    assert "T1003.001" in by_id["win.cred.wdigest"].check.techniques
    assert not any(k.startswith("lnx.") for k in by_id)


def test_linux_checks() -> None:
    posture = {
        "auditd_active": True,
        "auditd_rules": 50,
        "ssh_permit_root_login": "prohibit-password",
        "ssh_password_auth": "yes",
        "sudo_nopasswd_entries": 1,
        "uid0_accounts": 1,
        "aslr": 2,
        "ptrace_scope": 0,
        "ufw_active": False,
        "nft_chains": 3,
    }
    by_id = {f.check.id: f for f in evaluate(posture, "linux")}
    assert by_id["lnx.ssh.root-login"].ok
    assert by_id["lnx.ssh.password-auth"].status == "fail"
    assert by_id["lnx.acct.sudo-nopasswd"].status == "fail"
    assert by_id["lnx.kernel.ptrace-scope"].status == "fail"
    assert by_id["lnx.net.firewall"].ok
    assert by_id["lnx.apparmor"].status == "unknown"


def test_snapshot_roundtrip_and_diff(tmp_path: Path) -> None:
    a = Snapshot(
        host="h",
        os="linux",
        taken_at=datetime(2024, 1, 1, tzinfo=UTC),
        posture={"x": 1, "collected_at": "a"},
    )
    b = Snapshot(
        host="h",
        os="linux",
        taken_at=datetime(2024, 1, 2, tzinfo=UTC),
        posture={"x": 2, "y": True, "collected_at": "b"},
    )
    save_snapshot(a, tmp_path)
    save_snapshot(b, tmp_path)
    loaded = load_snapshots("h", tmp_path)
    assert [s.taken_at for s in loaded] == [a.taken_at, b.taken_at]
    assert diff_snapshots(loaded[0], loaded[1]) == {"x": (1, 2), "y": (None, True)}
