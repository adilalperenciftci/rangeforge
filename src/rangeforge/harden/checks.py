# ruff: noqa: E501  (one check per line reads better than wrapped tuples)
"""Posture checks. Each check reads one or more posture keys and decides
pass / fail / unknown. References point at CIS Benchmark sections where one
applies; the wording is ours."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

Status = Literal["pass", "fail", "unknown"]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Check:
    id: str
    os: Literal["windows", "linux"]
    title: str
    severity: Severity
    keys: tuple[str, ...]
    predicate: Callable[[dict[str, Any]], bool]
    rationale: str
    reference: str | None = None
    techniques: tuple[str, ...] = ()
    """ATT&CK techniques this control mitigates or exposes."""


@dataclass(frozen=True)
class Finding:
    check: Check
    status: Status
    observed: dict[str, Any]

    @property
    def ok(self) -> bool:
        return self.status == "pass"


def _b(d: dict[str, Any], k: str) -> bool:
    return bool(d.get(k))


def _i(d: dict[str, Any], k: str, default: int = 0) -> int:
    try:
        return int(d.get(k, default))
    except (TypeError, ValueError):
        return default


def _s(d: dict[str, Any], k: str) -> str:
    return str(d.get(k, "")).lower()


WINDOWS: tuple[Check, ...] = (
    Check(
        "win.audit.process-creation",
        "windows",
        "Process creation auditing enabled",
        "high",
        ("audit_process_creation",),
        lambda d: "success" in _s(d, "audit_process_creation"),
        "Without 4688 events most execution detections have nothing to match.",
        "CIS 17.3.2",
        ("T1059",),
    ),
    Check(
        "win.audit.cmdline",
        "windows",
        "Command line included in 4688",
        "high",
        ("cmdline_in_4688",),
        lambda d: _i(d, "cmdline_in_4688") == 1,
        "Process names alone cannot distinguish living-off-the-land abuse from normal use.",
        "CIS 18.9.3.1",
        ("T1059", "T1218"),
    ),
    Check(
        "win.audit.logon",
        "windows",
        "Logon auditing (success and failure)",
        "medium",
        ("audit_logon",),
        lambda d: "failure" in _s(d, "audit_logon") and "success" in _s(d, "audit_logon"),
        "Brute force and lateral movement are visible only with both outcomes logged.",
        "CIS 17.5.4",
        ("T1110", "T1021"),
    ),
    Check(
        "win.audit.account-mgmt",
        "windows",
        "User account management auditing",
        "medium",
        ("audit_account_management",),
        lambda d: "success" in _s(d, "audit_account_management"),
        "Account creation and group changes are core persistence signals.",
        "CIS 17.2.5",
        ("T1136", "T1098"),
    ),
    Check(
        "win.log.ps-scriptblock",
        "windows",
        "PowerShell script block logging",
        "high",
        ("ps_scriptblock_logging",),
        lambda d: _i(d, "ps_scriptblock_logging") == 1,
        "Script block logging (4104) exposes de-obfuscated PowerShell.",
        "CIS 18.10.87.1",
        ("T1059.001",),
    ),
    Check(
        "win.log.security-size",
        "windows",
        "Security log at least 192 MB",
        "low",
        ("security_log_max_mb",),
        lambda d: _i(d, "security_log_max_mb") >= 192,
        "A small log wraps before an investigation starts.",
        "CIS 18.10.25.1.2",
    ),
    Check(
        "win.log.sysmon",
        "windows",
        "Sysmon service running",
        "medium",
        ("sysmon_running",),
        lambda d: _b(d, "sysmon_running"),
        "Most process, network and image-load detections depend on Sysmon.",
        None,
    ),
    Check(
        "win.cred.lsa-ppl",
        "windows",
        "LSA runs as protected process (RunAsPPL)",
        "high",
        ("lsa_runasppl",),
        lambda d: _i(d, "lsa_runasppl") >= 1,
        "Blocks unsigned code from reading LSASS memory.",
        "CIS 18.4.4",
        ("T1003.001",),
    ),
    Check(
        "win.cred.wdigest",
        "windows",
        "WDigest cleartext caching disabled",
        "critical",
        ("wdigest_uselogoncredential",),
        lambda d: _i(d, "wdigest_uselogoncredential") == 0,
        "With UseLogonCredential=1 plaintext passwords sit in LSASS.",
        "CIS 18.4.7",
        ("T1003.001",),
    ),
    Check(
        "win.cred.lm-compat",
        "windows",
        "NTLMv2 only (LmCompatibilityLevel >= 5)",
        "high",
        ("lm_compatibility_level",),
        lambda d: _i(d, "lm_compatibility_level") >= 5,
        "LM and NTLMv1 responses are crackable and relayable.",
        "CIS 2.3.11.7",
        ("T1557.001", "T1110.002"),
    ),
    Check(
        "win.cred.anon-sam",
        "windows",
        "Anonymous SAM enumeration restricted",
        "medium",
        ("restrict_anonymous_sam",),
        lambda d: _i(d, "restrict_anonymous_sam") == 1,
        "Prevents unauthenticated account enumeration.",
        "CIS 2.3.10.2",
        ("T1087.001",),
    ),
    Check(
        "win.cred.cached-logons",
        "windows",
        "Cached domain logons limited (<= 4)",
        "low",
        ("cached_logons_count",),
        lambda d: _i(d, "cached_logons_count", 10) <= 4,
        "Cached verifiers can be dumped and cracked offline.",
        "CIS 2.3.7.6",
        ("T1003.005",),
    ),
    Check(
        "win.cred.token-filter",
        "windows",
        "Remote UAC filtering for local admins (LocalAccountTokenFilterPolicy=0)",
        "medium",
        ("local_account_token_filter",),
        lambda d: _i(d, "local_account_token_filter") == 0,
        "Setting it to 1 lets any local admin use full token remotely (pass-the-hash friendly). Labs often need 1 for WinRM; treat as accepted risk.",
        "CIS 18.4.1",
        ("T1550.002", "T1021.006"),
    ),
    Check(
        "win.proto.smb1",
        "windows",
        "SMBv1 disabled",
        "critical",
        ("smb1_enabled",),
        lambda d: not _b(d, "smb1_enabled"),
        "SMBv1 is the transport for EternalBlue-class exploits.",
        "CIS 18.4.3",
        ("T1210",),
    ),
    Check(
        "win.proto.smb-signing",
        "windows",
        "SMB server signing required",
        "high",
        ("smb_signing_required",),
        lambda d: _b(d, "smb_signing_required"),
        "Stops SMB relay attacks.",
        "CIS 2.3.9.2",
        ("T1557.001",),
    ),
    Check(
        "win.proto.llmnr",
        "windows",
        "LLMNR disabled",
        "high",
        ("llmnr_disabled",),
        lambda d: _b(d, "llmnr_disabled"),
        "LLMNR poisoning yields NTLM hashes from the local segment.",
        "CIS 18.6.4.2",
        ("T1557.001",),
    ),
    Check(
        "win.proto.netbios",
        "windows",
        "NetBIOS over TCP/IP disabled",
        "medium",
        ("netbios_over_tcpip",),
        lambda d: _i(d, "netbios_over_tcpip") == 2,
        "NBT-NS poisoning, same class as LLMNR.",
        None,
        ("T1557.001",),
    ),
    Check(
        "win.surface.ps-v2",
        "windows",
        "PowerShell v2 engine removed",
        "medium",
        ("powershell_v2_enabled",),
        lambda d: not _b(d, "powershell_v2_enabled"),
        "v2 has no script block logging or AMSI; it is a logging bypass.",
        "CIS 18.10.57.2",
        ("T1059.001", "T1562.001"),
    ),
    Check(
        "win.surface.autorun",
        "windows",
        "AutoRun disabled for all drives",
        "low",
        ("autorun_disabled",),
        lambda d: _b(d, "autorun_disabled"),
        "Removable media execution path.",
        "CIS 18.10.7.3",
        ("T1091",),
    ),
    Check(
        "win.remote.rdp-nla",
        "windows",
        "RDP requires Network Level Authentication",
        "high",
        ("rdp_enabled", "rdp_nla_required"),
        lambda d: (not _b(d, "rdp_enabled")) or _b(d, "rdp_nla_required"),
        "Pre-auth RDP exposes the login screen and BlueKeep-class bugs.",
        "CIS 18.10.64.3.9.1",
        ("T1021.001",),
    ),
    Check(
        "win.remote.winrm-basic",
        "windows",
        "WinRM basic authentication disabled",
        "high",
        ("winrm_basic_auth",),
        lambda d: not _b(d, "winrm_basic_auth"),
        "Basic auth sends credentials in a reversible form.",
        "CIS 18.10.89.2.1",
        ("T1021.006",),
    ),
    Check(
        "win.remote.winrm-unencrypted",
        "windows",
        "WinRM unencrypted traffic disallowed",
        "high",
        ("winrm_unencrypted",),
        lambda d: not _b(d, "winrm_unencrypted"),
        "Credential and command interception on the wire.",
        "CIS 18.10.89.2.3",
        ("T1557",),
    ),
    Check(
        "win.net.firewall",
        "windows",
        "Firewall enabled on all profiles",
        "high",
        ("firewall_domain_on", "firewall_private_on", "firewall_public_on"),
        lambda d: (
            _b(d, "firewall_domain_on")
            and _b(d, "firewall_private_on")
            and _b(d, "firewall_public_on")
        ),
        "Host firewall is the last line against lateral movement.",
        "CIS 9.1.1",
    ),
    Check(
        "win.av.realtime",
        "windows",
        "Defender real-time protection on",
        "high",
        ("defender_realtime",),
        lambda d: _b(d, "defender_realtime"),
        "Baseline malware prevention.",
        "CIS 18.10.43.10.1",
        ("T1562.001",),
    ),
    Check(
        "win.av.signatures",
        "windows",
        "Defender signatures newer than 7 days",
        "medium",
        ("defender_signatures_age_days",),
        lambda d: _i(d, "defender_signatures_age_days", 999) <= 7,
        "Stale signatures miss current commodity malware.",
        None,
    ),
    Check(
        "win.av.tamper",
        "windows",
        "Defender tamper protection on",
        "medium",
        ("defender_tamper_protection",),
        lambda d: _b(d, "defender_tamper_protection"),
        "Stops malware from switching Defender off.",
        None,
        ("T1562.001",),
    ),
    Check(
        "win.uac.enabled",
        "windows",
        "UAC enabled",
        "high",
        ("uac_enabled",),
        lambda d: _b(d, "uac_enabled"),
        "Integrity levels and elevation prompts depend on it.",
        "CIS 2.3.17.1",
        ("T1548.002",),
    ),
    Check(
        "win.acct.guest",
        "windows",
        "Guest account disabled",
        "medium",
        ("guest_enabled",),
        lambda d: not _b(d, "guest_enabled"),
        "Anonymous foothold.",
        "CIS 2.3.1.2",
        ("T1078.001",),
    ),
    Check(
        "win.acct.min-pw-len",
        "windows",
        "Minimum password length >= 14",
        "medium",
        ("min_password_length",),
        lambda d: _i(d, "min_password_length") >= 14,
        "Short passwords fall to offline cracking.",
        "CIS 1.1.4",
        ("T1110",),
    ),
    Check(
        "win.acct.lockout",
        "windows",
        "Account lockout threshold set",
        "medium",
        ("lockout_threshold",),
        lambda d: _s(d, "lockout_threshold") not in ("never", "", "none"),
        "Rate-limits online password guessing.",
        "CIS 1.2.2",
        ("T1110.001",),
    ),
)

LINUX: tuple[Check, ...] = (
    Check(
        "lnx.audit.active",
        "linux",
        "auditd running",
        "high",
        ("auditd_active",),
        lambda d: _b(d, "auditd_active"),
        "No auditd, no execve telemetry.",
        "CIS 4.1.1.1",
        ("T1059",),
    ),
    Check(
        "lnx.audit.rules",
        "linux",
        "auditd has rules loaded (>= 20)",
        "high",
        ("auditd_rules",),
        lambda d: _i(d, "auditd_rules") >= 20,
        "An empty rule set logs nothing useful.",
        "CIS 4.1.3",
    ),
    Check(
        "lnx.log.journald-persistent",
        "linux",
        "journald persists to disk",
        "low",
        ("journald_persistent",),
        lambda d: _b(d, "journald_persistent"),
        "Volatile journals vanish on reboot.",
        "CIS 4.2.1.3",
    ),
    Check(
        "lnx.ssh.root-login",
        "linux",
        "SSH root login disabled",
        "high",
        ("ssh_permit_root_login",),
        lambda d: _s(d, "ssh_permit_root_login") in ("no", "prohibit-password"),
        "Root is the first account every scanner tries.",
        "CIS 5.2.10",
        ("T1110", "T1021.004"),
    ),
    Check(
        "lnx.ssh.password-auth",
        "linux",
        "SSH password authentication disabled",
        "high",
        ("ssh_password_auth",),
        lambda d: _s(d, "ssh_password_auth") == "no",
        "Keys only removes password guessing from the attack surface.",
        "CIS 5.2.11",
        ("T1110",),
    ),
    Check(
        "lnx.ssh.max-auth-tries",
        "linux",
        "SSH MaxAuthTries <= 4",
        "low",
        ("ssh_max_auth_tries",),
        lambda d: 0 < _i(d, "ssh_max_auth_tries", 6) <= 4,
        "Slows per-connection guessing.",
        "CIS 5.2.7",
        ("T1110",),
    ),
    Check(
        "lnx.ssh.empty-passwords",
        "linux",
        "SSH empty passwords refused",
        "critical",
        ("ssh_permit_empty_passwords",),
        lambda d: _s(d, "ssh_permit_empty_passwords") == "no",
        "Self-explanatory.",
        "CIS 5.2.9",
        ("T1078",),
    ),
    Check(
        "lnx.acct.sudo-nopasswd",
        "linux",
        "No NOPASSWD sudo entries",
        "medium",
        ("sudo_nopasswd_entries",),
        lambda d: _i(d, "sudo_nopasswd_entries") == 0,
        "Any code running as that user is root. Lab automation often needs it; treat as accepted risk.",
        "CIS 5.3.4",
        ("T1548.003",),
    ),
    Check(
        "lnx.acct.empty-passwords",
        "linux",
        "No accounts with empty passwords",
        "critical",
        ("empty_password_accounts",),
        lambda d: _i(d, "empty_password_accounts") == 0,
        "Passwordless local logon.",
        "CIS 6.2.1",
        ("T1078.003",),
    ),
    Check(
        "lnx.acct.single-uid0",
        "linux",
        "Only root has UID 0",
        "high",
        ("uid0_accounts",),
        lambda d: _i(d, "uid0_accounts", 1) == 1,
        "Hidden root accounts are a classic persistence trick.",
        "CIS 6.2.3",
        ("T1136.001",),
    ),
    Check(
        "lnx.kernel.aslr",
        "linux",
        "ASLR fully enabled",
        "medium",
        ("aslr",),
        lambda d: _i(d, "aslr") == 2,
        "Raises the cost of memory-corruption exploits.",
        "CIS 1.5.2",
        ("T1068",),
    ),
    Check(
        "lnx.kernel.ptrace-scope",
        "linux",
        "ptrace restricted (yama scope >= 1)",
        "medium",
        ("ptrace_scope",),
        lambda d: _i(d, "ptrace_scope") >= 1,
        "Blocks same-user process injection and credential scraping.",
        None,
        ("T1055", "T1003"),
    ),
    Check(
        "lnx.kernel.kptr",
        "linux",
        "Kernel pointers hidden",
        "low",
        ("kptr_restrict",),
        lambda d: _i(d, "kptr_restrict") >= 1,
        "Leaked addresses defeat KASLR.",
        "CIS 1.5.1",
        ("T1068",),
    ),
    Check(
        "lnx.kernel.suid-dumpable",
        "linux",
        "Core dumps of setuid programs disabled",
        "low",
        ("suid_dumpable",),
        lambda d: _i(d, "suid_dumpable") == 0,
        "Dumps can contain secrets.",
        "CIS 1.5.1",
    ),
    Check(
        "lnx.kernel.unpriv-bpf",
        "linux",
        "Unprivileged BPF disabled",
        "low",
        ("unprivileged_bpf_disabled",),
        lambda d: _i(d, "unprivileged_bpf_disabled") >= 1,
        "Reduces kernel attack surface for local users.",
        None,
        ("T1068",),
    ),
    Check(
        "lnx.net.ip-forward",
        "linux",
        "IP forwarding off (non-router)",
        "low",
        ("ip_forward",),
        lambda d: _i(d, "ip_forward") == 0,
        "A pivot box should not route.",
        "CIS 3.2.1",
        ("T1090",),
    ),
    Check(
        "lnx.net.firewall",
        "linux",
        "Host firewall active (ufw or nftables)",
        "high",
        ("ufw_active", "nft_chains"),
        lambda d: _b(d, "ufw_active") or _i(d, "nft_chains") > 0,
        "Limits lateral movement and C2 egress.",
        "CIS 3.5",
        ("T1021",),
    ),
    Check(
        "lnx.fs.world-writable",
        "linux",
        "No world-writable regular files",
        "medium",
        ("world_writable_files",),
        lambda d: _i(d, "world_writable_files") == 0,
        "Anyone can plant content in them.",
        "CIS 6.1.10",
        ("T1574",),
    ),
    Check(
        "lnx.apparmor",
        "linux",
        "AppArmor active",
        "medium",
        ("apparmor_active",),
        lambda d: _b(d, "apparmor_active"),
        "Mandatory access control for exposed services.",
        "CIS 1.6.1.1",
    ),
    Check(
        "lnx.updates.unattended",
        "linux",
        "Unattended security upgrades installed",
        "medium",
        ("unattended_upgrades",),
        lambda d: _b(d, "unattended_upgrades"),
        "Patch latency is the biggest exploit enabler.",
        "CIS 1.9",
        ("T1190", "T1068"),
    ),
    Check(
        "lnx.updates.pending",
        "linux",
        "No pending package upgrades",
        "low",
        ("updates_pending",),
        lambda d: _i(d, "updates_pending") == 0,
        "Known vulnerabilities with available fixes.",
        None,
        ("T1190",),
    ),
)

CHECKS: tuple[Check, ...] = WINDOWS + LINUX


def evaluate(posture: dict[str, Any], os_name: str) -> list[Finding]:
    findings: list[Finding] = []
    for check in CHECKS:
        if check.os != os_name:
            continue
        observed = {k: posture.get(k) for k in check.keys}
        if all(v is None for v in observed.values()):
            findings.append(Finding(check, "unknown", observed))
            continue
        try:
            status: Status = "pass" if check.predicate(posture) else "fail"
        except Exception:  # a malformed value must not abort the report
            status = "unknown"
        findings.append(Finding(check, status, observed))
    return findings
