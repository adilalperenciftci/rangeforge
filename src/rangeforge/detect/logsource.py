"""Sigma logsource -> native event constraints and field aliases.

A Sigma rule's ``logsource`` says *where* the rule applies. We translate it to
an ``EventFilter``: the set of (channel, event id) pairs it covers plus the
field aliases needed when the same signal is carried by a different log
(e.g. ``Image`` is ``NewProcessName`` in Security 4688).
"""

from __future__ import annotations

from dataclasses import dataclass, field

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_CLASSIC = "Windows PowerShell"
SYSTEM_CHANNEL = "System"
APPLICATION_CHANNEL = "Application"
DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
TASKSCHED_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
WMI_CHANNEL = "Microsoft-Windows-WMI-Activity/Operational"
BITS_CHANNEL = "Microsoft-Windows-Bits-Client/Operational"
TS_LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
NTLM_CHANNEL = "Microsoft-Windows-NTLM/Operational"
FIREWALL_CHANNEL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
CODEINTEGRITY_CHANNEL = "Microsoft-Windows-CodeIntegrity/Operational"
DNS_CLIENT_CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
LDAP_CHANNEL = "Microsoft-Windows-LDAP-Client/Debug"
OPENSSH_CHANNEL = "OpenSSH/Operational"
PRINTSERVICE_CHANNEL = "Microsoft-Windows-PrintService/Operational"
SMBCLIENT_CHANNEL = "Microsoft-Windows-SmbClient/Security"
SECURITY_MITIGATIONS = "Microsoft-Windows-Security-Mitigations/KernelMode"

SECURITY_4688_ALIASES: dict[str, str] = {
    "Image": "NewProcessName",
    "ParentImage": "ParentProcessName",
    "User": "SubjectUserName",
    "ProcessId": "NewProcessId",
    "ParentProcessId": "ProcessId",
    "IntegrityLevel": "MandatoryLabel",
}


@dataclass(frozen=True)
class EventFilter:
    """Which (channel, event id) pairs a rule applies to.

    ``channels``: channel name -> allowed event ids (``None`` = any id).
    ``aliases``: (channel, event id) -> {sigma field: native field}.
    ``unrestricted`` means the logsource could not be mapped and the rule is
    evaluated against every event.
    """

    channels: dict[str, frozenset[int] | None] = field(default_factory=dict)
    aliases: dict[tuple[str, int], dict[str, str]] = field(default_factory=dict)
    unrestricted: bool = False

    def accepts(self, channel: str | None, event_id: int | None) -> bool:
        if self.unrestricted:
            return True
        if channel is None or channel not in self.channels:
            return False
        allowed = self.channels[channel]
        return allowed is None or event_id in allowed

    def alias_map(self, channel: str | None, event_id: int | None) -> dict[str, str] | None:
        if channel is None or event_id is None:
            return None
        return self.aliases.get((channel, event_id))

    def event_ids(self) -> frozenset[int] | None:
        """All event ids this filter accepts, or None if any id is accepted."""
        if self.unrestricted:
            return None
        ids: set[int] = set()
        for allowed in self.channels.values():
            if allowed is None:
                return None
            ids.update(allowed)
        return frozenset(ids)


def _sysmon(*ids: int) -> EventFilter:
    return EventFilter(channels={SYSMON_CHANNEL: frozenset(ids)})


# Windows categories (Sigma taxonomy) -> filter
_WINDOWS_CATEGORY: dict[str, EventFilter] = {
    "process_creation": EventFilter(
        channels={SYSMON_CHANNEL: frozenset({1}), SECURITY_CHANNEL: frozenset({4688})},
        aliases={(SECURITY_CHANNEL, 4688): SECURITY_4688_ALIASES},
    ),
    "file_change": _sysmon(2),
    "network_connection": _sysmon(3),
    "sysmon_status": _sysmon(4, 16),
    "process_termination": _sysmon(5),
    "driver_load": _sysmon(6),
    "image_load": _sysmon(7),
    "create_remote_thread": _sysmon(8),
    "raw_access_thread": _sysmon(9),
    "process_access": _sysmon(10),
    "file_event": _sysmon(11),
    "registry_event": _sysmon(12, 13, 14),
    "registry_add": _sysmon(12),
    "registry_delete": _sysmon(12),
    "registry_set": _sysmon(13),
    "registry_rename": _sysmon(14),
    "create_stream_hash": _sysmon(15),
    "pipe_created": _sysmon(17, 18),
    "wmi_event": _sysmon(19, 20, 21),
    "dns_query": _sysmon(22),
    "file_delete": _sysmon(23, 26),
    "clipboard_change": _sysmon(24),
    "process_tampering": _sysmon(25),
    "file_block": _sysmon(27),
    "file_executable_detected": _sysmon(29),
    "sysmon_error": _sysmon(255),
    "ps_script": EventFilter(channels={POWERSHELL_CHANNEL: frozenset({4104})}),
    "ps_module": EventFilter(channels={POWERSHELL_CHANNEL: frozenset({4103})}),
    "ps_classic_start": EventFilter(channels={POWERSHELL_CLASSIC: frozenset({400})}),
    "ps_classic_provider_start": EventFilter(channels={POWERSHELL_CLASSIC: frozenset({600})}),
    "ps_classic_script": EventFilter(channels={POWERSHELL_CLASSIC: frozenset({800})}),
    "antivirus": EventFilter(channels={DEFENDER_CHANNEL: None}),
}

# Windows services -> channel
_WINDOWS_SERVICE: dict[str, str] = {
    "security": SECURITY_CHANNEL,
    "sysmon": SYSMON_CHANNEL,
    "system": SYSTEM_CHANNEL,
    "application": APPLICATION_CHANNEL,
    "powershell": POWERSHELL_CHANNEL,
    "powershell-classic": POWERSHELL_CLASSIC,
    "windefend": DEFENDER_CHANNEL,
    "taskscheduler": TASKSCHED_CHANNEL,
    "wmi": WMI_CHANNEL,
    "bits-client": BITS_CHANNEL,
    "terminalservices-localsessionmanager": TS_LSM_CHANNEL,
    "ntlm": NTLM_CHANNEL,
    "firewall-as": FIREWALL_CHANNEL,
    "codeintegrity-operational": CODEINTEGRITY_CHANNEL,
    "dns-client": DNS_CLIENT_CHANNEL,
    "ldap_debug": LDAP_CHANNEL,
    "openssh": OPENSSH_CHANNEL,
    "printservice-operational": PRINTSERVICE_CHANNEL,
    "smbclient-security": SMBCLIENT_CHANNEL,
    "security-mitigations": SECURITY_MITIGATIONS,
}


def resolve_logsource(
    product: str | None, category: str | None, service: str | None
) -> EventFilter:
    product = (product or "").lower() or None
    category = (category or "").lower() or None
    service = (service or "").lower() or None

    if product == "windows":
        if category and category in _WINDOWS_CATEGORY:
            return _WINDOWS_CATEGORY[category]
        if service and service in _WINDOWS_SERVICE:
            return EventFilter(channels={_WINDOWS_SERVICE[service]: None})
        if service:
            # Best effort: "Microsoft-Windows-<Service>/Operational"-style channels
            return EventFilter(channels={_guess_channel(service): None})
        return EventFilter(unrestricted=True)

    # Non-Windows products are matched by the ingest layer tagging Channel with
    # the product/service name (auditd, sshd, ...). Keep them unrestricted until
    # the Linux normalizer lands.
    return EventFilter(unrestricted=True)


def _guess_channel(service: str) -> str:
    parts = service.split("-")
    name = "-".join(p.capitalize() for p in parts[:-1]) if len(parts) > 1 else service.capitalize()
    suffix = parts[-1].capitalize() if len(parts) > 1 else "Operational"
    return f"Microsoft-Windows-{name}/{suffix}"
