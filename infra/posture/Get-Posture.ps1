<#
.SYNOPSIS
    Collect a security-posture snapshot of a Windows host as JSON.

.DESCRIPTION
    Read-only. Gathers the settings RangeForge's hardening checks evaluate
    (audit policy, logging, LSA/credential protection, legacy protocols,
    remote access, Defender, UAC, account policy). Emits one JSON object on
    stdout; every value is a plain string, number or boolean.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'SilentlyContinue'

function Get-Reg([string]$Path, [string]$Name) {
    $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($null -eq $v) { return $null }
    return $v
}
function Get-AuditSetting([string]$Sub) {
    $line = (& auditpol /get /subcategory:"$Sub" 2>$null | Select-String -Pattern "^\s+$([regex]::Escape($Sub))\s{2,}(.+)$")
    if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
    return 'unknown'
}

$fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
$netacc = (& net accounts 2>$null) -join "`n"
function Get-NetAcc([string]$Label) {
    $m = [regex]::Match($netacc, "$([regex]::Escape($Label))\s*:?\s+(\S+)")
    if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}
$guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
$sysmon = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1

$posture = [ordered]@{
    host                         = $env:COMPUTERNAME
    os                           = (Get-CimInstance Win32_OperatingSystem).Caption
    collected_at                 = (Get-Date).ToUniversalTime().ToString('o')

    # logging
    audit_process_creation       = Get-AuditSetting 'Process Creation'
    audit_logon                  = Get-AuditSetting 'Logon'
    audit_account_management     = Get-AuditSetting 'User Account Management'
    audit_policy_change          = Get-AuditSetting 'Audit Policy Change'
    cmdline_in_4688              = [int](Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled')
    ps_scriptblock_logging       = [int](Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging')
    ps_module_logging            = [int](Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging')
    security_log_max_mb          = [int]((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1MB)
    sysmon_running               = [bool]($sysmon -and $sysmon.Status -eq 'Running')

    # credential protection
    lsa_runasppl                 = [int](Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
    wdigest_uselogoncredential   = [int](Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential')
    lm_compatibility_level       = [int](Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel')
    restrict_anonymous_sam       = [int](Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM')
    restrict_anonymous           = [int](Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous')
    cached_logons_count          = [int](Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount')
    credential_guard_running     = [bool]((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning -contains 1)
    local_account_token_filter   = [int](Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy')

    # legacy / attack surface
    smb1_enabled                 = [bool]($smb1 -and $smb1.State -eq 'Enabled')
    smb_signing_required         = [bool](Get-SmbServerConfiguration).RequireSecuritySignature
    llmnr_disabled               = ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0)
    netbios_over_tcpip           = [int]((Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled | Select-Object -First 1).TcpipNetbiosOptions)
    powershell_v2_enabled        = [bool]($ps2 -and $ps2.State -eq 'Enabled')
    autorun_disabled             = ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -eq 255)
    wsh_enabled                  = ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled') -ne 0)

    # remote access
    rdp_enabled                  = ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0)
    rdp_nla_required             = ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1)
    winrm_basic_auth             = [bool]((Get-Item WSMan:\localhost\Service\Auth\Basic).Value -eq 'true')
    winrm_unencrypted            = [bool]((Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value -eq 'true')
    firewall_domain_on           = [bool](($fw | Where-Object Name -eq 'Domain').Enabled)
    firewall_private_on          = [bool](($fw | Where-Object Name -eq 'Private').Enabled)
    firewall_public_on           = [bool](($fw | Where-Object Name -eq 'Public').Enabled)

    # defender
    defender_realtime            = [bool]($defender.RealTimeProtectionEnabled)
    defender_signatures_age_days = [int]$defender.AntivirusSignatureAge
    defender_tamper_protection   = [bool]($defender.IsTamperProtected)

    # uac + accounts
    uac_enabled                  = ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1)
    uac_admin_prompt             = [int](Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')
    guest_enabled                = [bool]($guest -and $guest.Enabled)
    min_password_length          = [int](Get-NetAcc 'Minimum password length')
    lockout_threshold            = (Get-NetAcc 'Lockout threshold')
    local_admins                 = @(Get-LocalGroupMember -Group Administrators | Select-Object -ExpandProperty Name) -join ';'
    pending_reboot               = [bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}
$posture | ConvertTo-Json -Compress -Depth 3
