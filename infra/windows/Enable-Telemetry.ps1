<#
.SYNOPSIS
    Turn a Windows lab host into a well-instrumented detection target.

.DESCRIPTION
    Installs Sysmon with a community configuration, enables the audit
    subcategories that SigmaHQ rules depend on, adds command lines to 4688,
    turns on PowerShell script-block and module logging, and grows the
    Security log so lab runs are not truncated.

    Idempotent: safe to re-run. Requires an elevated session on the target.

.PARAMETER SysmonConfigUrl
    Sysmon XML configuration to apply. Defaults to SwiftOnSecurity/sysmon-config.
#>
# rangeforge-collector: tagged so the telemetry collector can drop its own script-block events
[CmdletBinding()]
param(
    [string]$SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [string]$SysmonZipUrl = 'https://download.sysinternals.com/files/Sysmon.zip',
    [int]$SecurityLogMB = 512,
    [int]$SysmonLogMB = 512,
    [int]$PowerShellLogMB = 256
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = Join-Path $env:ProgramData 'RangeForge'
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Write-Step([string]$Text) { Write-Host "==> $Text" }
function Ensure-Key([string]$Path) { if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null } }

# ---------------------------------------------------------------- Sysmon
Write-Step 'Sysmon'
$configPath = Join-Path $work 'sysmonconfig.xml'
Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configPath -UseBasicParsing
$svc = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $svc) {
    $zip = Join-Path $work 'Sysmon.zip'
    Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath (Join-Path $work 'sysmon') -Force
    $exe = Join-Path $work 'sysmon\Sysmon64.exe'
    # Sysmon writes its banner to stderr; in a remote session that would be
    # promoted to a terminating error, so route through cmd and inspect text.
    $out = (& cmd /c "`"$exe`" -accepteula -i `"$configPath`" 2>&1") -join ' ' -replace "`0", ''
    if (-not (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue)) { throw "Sysmon install failed: $out" }
    Write-Host '    installed'
} else {
    $exe = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'").PathName.Trim('"')
    # Sysmon prints UTF-16; strip the interleaved NULs before inspecting the text.
    $out = (& cmd /c "`"$exe`" -c `"$configPath`" 2>&1") -join ' ' -replace "`0", ''
    if ($LASTEXITCODE -ne 0 -or $out -notmatch 'Configuration updated') { throw "Sysmon config refresh failed: $out" }
    Write-Host '    configuration refreshed'
}

# ---------------------------------------------------------------- Audit policy
Write-Step 'Audit policy'
$subcategories = @(
    'Process Creation', 'Process Termination',
    'Logon', 'Logoff', 'Special Logon', 'Other Logon/Logoff Events', 'Account Lockout',
    'Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations',
    'User Account Management', 'Security Group Management', 'Computer Account Management',
    'Security System Extension', 'System Integrity', 'Other System Events',
    'Audit Policy Change', 'Authentication Policy Change',
    'Sensitive Privilege Use',
    'File Share', 'Detailed File Share', 'Removable Storage', 'Other Object Access Events',
    'Registry', 'File System', 'SAM', 'Directory Service Access'
)
foreach ($sub in $subcategories) {
    $null = & cmd /c "auditpol /set /subcategory:`"$sub`" /success:enable /failure:enable 2>&1"
}
# Force advanced audit policy so legacy categories do not override subcategories.
Ensure-Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
# Command line in 4688
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Ensure-Key $auditKey
Set-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
Write-Host "    $($subcategories.Count) subcategories enabled, command line in 4688"

# ---------------------------------------------------------------- PowerShell logging
Write-Step 'PowerShell logging'
$psPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Ensure-Key "$psPolicy\ScriptBlockLogging"
Set-ItemProperty -Path "$psPolicy\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
Ensure-Key "$psPolicy\ModuleLogging"
Set-ItemProperty -Path "$psPolicy\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Ensure-Key "$psPolicy\ModuleLogging\ModuleNames"
Set-ItemProperty -Path "$psPolicy\ModuleLogging\ModuleNames" -Name '*' -Value '*'
Write-Host '    script block + module logging on'

# ---------------------------------------------------------------- Log sizes
Write-Step 'Event log sizes'
$sizes = @{
    'Security' = $SecurityLogMB
    'Microsoft-Windows-Sysmon/Operational' = $SysmonLogMB
    'Microsoft-Windows-PowerShell/Operational' = $PowerShellLogMB
}
foreach ($log in $sizes.Keys) {
    $null = & cmd /c "wevtutil set-log `"$log`" /maxsize:$($sizes[$log] * 1MB) /retention:false 2>&1"
}
$null = & cmd /c "wevtutil set-log `"Microsoft-Windows-TaskScheduler/Operational`" /enabled:true 2>&1"
$null = & cmd /c "wevtutil set-log `"Microsoft-Windows-DNS-Client/Operational`" /enabled:true 2>&1" 
Write-Host '    done'

# ---------------------------------------------------------------- Summary
Write-Step 'Summary'
[pscustomobject]@{
    Host         = $env:COMPUTERNAME
    Sysmon       = (Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1).Status
    ProcessAudit = ((& cmd /c 'auditpol /get /subcategory:"Process Creation" 2>&1') | Select-String 'Process Creation').ToString().Trim()
    CmdLine4688  = (Get-ItemProperty $auditKey).ProcessCreationIncludeCmdLine_Enabled
    ScriptBlock  = (Get-ItemProperty "$psPolicy\ScriptBlockLogging").EnableScriptBlockLogging
} | Format-List
