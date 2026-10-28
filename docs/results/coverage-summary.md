# Detection coverage: SigmaHQ windows rules vs EVTX-ATTACK-SAMPLES (2026-10-28)

- Samples: **270** (142 with technique labels)
- Events replayed: **36,564** in 42.7s (857 ev/s)
- Rules: **2425** loaded, 0 failed to compile
- Alerts: **953**
- Samples with any alert: **71%** (193/270)
- Labelled samples where the right technique fired: **46%** (66/142)
- Samples with parse errors: 0

## By tactic

| tactic | samples | any alert | right technique |
|---|---:|---:|---:|
| command-and-control | 6 | 4 (67%) | 4 |
| credential-access | 39 | 30 (77%) | 12 |
| defense-evasion | 36 | 25 (69%) | 3 |
| discovery | 11 | 4 (36%) | 0 |
| execution | 34 | 27 (79%) | 10 |
| lateral-movement | 47 | 28 (60%) | 7 |
| persistence | 22 | 16 (73%) | 1 |
| privilege-escalation | 66 | 57 (86%) | 28 |
| unknown | 9 | 2 (22%) | 1 |

## By technique

| technique | samples | detected | rate | noisy-only |
|---|---:|---:|---:|---:|
| T1003.001 | 13 | 7 | 54% | 5 |
| T1003.002 | 1 | 0 | 0% | 1 |
| T1003.003 | 2 | 1 | 50% | 1 |
| T1003.006 | 2 | 1 | 50% | 1 |
| T1021.001 | 13 | 4 | 31% | 4 |
| T1021.002 | 6 | 2 | 33% | 2 |
| T1021.003 | 3 | 0 | 0% | 1 |
| T1021.006 | 3 | 1 | 33% | 1 |
| T1033 | 1 | 1 | 100% | 0 |
| T1047 | 7 | 3 | 43% | 3 |
| T1053.005 | 5 | 1 | 20% | 2 |
| T1055 | 1 | 1 | 100% | 0 |
| T1055.012 | 1 | 1 | 100% | 0 |
| T1059.001 | 9 | 5 | 56% | 0 |
| T1059.005 | 1 | 1 | 100% | 0 |
| T1068 | 4 | 0 | 0% | 3 |
| T1070.001 | 2 | 0 | 0% | 2 |
| T1070.006 | 1 | 0 | 0% | 1 |
| T1087.002 | 1 | 0 | 0% | 1 |
| T1098 | 1 | 1 | 100% | 0 |
| T1134 | 3 | 0 | 0% | 2 |
| T1134.001 | 5 | 2 | 40% | 1 |
| T1178 | 1 | 0 | 0% | 1 |
| T1186 | 1 | 0 | 0% | 0 |
| T1187 | 1 | 0 | 0% | 0 |
| T1197 | 4 | 0 | 0% | 1 |
| T1218 | 7 | 4 | 57% | 2 |
| T1218.005 | 4 | 2 | 50% | 2 |
| T1218.010 | 2 | 1 | 50% | 0 |
| T1218.011 | 9 | 8 | 89% | 1 |
| T1543.003 | 8 | 0 | 0% | 3 |
| T1547.001 | 1 | 1 | 100% | 0 |
| T1548.002 | 37 | 25 | 68% | 10 |
| T1558.003 | 1 | 0 | 0% | 1 |
| T1562.004 | 1 | 0 | 0% | 1 |
| T1562.006 | 3 | 0 | 0% | 1 |
| T1569.002 | 4 | 2 | 50% | 0 |
| T1572 | 4 | 0 | 0% | 3 |
| T1574.002 | 2 | 0 | 0% | 2 |

## Noisiest rules

| rule | hits |
|---|---:|
| Remote Thread Creation In Uncommon Target Image | 93 |
| Potential Persistence Via Shim Database Modification | 30 |
| RunMRU Registry Key Deletion - Registry | 25 |
| Suspicious SYSTEM User Process Creation | 25 |
| Security Eventlog Cleared | 24 |
| Local Accounts Discovery | 24 |
| HackTool - UACMe Akagi Execution | 23 |
| Windows Default Domain GPO Modification | 22 |
| Powerview Add-DomainObjectAcl DCSync AD Extend Right | 20 |
| Microsoft IIS Service Account Password Dumped | 18 |
| Unsigned DLL Loaded by Windows Utility | 18 |
| Potential Credential Dumping Activity Via LSASS | 16 |
| Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | 16 |
| Potentially Suspicious Rundll32 Activity | 13 |
| WmiPrvSE Spawned A Process | 11 |
| Whoami.EXE Execution From Privileged Process | 11 |
| Password Policy Enumerated | 11 |
| Abused Debug Privilege by Arbitrary Parent Processes | 11 |
| Potential Shim Database Persistence via Sdbinst.EXE | 11 |
| MSSQL Server Failed Logon | 10 |
| Non Interactive PowerShell Process Spawned | 10 |
| Windows Processes Suspicious Parent Directory | 9 |
| Suspicious Process Parents | 9 |
| Unusual Parent Process For Cmd.EXE | 9 |
| HackTool - Potential Impacket Lateral Movement Activity | 9 |

## Labelled samples with no alert at all

- `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` (T1021.001, T1572, T1543.003, 228 events)
- `Command and Control/bits_openvpn.evtx` (T1197, 1537 events)
- `Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx` (T1187, T1562.006, 29109 events)
- `Credential Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx` (T1003.001, 2 events)
- `Credential Access/etw_rpc_zerologon.evtx` (T1068, T1562.006, 415 events)
- `Defense Evasion/DE_EventLog_Service_Crashed.evtx` (T1543.003, 4 events)
- `Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx` (T1059.001, 1 events)
- `Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx` (T1569.002, T1543.003, 11 events)
- `Defense Evasion/Win_4985_T1186_Process_Doppelganging.evtx` (T1186, 2 events)
- `Defense Evasion/de_powershell_execpolicy_changed_sysmon_13.evtx` (T1059.001, 5 events)
- `Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.evtx` (T1134.001, 20 events)
- `Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx` (T1218.010, T1218, 2 events)
- `Execution/temp_scheduled_task_4698_4699.evtx` (T1053.005, 2 events)
- `Execution/windows_bits_4_59_60_lolbas desktopimgdownldr.evtx` (T1197, 5 events)
- `Lateral Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx` (T1021.001, 21 events)
- `Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx` (T1543.003, 1 events)
- `Lateral Movement/LM_Remote_Service02_7045.evtx` (T1543.003, 3 events)
- `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx` (T1047, 8 events)
- `Lateral Movement/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx` (T1134.001, 1 events)
- `Lateral Movement/LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx` (T1021.003, 4 events)
- `Lateral Movement/LM_renamed_psexecsvc_5145.evtx` (T1569.002, 22 events)
- `Lateral Movement/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx` (T1021.003, 3 events)
- `Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx` (T1059.001, 3 events)
- `Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` (T1021.006, 1 events)
- `Lateral Movement/RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx` (T1059.001, 6 events)
- `Lateral Movement/dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx` (T1021.001, 40 events)
- `Lateral Movement/sharprdp_sysmon_7_mstscax.dll.evtx` (T1021.001, 4 events)
- `Lateral Movement/smb_bi_auth_conn_spoolsample.evtx` (T1021.002, 2 events)
- `Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.evtx` (T1021.001, 733 events)
- `Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx` (T1197, 6 events)
- `Privilege Escalation/PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx` (T1053.005, 4 events)
- `Privilege Escalation/PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx` (T1134, T1021.002, 1 events)
- `Privilege Escalation/UACME_61_Changepk.evtx` (T1548.002, 2 events)
- `Privilege Escalation/sysmon_13_1_12_11_perfmonUACBypass.evtx` (T1548.002, 5 events)
