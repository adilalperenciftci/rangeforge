# Detection coverage: SigmaHQ windows rules vs EVTX-ATTACK-SAMPLES, all 270 captures labelled (2026-10-28)

- Samples: **270** (270 with technique labels)
- Events replayed: **36,564** in 41.4s (882 ev/s)
- Rules: **2428** loaded, 0 failed to compile
- Alerts: **1,010**
- Samples with any alert: **73%** (196/270)
- Labelled samples where the right technique fired: **38%** (102/270)
- Samples with parse errors: 0

## By tactic

| tactic | samples | any alert | right technique |
|---|---:|---:|---:|
| command-and-control | 6 | 4 (67%) | 4 |
| credential-access | 39 | 31 (79%) | 19 |
| defense-evasion | 36 | 25 (69%) | 11 |
| discovery | 11 | 5 (45%) | 1 |
| execution | 34 | 27 (79%) | 17 |
| lateral-movement | 47 | 29 (62%) | 12 |
| persistence | 22 | 16 (73%) | 8 |
| privilege-escalation | 66 | 57 (86%) | 29 |
| unknown | 9 | 2 (22%) | 1 |

## By technique

| technique | samples | detected | rate | noisy-only |
|---|---:|---:|---:|---:|
| T1003.001 | 18 | 12 | 67% | 5 |
| T1003.002 | 2 | 0 | 0% | 2 |
| T1003.003 | 2 | 1 | 50% | 1 |
| T1003.006 | 2 | 1 | 50% | 1 |
| T1014 | 1 | 0 | 0% | 1 |
| T1021.001 | 14 | 4 | 29% | 5 |
| T1021.002 | 12 | 2 | 17% | 6 |
| T1021.003 | 4 | 1 | 25% | 1 |
| T1021.006 | 3 | 1 | 33% | 1 |
| T1033 | 4 | 1 | 25% | 1 |
| T1036 | 2 | 1 | 50% | 1 |
| T1047 | 7 | 3 | 43% | 4 |
| T1049 | 2 | 0 | 0% | 0 |
| T1053.005 | 8 | 3 | 38% | 2 |
| T1055 | 5 | 4 | 80% | 0 |
| T1055.012 | 2 | 1 | 50% | 0 |
| T1056.001 | 1 | 0 | 0% | 0 |
| T1057 | 1 | 0 | 0% | 1 |
| T1059.001 | 17 | 5 | 29% | 2 |
| T1059.003 | 5 | 2 | 40% | 2 |
| T1059.005 | 2 | 2 | 100% | 0 |
| T1059.007 | 1 | 0 | 0% | 1 |
| T1068 | 13 | 0 | 0% | 9 |
| T1069.001 | 2 | 0 | 0% | 0 |
| T1069.002 | 1 | 1 | 100% | 0 |
| T1070 | 1 | 1 | 100% | 0 |
| T1070.001 | 2 | 0 | 0% | 2 |
| T1070.006 | 1 | 0 | 0% | 1 |
| T1082 | 1 | 0 | 0% | 1 |
| T1087.001 | 1 | 0 | 0% | 0 |
| T1087.002 | 1 | 0 | 0% | 1 |
| T1098 | 5 | 1 | 20% | 1 |
| T1105 | 2 | 1 | 50% | 1 |
| T1110.001 | 1 | 1 | 100% | 0 |
| T1110.003 | 1 | 0 | 0% | 1 |
| T1112 | 1 | 0 | 0% | 1 |
| T1127 | 1 | 0 | 0% | 1 |
| T1134 | 6 | 0 | 0% | 3 |
| T1134.001 | 12 | 2 | 17% | 8 |
| T1134.002 | 1 | 0 | 0% | 1 |
| T1134.004 | 1 | 0 | 0% | 0 |
| T1135 | 1 | 0 | 0% | 0 |
| T1136.001 | 2 | 1 | 50% | 0 |
| T1136.002 | 1 | 0 | 0% | 1 |
| T1137 | 1 | 0 | 0% | 1 |
| T1178 | 1 | 0 | 0% | 1 |
| T1186 | 1 | 0 | 0% | 0 |
| T1187 | 2 | 0 | 0% | 0 |
| T1189 | 1 | 0 | 0% | 0 |
| T1197 | 4 | 0 | 0% | 1 |
| T1203 | 1 | 0 | 0% | 0 |
| T1204.002 | 1 | 0 | 0% | 0 |
| T1207 | 1 | 1 | 100% | 0 |
| T1218 | 8 | 4 | 50% | 2 |
| T1218.001 | 1 | 1 | 100% | 0 |
| T1218.002 | 1 | 0 | 0% | 0 |
| T1218.005 | 4 | 2 | 50% | 2 |
| T1218.007 | 2 | 1 | 50% | 1 |
| T1218.010 | 2 | 1 | 50% | 0 |
| T1218.011 | 9 | 8 | 89% | 1 |
| T1220 | 1 | 1 | 100% | 0 |
| T1484.001 | 1 | 0 | 0% | 0 |
| T1505.001 | 4 | 0 | 0% | 3 |
| T1505.003 | 3 | 1 | 33% | 2 |
| T1543.003 | 8 | 0 | 0% | 3 |
| T1546 | 1 | 0 | 0% | 0 |
| T1546.003 | 1 | 1 | 100% | 0 |
| T1546.008 | 1 | 0 | 0% | 1 |
| T1546.011 | 2 | 1 | 50% | 0 |
| T1546.012 | 1 | 1 | 100% | 0 |
| T1546.015 | 2 | 1 | 50% | 0 |
| T1547 | 1 | 0 | 0% | 1 |
| T1547.001 | 4 | 4 | 100% | 0 |
| T1547.004 | 1 | 0 | 0% | 1 |
| T1548.002 | 38 | 25 | 66% | 11 |
| T1550.002 | 1 | 0 | 0% | 1 |
| T1552.001 | 1 | 0 | 0% | 1 |
| T1553.006 | 2 | 0 | 0% | 1 |
| T1555 | 1 | 0 | 0% | 0 |
| T1555.003 | 2 | 0 | 0% | 2 |
| T1555.004 | 1 | 0 | 0% | 1 |
| T1555.005 | 2 | 2 | 100% | 0 |
| T1557.001 | 3 | 0 | 0% | 3 |
| T1558 | 1 | 0 | 0% | 0 |
| T1558.003 | 1 | 0 | 0% | 1 |
| T1562.001 | 3 | 0 | 0% | 3 |
| T1562.002 | 3 | 0 | 0% | 1 |
| T1562.004 | 1 | 0 | 0% | 1 |
| T1562.006 | 3 | 0 | 0% | 1 |
| T1564 | 1 | 0 | 0% | 1 |
| T1564.001 | 1 | 1 | 100% | 0 |
| T1569.002 | 5 | 2 | 40% | 0 |
| T1570 | 2 | 0 | 0% | 1 |
| T1572 | 4 | 0 | 0% | 3 |
| T1574.001 | 5 | 1 | 20% | 4 |
| T1574.002 | 2 | 0 | 0% | 2 |
| T1574.009 | 1 | 0 | 0% | 1 |

## Noisiest rules

| rule | hits |
|---|---:|
| Remote Thread Creation In Uncommon Target Image | 93 |
| Successful Logon | 42 |
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
| LSASS Process Access | 13 |
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

## Labelled samples with no alert at all

- `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` (T1021.001, T1572, T1543.003, 228 events)
- `Command and Control/bits_openvpn.evtx` (T1197, 1537 events)
- `Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx` (T1187, T1562.006, 29109 events)
- `Credential Access/CA_teamviewer-dumper_sysmon_10.evtx` (T1555, 1 events)
- `Credential Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx` (T1003.001, 2 events)
- `Credential Access/Sysmon13_MachineAccount_Password_Hash_Changed_via_LsarSetSecret.evtx` (T1098, 4 events)
- `Credential Access/Sysmon_13_Local_Admin_Password_Changed.evtx` (T1098, 1 events)
- `Credential Access/etw_rpc_zerologon.evtx` (T1068, T1562.006, 415 events)
- `Credential Access/sysmon17_18_kekeo_tsssp_default_np.evtx` (T1558, 3 events)
- `Credential Access/sysmon_13_keylogger_directx.evtx` (T1056.001, 6 events)
- `Defense Evasion/DE_EventLog_Service_Crashed.evtx` (T1543.003, 4 events)
- `Defense Evasion/DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx` (T1553.006, 6 events)
- `Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx` (T1059.001, 1 events)
- `Defense Evasion/DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx` (T1055.012, 4 events)
- `Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx` (T1562.002, 6 events)
- `Defense Evasion/DE_remote_eventlog_svc_crash_byt3bl33d3r_sysmon_17_1_3.evtx` (T1562.002, 11 events)
- `Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx` (T1569.002, T1543.003, 11 events)
- `Defense Evasion/Win_4985_T1186_Process_Doppelganging.evtx` (T1186, 2 events)
- `Defense Evasion/de_powershell_execpolicy_changed_sysmon_13.evtx` (T1059.001, 5 events)
- `Defense Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx` (T1055, 1 events)
- `Defense Evasion/sysmon_10_1_ppid_spoofing.evtx` (T1134.004, 5 events)
- `Discovery/4799_remote_local_groups_enumeration.evtx` (T1069.001, 5 events)
- `Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.evtx` (T1134.001, 20 events)
- `Discovery/discovery_enum_shares_target_sysmon_3_18.evtx` (T1135, 4 events)
- `Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx` (T1087.001, T1069.001, 3 events)
- `Discovery/discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx` (T1033, T1049, 1 events)
- `Discovery/discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx` (T1033, T1049, 9 events)
- `Execution/Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet.evtx` (T1218.002, 4 events)
- `Execution/evasion_execution_imageload_wuauclt_lolbas.evtx` (T1218, 3 events)
- `Execution/exec_driveby_cve-2018-15982_sysmon_1_10.evtx` (T1189, T1203, 2 events)
- `Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx` (T1218.010, T1218, 2 events)
- `Execution/revshell_cmd_svchost_sysmon_1.evtx` (T1059.003, 4 events)
- `Execution/temp_scheduled_task_4698_4699.evtx` (T1053.005, 2 events)
- `Execution/windows_bits_4_59_60_lolbas desktopimgdownldr.evtx` (T1197, 5 events)
- `Lateral Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx` (T1021.001, 21 events)
- `Lateral Movement/LM_5145_Remote_FileCopy.evtx` (T1021.002, T1570, 869 events)
- `Lateral Movement/LM_NewShare_Added_Sysmon_12_13.evtx` (T1021.002, 3 events)
- `Lateral Movement/LM_REMCOM_5145_TargetHost.evtx` (T1569.002, 30 events)
- `Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx` (T1543.003, 1 events)
- `Lateral Movement/LM_Remote_Service02_7045.evtx` (T1543.003, 3 events)
- `Lateral Movement/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx` (T1134.001, 1 events)
- `Lateral Movement/LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx` (T1021.003, 4 events)
- `Lateral Movement/LM_renamed_psexecsvc_5145.evtx` (T1569.002, 22 events)
- `Lateral Movement/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx` (T1021.003, 3 events)
- `Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx` (T1059.001, 3 events)
- `Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` (T1021.006, 1 events)
- `Lateral Movement/MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx` (T1505.001, 1 events)
- `Lateral Movement/RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx` (T1059.001, 6 events)
- `Lateral Movement/dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx` (T1021.001, 40 events)
- `Lateral Movement/sharprdp_sysmon_7_mstscax.dll.evtx` (T1021.001, 4 events)
- `Lateral Movement/smb_bi_auth_conn_spoolsample.evtx` (T1021.002, 2 events)
- `Lateral Movement/spoolsample_5145.evtx` (T1187, 1 events)
- `Other/emotet/exec_emotet_ps_4104.evtx` (T1059.001, 1 events)
- `Other/emotet/exec_emotet_ps_800_get-item.evtx` (T1059.001, 1 events)
- `Other/emotet/exec_emotet_ps_800_invoke-item.evtx` (T1059.001, 1 events)
- `Other/emotet/exec_emotet_ps_800_new-item.evtx` (T1059.001, 1 events)
- `Other/emotet/exec_emotet_ps_800_new-object.evtx` (T1059.001, 1 events)
- `Other/emotet/exec_emotet_sysmon_1.evtx` (T1059.001, T1204.002, 1 events)
- `Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.evtx` (T1021.001, 733 events)
- `Persistence/Persistence_Shime_Microsoft-Windows-Application-Experience_Program-Telemetry_500.evtx` (T1546.011, 7 events)
- `Persistence/Persistence_Winsock_Catalog Change EventId_1.evtx` (T1546, 2 events)
- `Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx` (T1197, 6 events)
- `Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx` (T1546.015, 19 events)
- `Persistence/persistence_pendingGPO_sysmon_13.evtx` (T1484.001, 4 events)
- `Persistence/sysmon_local_account_creation_and_added_admingroup_12_13.evtx` (T1136.001, T1098, 17 events)
- `Privilege Escalation/PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx` (T1053.005, 4 events)
- `Privilege Escalation/PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx` (T1134, T1021.002, 1 events)
- `Privilege Escalation/PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx` (T1134, T1053.005, 2 events)
- `Privilege Escalation/UACME_61_Changepk.evtx` (T1548.002, 2 events)
- `Privilege Escalation/privesc_registry_symlink_CVE-2020-1377.evtx` (T1068, 30 events)
- `Privilege Escalation/privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.evtx` (T1068, 4 events)
- `Privilege Escalation/privesc_sysmon_cve_20201030_spooler.evtx` (T1068, 8 events)
- `Privilege Escalation/sysmon_13_1_12_11_perfmonUACBypass.evtx` (T1548.002, 5 events)
- `Privilege Escalation/win10_4703_SeDebugPrivilege_enabled.evtx` (T1134, 1 events)
