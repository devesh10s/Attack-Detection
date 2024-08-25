// IMPACT
#include "win_impact_rules.h"
#include <sstream>
// T1489: Service Stop
/*
"i) select path, parent_path, cmdline from win_process_events where (parent_path like '%powershell.exe%' or parent_path like '%cmd.exe%') and path like '%sc.exe%' and cmdline like '%sc.exe% stop %';
ii) select path, parent_path, cmdline from win_process_events where parent_path like '%net.exe%'  and path like '%net1.exe%' and cmdline like '%net1% stop %';
iii) select path, parent_path, cmdline from win_process_events where (parent_path like '%powershell.exe%' or parent_path like '%cmd.exe%') and path like '%taskkill.exe' and cmdline like '%taskkill.exe%/im%';"
*/

bool service_stop_one(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string parent_path = win_process_event.entry.parent_path;
	std::string path = win_process_event.entry.path;
	std::string cmdline = win_process_event.entry.cmdline;
	if ((parent_path.find("powershell.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos) && path.find("sc.exe") != std::string::npos && cmdline.find("sc.exe") != std::string::npos && cmdline.find("stop") != std::string::npos)
	{
		rule_event.metadata = "Attempt to stop a service";
		return true;
	}
	return false;
}

bool service_stop_two(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string parent_path = win_process_event.entry.parent_path;
	std::string path = win_process_event.entry.path;
	std::string cmdline = win_process_event.entry.cmdline;
	if (parent_path.find("net.exe") != std::string::npos && path.find("net1.exe") != std::string::npos && cmdline.find("net1") != std::string::npos && cmdline.find("stop") != std::string::npos)
	{
		rule_event.metadata = "Attempt to stop a service";
		return true;
	}
	return false;
}

bool service_stop_three(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string parent_path = win_process_event.entry.parent_path;
	std::string path = win_process_event.entry.path;
	std::string cmdline = win_process_event.entry.cmdline;
	if ((parent_path.find("powershell.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos) && path.find("taskkill.exe") != std::string::npos && cmdline.find("taskkill.exe") != std::string::npos && cmdline.find("im") != std::string::npos)
	{
		rule_event.metadata = "Attempt to stop a service";
		return true;
	}
	return false;
}

// T1491: Defacement: Internal Defacement
/*
i) select * from win_process_events where cmdline like '%namespace Win32{%DllImport%SystemParametersInfo%';
ii) select * from win_process_events where cmdline like '%HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption%' or cmdline like '%HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText -Value $newLegalNoticeText%';
*/

bool internal_defacement_one(const ProcessEvent &win_process_event, Event &rule_event)
{
	if (win_process_event.entry.cmdline.find("namespace Win32") != std::string::npos && win_process_event.entry.cmdline.find("DllImport") != std::string::npos && win_process_event.entry.cmdline.find("SystemParametersInfo") != std::string::npos)
	{
		rule_event.metadata = "Defacement: Internal Defacement";
		return true;
	}
	return false;
}

bool internal_defacement_two(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name LegalNoticeCaption") != std::string::npos && process_event.entry.cmdline.find("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name LegalNoticeText -Value $newLegalNoticeText") != std::string::npos)
	{
		rule_event.metadata = "Defacement: Internal Defacement";
		return true;
	}
	return false;
}

// T1486 - Data Encrypted for Impact
//  select * from win_process_events where cmdline like '%GnuPG\\bin\\gpg.exe%';

bool data_encrypted_impact(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("GnuPG\\bin\\gpg.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Data encrypted to to interrupt availability of system";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1490 - Inhibit System Recovery, Disable System Restore Through Registry

bool inhibit_system_recovery_registry(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Policies\\Microsoft\\Windows NT\\SystemRestore") != std::string::npos && cmdline.find("DisableConfig") != std::string::npos && cmdline.find("DisableSR") != std::string::npos)
	{
		std::stringstream ss;
		ss << "System restore disabled through registry";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1531 - Remove Account From Domain Admin Group
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Get-ADUser%' and cmdline like '%Remove-ADGroupMember%' and cmdline like '%-Identity%' and cmdline like '%-Members%');

bool remove_account_from_domain_admin_group(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-ADUser") != std::string::npos && cmdline.find("Remove-ADGroupMember") != std::string::npos && cmdline.find("-Identity") != std::string::npos && cmdline.find("-Members") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Account removed from domain admin group";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1491.001 - Replace Desktop Wallpaper by Powershell
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Get-ItemProperty%' and cmdline like '%Registry::%' and cmdline like '%HKEY_CURRENT_USER\Control Panel\Desktop\%' and cmdline like '%c%');

bool replace_desktop_wallpaper_by_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-ItemProperty") != std::string::npos && cmdline.find("Registry::") != std::string::npos && cmdline.find("HKEY_CURRENT_USER\\Control Panel\\Desktop\\") != std::string::npos && cmdline.find("WallPaper") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Account removed from domain admin group";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// Impact Rules

// T1565 - Powershell Add Name Resolution Policy Table Rule
//  select * from win_process_events where cmdline like '%Add-DnsClientNrptRule%' and cmdline like '%-Namesp%' and cmdline like '%-NameSe%';

bool powershell_add_name_resolution_policy_table_rule(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	if (cmdline.find("Add-DnsClientNrptRule") != std::string::npos && cmdline.find("-Namesp") != std::string::npos && cmdline.find("-NameSe") != std::string::npos)
	{
		rule_event.metadata = "Default DNS server bypassed and may use a specified server for answering the query";
		return true;
	}
	return false;
}

// T1496 - Potential Crypto Mining Activity
//  select * from win_process_events where (cmdline like '%--cpu-priority=%' or cmdline like '%--donate-level=0%' or cmdline like '%stratum%') and (cmdline like '%pool.c%' or cmdline like '%pool.o%' or cmdline like '%gcc -%');

bool potential_crypto_mining_activity(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	{
		rule_event.metadata = "Detected potential crypto mining activity";
		return true;
	}
	return false;
}

// T1496 - Potential Crypto Monero Mining
//  select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%xmrig%' and cmdline like '%Expand-Archive%' and cmdline like '%-WindowStyle%' and cmdline like '%pool.c%' and cmdline like '%pool.o%' and cmdline like '%gcc -%';

bool potential_crypto_monero_mining(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("xmrig") != std::string::npos && cmdline.find("Expand-Archive") != std::string::npos && cmdline.find("-WindowStyle") != std::string::npos && cmdline.find("pool.c") != std::string::npos && cmdline.find("pool.o") != std::string::npos && cmdline.find("gcc -") != std::string::npos)
	{
		rule_event.metadata = "Crypto Monero mining detected (Monero miner - xmrig)";
		return true;
	}
	return false;
}

// T1489 - Stop Windows Service Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% stop%');

bool stop_windows_service_via_net_exe(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	std::string path = win_process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" stop") != std::string::npos)
	{
		rule_event.metadata = "Stop Windows Service Via Net.EXE";
		return true;
	}
	return false;
}

// T1486 - Suspicious Reg Add BitLocker
//  select * from win_process_events where (cmdline like '%REG%' and cmdline like '%ADD%' and cmdline like '%\SOFTWARE\Policies\Microsoft\FVE%' and cmdline like '%/v%' and cmdline like '%/f%') and (cmdline like '%EnableBDEWithNoTPM%' or cmdline like '%UseAdvancedStartup%' or cmdline like '%UseTPM%' or cmdline like '%UseTPMKey%' or cmdline like '%UseTPMKeyPIN%' or cmdline like '%RecoveryKeyMessageSource%' or cmdline like '%UseTPMPIN%' or cmdline like '%RecoveryKeyMessage%');

bool suspicious_reg_add_bitlocker(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	if ((cmdline.find("REG") != std::string::npos && cmdline.find("ADD") != std::string::npos && cmdline.find("\\SOFTWARE\\Policies\\Microsoft\\FVE") != std::string::npos && cmdline.find("/v") != std::string::npos && cmdline.find("/f") != std::string::npos) && (cmdline.find("EnableBDEWithNoTPM") != std::string::npos || cmdline.find("UseAdvancedStartup") != std::string::npos || cmdline.find("UseTPM") != std::string::npos || cmdline.find("UseTPMKey") != std::string::npos || cmdline.find("UseTPMKeyPIN") != std::string::npos || cmdline.find("RecoveryKeyMessageSource") != std::string::npos || cmdline.find("UseTPMPIN") != std::string::npos || cmdline.find("RecoveryKeyMessage") != std::string::npos))
	{
		rule_event.metadata = "Detected suspicious addition to BitLocker related registry keys";
		return true;
	}
	return false;
}

// T1485 - Potential File Overwrite Via Sysinternals SDelete
//  SELECT * FROM win_process_events WHERE cmdline LIKE '%New-Item%' AND cmdline LIKE '%Invoke-Expression%' AND cmdline LIKE '%-Command%' AND cmdline LIKE '%-accepteula%' AND cmdline LIKE '%sdelete.exe%';

bool potential_file_overwrite_via_sysinternals_sDelete(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	if (cmdline.find("New-Item") != std::string::npos && cmdline.find("Invoke-Expression") != std::string::npos && cmdline.find("-Command") != std::string::npos && cmdline.find("-accepteula") != std::string::npos && cmdline.find("sdelete.exe") != std::string::npos)
	{
		rule_event.metadata = "Detected the use of SDelete to erase a file not the free space.";
		return true;
	}
	return false;
}

// T1486 - Renamed Gpg.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%gpg%') AND NOT (path LIKE '%\gpg.exe%' OR path LIKE '%\gpg2.exe%');

bool renamed_gpgexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("gpg") != std::string::npos) && !(path.find("\\gpg.exe") != std::string::npos || path.find("\\gpg2.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of a renamed 'gpg.exe'.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1490 - SystemStateBackup Deleted Using Wbadmin.EXE
//  SELECT * FROM win_process_events WHERE cmdline LIKE '%wbadmin%' AND cmdline LIKE '%delete%' AND cmdline LIKE '%systemstatebackup%' AND cmdline LIKE '%-keepVersions:%';

bool systemStateBackup_deleted_using_wbadmin_EXE(const ProcessEvent &win_process_event, Event &rule_event)
{
	std::string cmdline = win_process_event.entry.cmdline;
	
	if (cmdline.find("wbadmin") != std::string::npos &&
    cmdline.find("delete ") != std::string::npos &&
    cmdline.find("systemstatebackup ") != std::string::npos &&
    cmdline.find("-keepVersions:") != std::string::npos)

	{
		rule_event.metadata = "Detected the use of SDelete to erase a file not the free space.";
		return true;
	}
	return false;
}

// T1485 - Renamed Sysinternals Sdelete Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%sdelete%') AND NOT (path LIKE '%\sdelete.exe%' OR path LIKE '%\sdelete64.exe%');

bool renamed_sysinternals_sdelete_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("sdelete") != std::string::npos) && (path.find("\\sdelete.exe") != std::string::npos || path.find("\\sdelete64.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the use of a renamed SysInternals Sdelete";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

//T1490 - Deletion of Volume Shadow Copies via WMI with PowerShell
//SELECT * FROM win_process_events WHERE 
//cmdline LIKE '%Win32_Shadowcopy%' AND
//(cmdline LIKE '%Get-WmiObject%' OR 
//cmdline LIKE '%gwmi%' OR
//cmdline LIKE '%Get-CimInstance%' OR
//cmdline LIKE '%gcim%') AND
//(cmdline LIKE '%.Delete()%' OR
//cmdline LIKE '%Remove-WmiObject%' OR
//cmdline LIKE '%rwmi%' OR
//cmdline LIKE '%Remove-CimInstance%' OR
//cmdline LIKE '%rcim%');

bool deletion_of_volume_shadow_copies_via_wmi_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("Win32_Shadowcopy") != std::string::npos) &&
    (cmdline.find("Get-WmiObject") != std::string::npos || 
	cmdline.find("gwmi") != std::string::npos ||
	cmdline.find("Get-CimInstance") != std::string::npos ||
	cmdline.find("gcim") != std::string::npos) &&
	(cmdline.find(".Delete()") != std::string::npos ||
	cmdline.find("Remove-WmiObject") != std::string::npos ||
	cmdline.find("rwmi") != std::string::npos ||
	cmdline.find("Remove-CimInstance") != std::string::npos ||
	cmdline.find("rcim") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Deletion of Volume Shadow Copies via WMI with PowerShell";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

//T1490 - Stop Windows Service Via PowerShell Stop-Service
//SELECT * FROM win_process_events WHERE cmdline LIKE '%Stop-Service%';

bool stop_windows_service_via_powershell_stop_service(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("Stop-Service ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Stop Windows Service Via PowerShell Stop-Service";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

//T1489 - Stop Windows Service Via Sc.EXE
//SELECT * FROM win_process_events WHERE (path LIKE '%\sc.exe%' AND cmdline LIKE '% stop %') AND NOT ((cmdline LIKE '%sc  stop KSCWebConsoleMessageQueue%' OR cmdline LIKE '%sc  stop LGHUBUpdaterService%') AND (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%'));

bool stop_windows_service_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\sc.exe") != std::string::npos && cmdline.find(" stop ") != std::string::npos) && !((cmdline.find("sc  stop KSCWebConsoleMessageQueue") != std::string::npos || cmdline.find("sc  stop LGHUBUpdaterService") != std::string::npos) && (cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos)))
	{
		std::stringstream ss;

		ss << "Detected the stopping of a Windows service";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

//T1489 - Delete All Scheduled Tasks
//SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '% /delete %' AND cmdline LIKE '%/tn \*%' AND cmdline LIKE '% /f%');

bool delete_all_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find(" /delete ") != std::string::npos && cmdline.find("/tn \\*") != std::string::npos && cmdline.find(" /f") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the usage of schtasks to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1489 - Delete Important Scheduled Task
//SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '%/delete%' AND cmdline LIKE '%/tn%') AND (cmdline LIKE '%\Windows\SystemRestore\SR%' OR cmdline LIKE '%\Windows\Windows Defender\%' OR cmdline LIKE '%\Windows\BitLocker%' OR cmdline LIKE '%\Windows\WindowsBackup\%' OR cmdline LIKE '%\Windows\WindowsUpdate\%' OR cmdline LIKE '%\Windows\UpdateOrchestrator\%' OR cmdline LIKE '%\Windows\ExploitGuard%');

bool delete_important_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("/delete") != std::string::npos && cmdline.find("/tn") != std::string::npos) && (cmdline.find("\\Windows\\SystemRestore\\SR") != std::string::npos || cmdline.find("\\Windows\\Windows Defender\\") != std::string::npos || cmdline.find("\\Windows\\BitLocker") != std::string::npos || cmdline.find("\\Windows\\WindowsBackup\\") != std::string::npos || cmdline.find("\\Windows\\WindowsUpdate\\") != std::string::npos || cmdline.find("\\Windows\\UpdateOrchestrator\\") != std::string::npos || cmdline.find("\\Windows\\ExploitGuard") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected adversaries stopping services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1489 - Disable Important Scheduled Task
//SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '%/delete%' AND cmdline LIKE '%/TN%' AND cmdline LIKE '%/disable%') AND (cmdline LIKE '%\Windows\SystemRestore\SR%' OR cmdline LIKE '%\Windows\Windows Defender\%' OR cmdline LIKE '%\Windows\BitLocker%' OR cmdline LIKE '%\Windows\WindowsBackup\%' OR cmdline LIKE '%\Windows\WindowsUpdate\%' OR cmdline LIKE '%\Windows\UpdateOrchestrator\%' OR cmdline LIKE '%\Windows\ExploitGuard%');

bool disable_important_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("/Change") != std::string::npos && cmdline.find("/TN") != std::string::npos && cmdline.find("/disable") != std::string::npos) && (cmdline.find("\\Windows\\SystemRestore\\SR") != std::string::npos || cmdline.find("\\Windows\\Windows Defender\\") != std::string::npos || cmdline.find("\\Windows\\BitLocker") != std::string::npos || cmdline.find("\\Windows\\WindowsBackup\\") != std::string::npos || cmdline.find("\\Windows\\WindowsUpdate\\") != std::string::npos || cmdline.find("\\Windows\\UpdateOrchestrator\\") != std::string::npos || cmdline.find("\\Windows\\ExploitGuard") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected adversaries stopping services or processes by disabling their respective scheduled tasks.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1529 - Suspicious Execution of Shutdown
//SELECT * FROM win_process_events WHERE path LIKE '%\shutdown.exe%' AND (cmdline LIKE '%/r %' OR cmdline LIKE '%/s %');

bool suspicious_execution_of_shutdown(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\shutdown.exe") != std::string::npos && (cmdline.find("/r ") != std::string::npos || cmdline.find("/s ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected use of the commandline to shutdown or reboot windows.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1529 - Suspicious Execution of Shutdown to Log Out
//SELECT * FROM win_process_events WHERE path LIKE '%\shutdown.exe%' AND cmdline LIKE '%/l%';

bool suspicious_execution_of_shutdown_to_log_out(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\shutdown.exe") != std::string::npos && cmdline.find("/l") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected the use of the command line tool shutdown to logoff a user.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}


// T1490 - Sensitive Registry Access via Volume Shadow Copy
// SELECT * FROM win_process_events WHERE 
//     cmdline LIKE '%\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%' OR
//     cmdline LIKE '%\\NTDS.dit%' OR
//     cmdline LIKE '%\\SYSTEM%' OR
//     cmdline LIKE '%\\SECURITY%' OR
//     cmdline LIKE '%C:\\tmp\\log%';
bool sensitivity_registry_access_via_volume_shadow_copy(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy") != std::string::npos && (cmdline.find("\\NTDS.dit") != std::string::npos || cmdline.find("\\SYSTEM") != std::string::npos || cmdline.find("\\SECURITY") != std::string::npos || cmdline.find("C:\\tmp\\log") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Command that accesses password storing registry hives via volume shadow backups detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


//T1490 - Boot Configuration Tampering Via Bcdedit.EXE
//select * from win_process_events where path like '%bcdedit.exe%' and cmdline like '%bootstatuspolicy%' and cmdline like '%ignoreallfailures%' and cmdline like '%recoveryenabled%' and cmdline like '%no%';


bool boot_configuration_tampering_bcdedit(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if(path.find("bcdedit.exe") != std::string::npos && cmdline.find("bootstatuspolicy") != std::string::npos && cmdline.find("ignoreallfailures") != std::string::npos && cmdline.find("recoveryenabled") != std::string::npos && cmdline.find("no") != std::string::npos)
		{
			std::stringstream ss;
			ss << "Detected tampering with boot configuration using bcdedit.exe";
			rule_event.metadata = ss.str();
			return true;
		}
		return false;
}

//T1485 - Deleted Data Overwritten Via Cipher.EXE
//select * from win_process_events where path like '%cipher.exe%' and cmdline like '% /w:%';

bool deleted_data_overwritten_cipher(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if(path.find("cipher.exe") != std::string::npos && cmdline.find(" /w:") != std::string::npos){
		std::stringstream ss;
		ss << "detected cipher utility overwritting deleted data";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1490 - Copy From VolumeShadowCopy Via Cmd.EXE
//SELECT * FROM win_process_events WHERE (cmdline LIKE '%copy%' AND cmdline LIKE '%\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%');

bool copy_volumeshadowcopy(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("copy ") != std::string::npos && cmdline.find("\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected execution of copy command that targets a shadow copy";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1490 - Deletion of shadowcopy via vssadmin or wmic
// SELECT * FROM process_events WHERE (path LIKE '%vssadmin.exe%' AND cmdline LIKE '%delete%') OR (path LIKE '%wmic.exe%' AND cmdline LIKE '%shadowcopy%');

bool deletion_of_shadowcopy_via_vssadmin_or_wmic(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("vssadmin.exe") != std::string::npos && cmdline.find("delete") != std::string::npos) || (path.find("wmic.exe") != std::string::npos && cmdline.find("shadowcopy") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Deletion of shadowcopy via vssadmin or wmic";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

