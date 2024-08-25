#include <sstream>
#include "win_persistence_rules.h"

// T1546.013 - Event Triggered Execution: PowerShell Profile
// Append malicious start-process cmdlet
// select * from win_process_events where cmdline like '%Add-Content%' and cmdline like '%Value%';

bool append_malicious_start_process_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Add-Content") != std::string::npos && cmdline.find("Value") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Malicious content triggered by powershell profiles";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1133 - External Remote Services
// Running Chrome VPN Extensions via the Registry 2 vpn extension
// select * from win_process_events where cmdline like '%New-ItemProperty%' and cmdline like '%HKLM:\\Software\\Wow6432Node\\Google\\Chrome\\Extensions%';

bool running_chrome_vpn_extensions(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("HKLM:\\Software\\Wow6432Node\\Google\\Chrome\\Extensions") != std::string::npos && cmdline.find("New-ItemProperty") != std::string::npos)
	{
		std::stringstream ss;

		ss << "External remote services used to access within a network";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.014 - Active Setup
// select * from win_process_events where cmdline like '%HKLM:\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components%';

bool active_setup(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("HKLM:\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Registry Key added to active setup for gaining persistence";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.003 - Time Providers
// Create a new time provider
// select * from win_process_events where cmdline like '%reg%' and cmdline like '%add%' and cmdline like '%HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders%';

bool time_providers_new(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("reg") != std::string::npos && (cmdline.find("add") != std::string::npos) && (cmdline.find("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders") != std::string::npos)) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Time providers may be abused to execute DLLs";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1137.006 - Office Application Startup: Add-ins
// Persistent Code Execution Via Excel VBA Add-in File (XLAM)
// select * from win_process_events where cmdline like '%Microsoft\\Excel\\XLSTART%' and cmdline like '%.xlam%';

bool persistent_code_evecution_via_excel_vba_addin(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Microsoft\\Excel\\XLSTART") != std::string::npos && cmdline.find(".xlam") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Excel VBA Add-ins used for obtaining persistence";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1137.006 - Office Application Startup: Add-ins
// Persistent Code Execution Via Word Add-in File (WLL)
// select * from win_process_events where cmdline like '%Microsoft\\Word\\Startup%' and cmdline like '%.wll%';

bool persistent_code_execution_via_word_addin(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Microsoft\\Word\\Startup") != std::string::npos && cmdline.find(".wll") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Word Add-in file used for obtaining persistence";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.010 - Boot or Logon Autostart Execution: Port Monitors
//  select * from win_process_events where cmdline like '%reg%' and cmdline like '%add%' and cmdline like '%monitors\\ART%';

bool port_monitors(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("monitors\\ART") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Port Monitors may be used to execute DLLs for obtaining persistence";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification
// select * from win_process_events where cmdline like '%WScript.Shell%' and cmdline like '%CreateShorcut%';

bool shortcut_modification(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("WScript.Shell") != std::string::npos && cmdline.find("CreateShortcut") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Shortcuts created or modified for executing malicious programs";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1574.008 - Hijack Execution Flow: Path Interception by Search Order Hijacking
// select * from win_process_events where (cmdline like '%csc.exe%' or path like '%csc.exe%') AND (cmdline like '%Microsoft\\WindowsApps\\Get-Variable.exe%');

bool search_order_hijacking(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("csc.exe") != std::string::npos || process_event.entry.path.find("csc.exe") != std::string::npos) && (cmdline.find("Microsoft\\WindowsApps\\Get-Variable.exe") != std::string::npos)) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Malicious payload inserted into the search order used by other programs";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1505.003 - Server Software Component: Web Shell
//  select * from win_process_events where path like '%xcopy.exe%' and cmdline like '%xcopy%' and cmdline like '%wwwroot%';

bool server_software_component_web_shell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (process_event.entry.path.find("xcopy.exe") != std::string::npos && process_event.entry.cmdline.find("xcopy") != std::string::npos && process_event.entry.cmdline.find("wwwroot") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Web shells abused for obtaining persistence access to the system";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.015 - Event Triggered Execution: Component Object Model Hijacking
//  select * from win_process_events where cmdline like '%New-Item%' and '%SOFTWARE\\Classes\\CLSID%';

bool component_object_model_hijacking(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.cmdline.find("New-Item") != std::string::npos && process_event.entry.cmdline.find("SOFTWARE\\Classes\\CLSID") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Malicious content triggered by hijacking component object model";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.001 - Event Triggered Execution: Change Default File Association
// select * from win_process_events where cmdline like '%.hta=txtfile%' and cmdline like '%assoc%';

bool change_default_file_association(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find(".hta=txtfile") != std::string::npos && process_event.entry.cmdline.find("assoc") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Persistence established triggering malicious content by file type assosciation";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1037.001 -  Boot or Logon Initialization Scripts: Logon Script (Windows)
//  select * from win_process_events where cmdline like '%UserInitMprLogonScript%';
bool win_logon_script(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("UserInitMprLogonScript") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Windows logon script executed to gain persistence";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.002 - Event Triggered Execution: Screensaver
// select * from win_process_events where path like '%reg.exe%' and cmdline like '%Control Panel\\Desktop%' and cmdline like '%ScreenSaveActive%';

bool event_triggered_exevution_screensaver(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (process_event.entry.path.find("reg.exe") != std::string::npos && cmdline.find("Control Panel\\Desktop") != std::string::npos && cmdline.find("ScreenSaveActive") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Malicious activity triggered while user was inactive";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder, Add persistance via Recycle bin
//  select * from win_process_events where cmdline like '%CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open\\command%';

bool registry_run_keys_persistence_via_recycle_bin(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open\\command") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Persistence obtained via recycle bin";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1547.005 - Boot or Logon Autostart Execution: Security Support Provider
//  select * from win_process_events where cmdline like '%HKLM:\\System\\CurrentControlSet\\Control\\Lsa%' and cmdline like '%Security Packages%';

bool security_support_provider_ssp(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("HKLM:\\System\\CurrentControlSet\\Control\\Lsa") != std::string::npos && process_event.entry.cmdline.find("Security Packages") != std::string::npos)
	{
		std::stringstream ss;
		ss << "SSP DLLs are loaded into Local Security Authority";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control, Bypass UAC using sdclt DelegateExecute
//  select * from win_process_events where cmdline like '%shell\\open\\command%' and cmdline like '%DelegateExecute%';

bool bypass_uac_sdclt_delegate_execute(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("\\shell\\open\\command") != std::string::npos && process_event.entry.cmdline.find("DelegateExecute") != std::string::npos)
	{
		std::stringstream ss;
		ss << "User Account Control bypassed using DelegateExecute";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control, Bypass UAC using Event Viewer
//  select * from win_process_events where cmdline like '%mscfile\\shell\\open\\command%' and path like '%mmc.exe%';

bool bypass_uac_eventviewer(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("mscfile\\shell\\open\\command") != std::string::npos && process_event.entry.path.find("mmc.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "User Account Control bypassed using Eventviewer";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control, Disable UAC using reg.exe
//  select * from win_process_events where cmdline like '%\\CurrentVersion\\Policies\\System%' and cmdline like '%EnableLUA%';

bool bypass_uac_disable_reg(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("\\CurrentVersion\\Policies\\System") != std::string::npos && process_event.entry.cmdline.find("EnableLUA") != std::string::npos)
	{
		std::stringstream ss;
		ss << "User Account Control disabled using reg.exe";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1137 - Office Application Startup
// select * from win_process_events where cmdline like '%Outlook\\Security\\Level%';

bool office_applicatoin_startup(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("Outlook\\Security\\Level") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Microsoft Office applications used to gain persistence at startup";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder, Reg Key Run/RunOnce
// select * from win_process_events where cmdline '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%' or cmdline like '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx%';

bool boot_logon_autostart_execution_run_runonce(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos || process_event.entry.cmdline.find("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Boot or Logon Autostart Execution.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1574.012 - Registry-Free Process Scope COR_PROFILER
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%$env:COR_ENABLE_PROFILING%' and cmdline like '%$env:COR_PROFILER%' and cmdline like '%$env:COR_PROFILER_PATH%');

bool registry_free_process_scope_COR_PROFILER(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("$env:COR_ENABLE_PROFILING") != std::string::npos && cmdline.find("$env:COR_PROFILER") != std::string::npos && cmdline.find("$env:COR_PROFILER_PATH") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Execution flow of programs that load the .NET CLR has been hijacked";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1574.011 - Service Registry Permissions Weakness Check
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%get-acl%' and cmdline like '%REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services%');

bool service_registry_permissions_weakness_check(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("get-acl") != std::string::npos && cmdline.find("REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Registry entries used by services have been hijacked";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1098 - Powershell LocalAccount Manipulation
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%Get-LocalGroupMember%' or cmdline like '%-Group Administrators%' or cmdline like '%Disable-LocalUser%' or cmdline like '%Enable-LocalUser%' or cmdline like '%Get-LocalUser%' or cmdline like '%Set-LocalUser%' or cmdline like '%New-LocalUser%' or cmdline like '%Rename-LocalUser%' or cmdline like '%Remove-LocalUser%'));

bool powershell_localAccount_manipulation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Get-LocalGroupMember") != std::string::npos || cmdline.find("-Group Administrators") != std::string::npos || cmdline.find("Disable-LocalUser") != std::string::npos || cmdline.find("Enable-LocalUser") != std::string::npos || cmdline.find("Get-LocalUser") != std::string::npos || cmdline.find("Set-LocalUser") != std::string::npos || cmdline.find("New-LocalUser") != std::string::npos || cmdline.find("Rename-LocalUser") != std::string::npos || cmdline.find("Remove-LocalUser") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Local account has been manipulated";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1546.015 - Suspicious GetTypeFromCLSID ShellExecute
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%::GetTypeFromCLSID(%' and cmdline like '%.ShellExecute(%');

bool suspicious_GetTypeFromCLSID_shellexecute(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("::GetTypeFromCLSID(") != std::string::npos && cmdline.find(".ShellExecute(") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected suspicious Powershell code that execute COM Objects";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1546.013 - Potential Persistence Via PowerShell User Profile Using Add-Content
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Add-Content%' and cmdline like '%Start-Process%');

bool potential_persistence_via_powershell_user_profile_using_add_content(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Add-Content") != std::string::npos && cmdline.find("Start-Process") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Creation or modification of a PowerShell profile might be done";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// // T1547.004 - Winlogon Helper DLL
// // select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%CurrentVersion\Winlogon%' and (cmdline like '%New-Item%' or cmdline like '%Set-ItemProperty%'));

// bool winlogon_helper_DLL(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;

// 	if(cmdline.find("powershell.exe") != std::string::npos && cmdline.find("CurrentVersion\\Winlogon") != std::string::npos && (cmdline.find("Set-ItemProperty") != std::string::npos || cmdline.find("New-Item") != std::string::npos))
// 	{
// 		std::stringstream ss;

// 		ss << "Abuse of features of Winlogon to execute DLLs and/or executables when a user logs in";
// 		rule_event.metadata = ss.str();

// 		return true;
// 	}

// 	return false;
// }

// T1136.002 - Manipulation of User Computer or Group Security Principals Across AD
// select * from win_process_events where cmdline like '%System.DirectoryServices.AccountManagement%';

bool manipulation_of_user_computer_or_group_security_principals_across_AD(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("System.DirectoryServices.AccountManagement") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Adversaries may create a domain account to maintain access to victim systems";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1137.006 - Code Executed Via Office Add-in XLL File
//  select * from win_process_events where cmdline like '%new-object%' and cmdline like '%-ComObject%' and cmdline like '%.application%' and cmdline like '%.RegisterXLL%';

bool code_executed_via_office_add_in_XLL_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("new-object") != std::string::npos && cmdline.find("-ComObject") != std::string::npos && cmdline.find(".application") != std::string::npos && cmdline.find(".RegisterXLL") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1133 - Suspicious Add User to Remote Desktop Users Group
//  select * from win_process_events where cmdline like '%localgroup%' and cmdline like '%/add%' and cmdline like '%Add-LocalGroupMember%' and cmdline like '%-Group%';

bool suspicious_add_user_to_remote_desktop_users_group(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("localgroup") != std::string::npos && cmdline.find("/add") != std::string::npos && cmdline.find("Add-LocalGroupMember") != std::string::npos && cmdline.find("-Group") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected suspicious command line in which a user has been added to the local Remote Desktop Users group";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.001 - Potential Persistence Attempt Via Run Keys Using Reg.EXE
//  select * from win_process_events where cmdline like '%reg%' and cmdline like '% ADD %' and cmdline like '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%';

bool persistence_attempt_via_runkeys(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("reg") != std::string::npos && cmdline.find(" ADD ") != std::string::npos && cmdline.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected reg.exe tool adding key to RUN key in Registry";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1136.001 - New User Created Via Net.EXE With Never Expire Option
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '%user%' and cmdline like '%add%' and cmdline like '%expires:never%');

bool new_user_created_via_net_exe_with_never_expire_option(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find("user") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("expires:never") != std::string::npos)
	{
		std::stringstream ss;

		ss << "New User Created Via Net.EXE With Never Expire Option";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1136.001 - New User Created Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '%user%' and cmdline like '%add%');

bool new_user_created_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find("user") != std::string::npos && cmdline.find("add") != std::string::npos)
	{
		std::stringstream ss;

		ss << "New User Created Via Net.EXE";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.001 - Direct Autorun Keys Modification
// select * from win_process_events where path like '%\\reg.exe%' and cmdline like '%add%' and (cmdline like '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%' or cmdline like '%Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit%' or cmdline like '%Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell%' or cmdline like '%Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows%' or cmdline like '%Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders%' or cmdline like '%System\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell%');

bool direct_autorun_keys_modification(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\reg.exe") != std::string::npos && cmdline.find("add") != std::string::npos && (cmdline.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos || cmdline.find("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit") != std::string::npos || cmdline.find("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell") != std::string::npos || cmdline.find("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows") != std::string::npos || cmdline.find("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") != std::string::npos || cmdline.find("\\System\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected direct modification of autostart extensibility point (ASEP) in registry using reg.exe";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1574.011 - Changing Existing Service ImagePath Value Via Reg.EXE
//  select * from win_process_events where path like '%reg.exe%' and (cmdline like '%add %' and cmdline like '%SYSTEM\\CurrentControlSet\\Services\\%' and cmdline like '% ImagePath %') and (cmdline like '% /d %' or cmdline like '% -d %');

bool changing_existing_service_imagepath_value_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("reg.exe") != std::string::npos && (cmdline.find("add ") != std::string::npos && cmdline.find("SYSTEM\\CurrentControlSet\\Services\\") != std::string::npos && cmdline.find(" ImagePath ") != std::string::npos) && (cmdline.find(" /d ") != std::string::npos || cmdline.find(" -d ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected reg.exe tool changing existing service ImagePath";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1547.001 - Suspicious Process Execution From Fake Recycle.Bin Folder
// SELECT * FROM win_process_events WHERE path LIKE '%:\\RECYCLERS.BIN\\%' OR path LIKE '%:\\RECYCLER.BIN\\%' OR path LIKE '%:\\RECYCLE.BIN\\%';

bool suspicious_process_execution_from_fake_recycle_bin_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find(":\\RECYCLERS.BIN\\") != std::string::npos || path.find(":\\RECYCLER.BIN\\") != std::string::npos || path.find(":\\RECYCLE.BIN\\") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected reg.exe tool adding key to RUN key in Registry";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1543.001 - Suspicious New Service Creation
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%sc.exe%' AND cmdline LIKE '%create%' AND cmdline LIKE '%binPath=%') OR (cmdline LIKE '%powershell%' AND cmdline LIKE '%New-Service%' AND cmdline LIKE '%-BinaryPathName%');

bool suspicious_new_service_creation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("sc.exe") != std::string::npos && cmdline.find("create") != std::string::npos && cmdline.find("binPath=") != std::string::npos) || (cmdline.find("powershell") != std::string::npos && cmdline.find("New-Service") != std::string::npos && cmdline.find("-BinaryPathName") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected reg.exe tool adding key to RUN key in Registry";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1053 - Hacktool - SharPersist Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%-t reg -c%' AND cmdline LIKE '%-m add%' AND cmdline LIKE '%-t service -c%' AND cmdline LIKE '%-t schtask -c%') OR cmdline LIKE '%-t startupfolder -c%';

bool hacktool_sharpersist_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\SharPersist.exe") != std::string::npos) && ((cmdline.find("-t schtask -c") != std::string::npos || cmdline.find("-t startupfolder -c") != std::string::npos) || (cmdline.find("-t reg -c") != std::string::npos && cmdline.find("-m add") != std::string::npos) || (cmdline.find("-t service -c") != std::string::npos && cmdline.find("-m add") != std::string::npos ) || (cmdline.find("-m add") != std::string::npos && cmdline.find("-t schtask -c") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Detected reg.exe tool adding key to RUN key in Registry";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.008 - Suspicious Debugger Registration Cmdline
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\\CurrentVersion\\Image File Execution Options\\%' AND (cmdline LIKE '%sethc.exe%' OR cmdline LIKE '%utilman.exe%' OR cmdline LIKE '%osk.exe%' OR cmdline LIKE '%magnify.exe%' OR cmdline LIKE '%narrator.exe%' OR cmdline LIKE '%displayswitch.exe%' OR cmdline LIKE '%atbroker.exe%' OR cmdline LIKE '%HelpPane.exe%');

bool suspicious_debugger_registration_cmdline(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\CurrentVersion\\Image File Execution Options\\") != std::string::npos && (cmdline.find("sethc.exe") != std::string::npos || cmdline.find("utilman.exe") != std::string::npos || cmdline.find("osk.exe") != std::string::npos || cmdline.find("magnify.exe") != std::string::npos || cmdline.find("narrator.exe") != std::string::npos || cmdline.find("displayswitch.exe") != std::string::npos || cmdline.find("atbroker.exe") != std::string::npos || cmdline.find("HelpPane.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected the registration of a debugger for a program that is available in the logon screen";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1037.001 - Potential Persistence Via Logon Scripts - CommandLine
// SELECT * FROM win_process_events WHERE cmdline LIKE '%UserInitMprLogonScript%';

bool potential_persistence_via_logon_scripts_commandline(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("UserInitMprLogonScript") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected the addition of a new LogonScript to the registry value 'UserInitMprLogonScript' for potential persistence";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1037.001 - Persistence Via TypedPaths - CommandLine
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths%';

bool persistence_via_typedpaths_commandline(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected modification addition to the 'TypedPaths' key in the user or admin registry via the commandline";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1037.001 - Uncommon Userinit Child Process
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell.exe%' AND parent_path LIKE '%userinit.exe%' AND (cmdline LIKE '%netlogon.bat%' OR cmdline LIKE '%UsrLogon.cmd%');

bool uncommon_userinit_child_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;

	
	{
		std::stringstream ss;
		ss << "Detected uncommon 'userinit.exe' child processes, which could be a sign of uncommon shells or login scripts used for persistence.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool iis_native_code_module_commandline_installation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\appcmd.exe") != std::string::npos) && (cmdline.find("/name:") != std::string::npos || cmdline.find("-name:") != std::string::npos) && cmdline.find("module") != std::string::npos && cmdline.find("install") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious IIS native-code module installations via command line detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - New Service Creation Using PowerShell
// select * from win_process_events where (cmdline like '%New-Service%' and cmdline like '%BinaryPathName%');

bool new_service_creation_using_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("New-Service") != std::string::npos &&
		 cmdline.find("BinaryPathName") != std::string::npos))
	{
		std::stringstream ss;
		ss << "New Service Creation Using PowerShell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1505.003 - Chopper Webshell Process Pattern
// SELECT * FROM win_process_events WHERE cmdline LIKE '%w3wp%' AND (cmdline LIKE '%&ipconfig&echo%' OR cmdline LIKE '%&quser&echo%' OR cmdline LIKE '%&whoami&echo%' OR cmdline LIKE '%&c:&echo%' OR cmdline LIKE '%&cd&echo%' OR cmdline LIKE '%&dir&echo%' OR cmdline LIKE '%&echo [E]%' OR cmdline LIKE '%&echo [S]%');

bool chopper_webshell_process_pattern(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	
	if (cmdline.find("w3wp") != std::string::npos &&
		(cmdline.find("&ipconfig&echo") != std::string::npos ||
		 cmdline.find("&quser&echo") != std::string::npos ||
		 cmdline.find("&whoami&echo") != std::string::npos ||
		 cmdline.find("&c:&echo") != std::string::npos ||
		 cmdline.find("&cd&echo") != std::string::npos ||
		 cmdline.find("&dir&echo") != std::string::npos ||
		 cmdline.find("&echo [E]") != std::string::npos ||
		 cmdline.find("&echo [S]") != std::string::npos))

	{
		std::stringstream ss;
		ss << "Detected patterns found in process executions cause by China Chopper like tiny (ASPX)";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1505.003 - Web Shell Written to Disk
// SELECT * FROM win_process_events WHERE cmdline LIKE '%xcopy%' AND cmdline LIKE '%/I%' AND cmdline LIKE '%/Y%' AND cmdline LIKE '%C:\\inetpub\\wwwroot%';

bool webshell_detection_with_command_line_keywords(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("xcopy") != std::string::npos &&
		cmdline.find("/I") != std::string::npos &&
		cmdline.find("/Y") != std::string::npos &&
		cmdline.find("C:\\inetpub\\wwwroot") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected an adversary leveraging Web Shells by simulating the file modification to disk.Idea from APTSimulator.cmd.aspx";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_iis_module_registration(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	if ((parent_path.find("\\w3wp.exe") != std::string::npos) && (cmdline.find("gacutil") != std::string::npos && cmdline.find("/I") != std::string::npos) && (cmdline.find("system.enterpriseservices.internal.publish") != std::string::npos || cmdline.find("appcmd.exe add module") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected an adversary leveraging Web Shells by simulating the file modification to disk.Idea from APTSimulator.cmd.aspx";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_driver_install_by_pnputilexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (cmdline.find("\\pnputil.exe") != std::string::npos && (cmdline.find("-i") != std::string::npos || cmdline.find("/install") != std::string::npos || cmdline.find("-a") != std::string::npos || cmdline.find("/add-driver") != std::string::npos || cmdline.find(".inf") != std::string::npos))
	{
		std::stringstream ss;
		ss << "A suspicious driver is being installed via pnputil.exe lolbin !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1547 - Suspicious GrpConv Execution

bool suspicious_grpconv_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("grpconv.exe -o") != std::string::npos || cmdline.find("grpconv -o") != std::string::npos)
	{
		std::stringstream ss;
		ss << "A suspicious execution of a utility to convert Windows 3.x .grp files or for persistence purposes by malicious software or actors detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1505 - Unsigned AppX Installation Attempt Using Add-AppxPackage
// SELECT * FROM your_process_events_table WHERE (cmdline LIKE '%Add-AppPackage %' OR cmdline LIKE '%Add-AppxPackage %') AND cmdline LIKE '% -AllowUnsigned%';

bool unsigned_appx_installation_attempt_using_add_appxpackage(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("Add-AppPackage ") != std::string::npos ||
		 cmdline.find("Add-AppxPackage ") != std::string::npos) &&
		cmdline.find(" -AllowUnsigned") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Unsigned AppX Installation Attempt Using Add-AppxPackage";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1505.002 - MSExchange Transport Agent Installation
// SELECT * FROM win_process_events WHERE cmdline LIKE '%Install-TransportAgent%';

bool msexchange_transport_agent_installation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Install-TransportAgent") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Unsigned AppX Installation Attempt Using Add-AppxPackage";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - Suspicious Service DACL Modification Via Set-Service Cmdlet
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%-SecurityDescriptorSddl%' OR cmdline LIKE '%-sd%') AND cmdline LIKE '%Set-Service%' AND cmdline LIKE '%D\;\;%' AND (cmdline LIKE '%\;\;\;IU%' OR cmdline LIKE '%\;\;\;SU%' OR cmdline LIKE '%\;\;\;BA%' OR cmdline LIKE '%\;\;\;SY%' OR cmdline LIKE '%\;\;\;WD%');


bool suspicious_service_dacl_modification_via_set_service_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("-SecurityDescriptorSddl") != std::string::npos ||
		 cmdline.find("-sd") != std::string::npos) &&
		cmdline.find("Set-Service") != std::string::npos &&
		cmdline.find("D;;") != std::string::npos &&
		(cmdline.find(";;;IU") != std::string::npos ||
		 cmdline.find(";;;SU") != std::string::npos ||
		 cmdline.find(";;;BA") != std::string::npos ||
		 cmdline.find(";;;SY") != std::string::npos ||
		 cmdline.find(";;;WD") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious Service DACL Modification Via Set-Service Cmdlet";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1574.011 - Possible Privilege Escalation via Weak Service Permissions
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND ((cmdline LIKE '%config%' AND cmdline LIKE '%binPath%') OR (cmdline LIKE '%failure%' AND cmdline LIKE '%command%'));

bool possible_privilege_escalation_via_weak_service_permissions(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && ((cmdline.find("config") != std::string::npos && cmdline.find("binPath") != std::string::npos) || (cmdline.find("failure") != std::string::npos && cmdline.find("command") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Detected sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - New Service Creation Using Sc.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\sc.exe%' AND (cmdline LIKE '%create%' AND cmdline LIKE '%binPath%');

bool new_service_creation_using_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && (cmdline.find("create") != std::string::npos && cmdline.find("binPath") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected the creation of a new service using the 'sc.exe' utility.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - New Kernel Driver Via SC.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND (cmdline LIKE '%create%' OR cmdline LIKE '%config%') AND (cmdline LIKE '%binPath%' AND cmdline LIKE '%type%' AND cmdline LIKE '%kernel%');

bool new_kernel_driver_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && (cmdline.find("create") != std::string::npos || cmdline.find("config") != std::string::npos) && (cmdline.find("binPath") != std::string::npos && cmdline.find("type") != std::string::npos && cmdline.find("kernel") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected creation of a new service (kernel driver) with the type 'kernel'";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - Allow Service Access Using Security Descriptor Tampering Via Sc.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND (cmdline LIKE '%sdset%' AND cmdline LIKE '%A\;%') AND (cmdline LIKE '%\;IU%' OR cmdline LIKE '%\;SU%' OR cmdline LIKE '%\;BA%' OR cmdline LIKE '%\;SY%' OR cmdline LIKE '%\;WD%');

bool allow_service_access_using_security_descriptor_tampering_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && (cmdline.find("sdset") != std::string::npos && cmdline.find("A;") != std::string::npos) && (cmdline.find(";IU") != std::string::npos || cmdline.find(";SU") != std::string::npos || cmdline.find(";BA") != std::string::npos || cmdline.find(";SY") != std::string::npos || cmdline.find(";WD") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious DACL modifications to allow access to a service from a suspicious trustee";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - Deny Service Access Using Security Descriptor Tampering Via Sc.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND (cmdline LIKE '%sdset%' AND cmdline LIKE '%D\;%') AND (cmdline LIKE '%\;IU%' OR cmdline LIKE '%\;SU%' OR cmdline LIKE '%\;BA%' OR cmdline LIKE '%\;SY%' OR cmdline LIKE '%\;WD%');

bool deny_service_access_using_security_descriptor_tampering_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && (cmdline.find("sdset") != std::string::npos && cmdline.find("D;") != std::string::npos) && (cmdline.find(";IU") != std::string::npos || cmdline.find(";SU") != std::string::npos || cmdline.find(";BA") != std::string::npos || cmdline.find(";SY") != std::string::npos || cmdline.find(";WD") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious DACL modifications to deny access to a service that affects critical trustees";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1574.011 - Service DACL Abuse To Hide Services Via Sc.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND cmdline LIKE '%sdset%' AND cmdline LIKE '%DCLCWPDTSD%';

bool service_dacl_abuse_to_hide_services_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && cmdline.find("sdset") != std::string::npos && cmdline.find("DCLCWPDTSD") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected usage of the 'sc.exe' utility adding a new service with special permission";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1574.011 - Service Security Descriptor Tampering Via Sc.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND cmdline LIKE '%sdset%';

bool service_security_descriptor_tampering_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && cmdline.find("sdset") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected sc.exe utility adding a new service with special permission which hides that service.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - Suspicious Service Path Modification
// SELECT * FROM win_process_events WHERE path LIKE '%\\sc.exe%' AND (cmdline LIKE '%config%' AND cmdline LIKE '%binPath%') AND (cmdline LIKE '%powershell%' OR cmdline LIKE '%cmd %' OR cmdline LIKE '%mshta%' OR cmdline LIKE '%wscript%' OR cmdline LIKE '%cscript%' OR cmdline LIKE '%rundll32%' OR cmdline LIKE '%svchost%' OR cmdline LIKE '%dllhost%' OR cmdline LIKE '%cmd.exe /c%' OR cmdline LIKE '%cmd.exe /k%' OR cmdline LIKE '%cmd.exe /r%' OR cmdline LIKE '%cmd /c%' OR cmdline LIKE '%cmd /k%' OR cmdline LIKE '%cmd /r%' OR cmdline LIKE '%C:\\Users\\Public%' OR cmdline LIKE '%\\Downloads\\%' OR cmdline LIKE '%\\Desktop\\%' OR cmdline LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%' OR cmdline LIKE '%C:\\Windows\\TEMP\\%' OR cmdline LIKE '%\\AppData\\Local\\Temp%');

bool suspicious_service_path_modification(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && (cmdline.find("config") != std::string::npos && cmdline.find("binPath") != std::string::npos) && (cmdline.find("powershell") != std::string::npos || cmdline.find("cmd ") != std::string::npos || cmdline.find("mshta") != std::string::npos || cmdline.find("wscript") != std::string::npos || cmdline.find("cscript") != std::string::npos || cmdline.find("rundll32") != std::string::npos || cmdline.find("svchost") != std::string::npos || cmdline.find("dllhost") != std::string::npos || cmdline.find("cmd.exe /c") != std::string::npos || cmdline.find("cmd.exe /k") != std::string::npos || cmdline.find("cmd.exe /r") != std::string::npos || cmdline.find("cmd /c") != std::string::npos || cmdline.find("cmd /k") != std::string::npos || cmdline.find("cmd /r") != std::string::npos || cmdline.find("C:\\Users\\Public") != std::string::npos || cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") != std::string::npos || cmdline.find("C:\\Windows\\TEMP\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected service path modification via the 'sc' binary to a suspicious command or path.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - Potential Persistence Attempt Via Existing Service Tampering
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%sc %' AND cmdline LIKE '%config %' AND cmdline LIKE '%binpath=%') OR (cmdline LIKE '%sc %' AND cmdline LIKE '%failure%' AND cmdline LIKE '%command=%')) OR (((cmdline LIKE '%reg %' AND cmdline LIKE '%add %' AND cmdline LIKE '%FailureCommand%') OR (cmdline LIKE '%reg %' AND cmdline LIKE '%add %' AND cmdline LIKE '%ImagePath%')) AND (cmdline LIKE '%.sh%' OR cmdline LIKE '%.exe%' OR cmdline LIKE '%.dll%' OR cmdline LIKE '%.bin$%' OR cmdline LIKE '%.bat%' OR cmdline LIKE '%.cmd%' OR cmdline LIKE '%.js%' OR cmdline LIKE '%.msh$%' OR cmdline LIKE '%.reg$%' OR cmdline LIKE '%.scr%' OR cmdline LIKE '%.ps%' OR cmdline LIKE '%.vb%' OR cmdline LIKE '%.jar%' OR cmdline LIKE '%.pl%'));

bool potential_persistence_attempt_via_existing_service_tampering(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	
	if (((cmdline.find("sc ") != std::string::npos && cmdline.find("config ") != std::string::npos && cmdline.find("binpath=") != std::string::npos) || (cmdline.find("sc ") != std::string::npos && cmdline.find("failure") != std::string::npos && cmdline.find("command=") != std::string::npos)) || (((cmdline.find("reg ") != std::string::npos && cmdline.find("add ") != std::string::npos && cmdline.find("FailureCommand") != std::string::npos) || (cmdline.find("reg ") != std::string::npos && cmdline.find("add ") != std::string::npos && cmdline.find("ImagePath") != std::string::npos)) && (cmdline.find(".sh") != std::string::npos || cmdline.find(".exe") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".bin$") != std::string::npos || cmdline.find(".bat") != std::string::npos || cmdline.find(".cmd") != std::string::npos || cmdline.find(".js") != std::string::npos || cmdline.find(".msh$") != std::string::npos || cmdline.find(".reg$") != std::string::npos || cmdline.find(".scr") != std::string::npos || cmdline.find(".ps") != std::string::npos || cmdline.find(".vb") != std::string::npos || cmdline.find(".jar") != std::string::npos || cmdline.find(".pl") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Detected the modification of an existing service in order to execute an arbitrary payload.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}



// T1546.003 - New ActiveScriptEventConsumer Created Via Wmic.EXE
// SELECT * FROM win_process_events WHERE cmdline LIKE '%ActiveScriptEventConsumer%' AND cmdline LIKE '%CREATE%';

bool new_activeScriptEventConsumer_created_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("ActiveScriptEventConsumer") != std::string::npos && cmdline.find("CREATE") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected WMIC executions in which an event consumer gets created. This could be used to establish persistence.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543 - PUA - Process Hacker Execution
// select * from win_process_events where cmdline like '%\ProcessHacker_%';

bool pua_process_hacker_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\ProcessHacker_") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PUA - Process Hacker Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1053.005 - Potential Persistence Via Microsoft Compatibility Appraiser
// select * from win_process_events where path like '%\\schtasks.exe%' AND (cmdline like '%run %' AND cmdline like '%\\Application Experience\\Microsoft Compatibility Appraiser%');

bool potential_persistence_via_microsoft_compatibility_appraiser(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("run ") != std::string::npos && cmdline.find("\\Application Experience\\Microsoft Compatibility Appraiser") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected manual execution of the 'Microsoft Compatibility Appraiser' task via schtasks.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.011 - Potential Shim Database Persistence via Sdbinst.EXE
// select * from win_process_events where (path like '%\\sdbinst.exe%' AND cmdline like '%.sdb%') AND NOT (parent_path like '%\\msiexec.exe%' AND cmdline like '%iisexpressshim.sdb%');

bool potential_shim_database_persistence_via_sdbinstexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((path.find("\\sdbinst.exe") != std::string::npos && cmdline.find(".sdb") != std::string::npos) && !(parent_path.find("\\msiexec.exe") != std::string::npos && cmdline.find("iisexpressshim.sdb") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected installation of a new shim using sdbinst.exe.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1098 - Add User to Local Administrators Group
// select * from win_process_events where (cmdline like '%localgroup %' AND cmdline like '% /add%') AND (cmdline like '%Add-LocalGroupMember %' AND cmdline like '% -Group %') AND (cmdline like '% administrators %' OR cmdline like '% administrateur%');

bool add_user_to_local_administrators_group(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("localgroup ") != std::string::npos && cmdline.find(" /add") != std::string::npos) && (cmdline.find("Add-LocalGroupMember ") != std::string::npos && cmdline.find(" -Group ") != std::string::npos) && (cmdline.find(" administrators ") != std::string::npos || cmdline.find(" administrateur") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious command line that adds an account to the local administrators/administrateurs group.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.003 - WMI Persistence - Script Event Consumer
// select * from win_process_events where path like '%C:\\WINDOWS\\system32\\wbem\\scrcons.exe%' AND parent_path like '%C:\\Windows\\System32\\svchost.exe%';

bool wmi_persistence_script_event_consumer(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("C:\\WINDOWS\\system32\\wbem\\scrcons.exe") != std::string::npos && parent_path.find("C:\\Windows\\System32\\svchost.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected WMI script event consumers.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.011 - Suspicious Shim Database Installation via Sdbinst.EXE
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\sdbinst.exe%' AND NOT (cmdline LIKE '%.sdb%') AND NOT (parent_path LIKE '%:\\Windows\\System32\\svchost.exe%' AND path LIKE '%:\\Windows\\System32\\sdbinst.exe%' AND cmdline LIKE '% -m -bg%') AND NOT (parent_path LIKE '%:\\Windows\\System32\\svchost.exe%' AND path LIKE '%:\\Windows\\System32\\sdbinst.exe%' AND cmdline LIKE '% -mm%')));


bool suspicious_shim_database_installation_via_sdbinstexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("\\sdbinst.exe") != std::string::npos && !(cmdline.find(".sdb") != std::string::npos) && !(parent_path.find(":\\Windows\\System32\\svchost.exe") != std::string::npos && path.find(":\\Windows\\System32\\sdbinst.exe") != std::string::npos && cmdline.find(" -m -bg") != std::string::npos) && !(parent_path.find(":\\Windows\\System32\\svchost.exe") != std::string::npos && path.find(":\\Windows\\System32\\sdbinst.exe") != std::string::npos && cmdline.find(" -mm") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1176 - Suspicious Chromium Browser Instance Executed With Custom Extensions
// select * from win_process_events where ((parent_path like '%\\cmd.exe%' or parent_path like '%\\cscript.exe%' or parent_path like '%\\mshta.exe%' or parent_path like '%\\powershell.exe%' or parent_path like '%\\pwsh.exe%' or parent_path like '%\\regsvr32.exe%' or parent_path like '%\\rundll32.exe%' or parent_path like '%\\wscript.exe%') and (path like '%\\brave.exe%' or path like '%\\chrome.exe%' or path like '%\\msedge.exe%' or path like '%\\opera.exe%' or path like '%\\vivaldi.exe%') and cmdline like '%--load-extension=%');


bool suspicious_chromium_custom_extensions(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	if ((parent_path.find("\\cmd.exe") != std::string::npos || parent_path.find("\\cscript.exe") != std::string::npos || parent_path.find("\\mshta.exe") != std::string::npos || parent_path.find("\\powershell.exe") != std::string::npos || parent_path.find("\\pwsh.exe") != std::string::npos || parent_path.find("\\regsvr32.exe") != std::string::npos || parent_path.find("\\rundll32.exe") != std::string::npos || parent_path.find("\\wscript.exe") != std::string::npos) &&
    (path.find("\\brave.exe") != std::string::npos || path.find("\\chrome.exe") != std::string::npos || path.find("\\msedge.exe") != std::string::npos || path.find("\\opera.exe") != std::string::npos || path.find("\\vivaldi.exe") != std::string::npos) &&
    cmdline.find("--load-extension=") != std::string::npos)

	{
		std::stringstream ss;
		ss << "Detected chromium based browser to start an instance of a custom extension";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//T1546.008 - Sticky Key Like Backdoor Execution
//SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\winlogon.exe%' AND (path LIKE '%\\cmd.exe%' OR path LIKE '%\\cscript.exe%' OR path LIKE '%\\mshta.exe%' OR path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR path LIKE '%\\regsvr32.exe%' OR path LIKE '%\\rundll32.exe%' OR path LIKE '%\\wscript.exe%' OR path LIKE '%\\wt.exe%') AND (cmdline LIKE '%sethc.exe%' OR cmdline LIKE '%utilman.exe%' OR cmdline LIKE '%osk.exe%' OR cmdline LIKE '%Magnify.exe%' OR cmdline LIKE '%Narrator.exe%' OR cmdline LIKE '%DisplaySwitch.exe%'));

bool sticky_key_backdoor_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((parent_path.find("\\winlogon.exe") != std::string::npos && (path.find("\\cmd.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos || path.find("\\wt.exe") != std::string::npos) && (cmdline.find("sethc.exe") != std::string::npos || cmdline.find("utilman.exe") != std::string::npos || cmdline.find("osk.exe") != std::string::npos || cmdline.find("Magnify.exe") != std::string::npos || cmdline.find("Narrator.exe") != std::string::npos || cmdline.find("DisplaySwitch.exe") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Detected the usage and installation of backdoor";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//T1546.008 - Persistence Via Sticky Key Backdoor
//
bool sticky_key_backdoor_persistence(const ProcessEvent &process_event, Event &rule_event)
{
		std::string cmdline = process_event.entry.cmdline;
		if (cmdline.find("copy ") != std::string::npos && cmdline.find("/y ") != std::string::npos && cmdline.find("C:\\windows\\system32\\cmd.exe C:\\windows\\system32\\sethc.exe") != std::string::npos)
		{
			std::stringstream ss;
			ss << "Detected replacement of sticky keys executable with admin cmd executable";
			rule_event.metadata = ss.str();
			return true;
		}
		return false;
}

//T1176 - Extension loaded into browser at process start
// select * from win_process_events where (path like '%\\brave.exe%' or path like '%\\chrome.exe%' or path like '%\\msedge.exe%' or path like '%\\opera.exe%' or path like '%\\vivaldi.exe%') and cmdline like '%--load-extension%';


bool extension_loaded_into_browser_at_process_start(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\brave.exe") != std::string::npos || path.find("\\chrome.exe") != std::string::npos || path.find("\\msedge.exe") != std::string::npos || path.find("\\opera.exe") != std::string::npos || path.find("\\vivaldi.exe") != std::string::npos) && cmdline.find("--load-extension") != std::string::npos)

	{
		std::stringstream ss;
		ss << "Detected the execution of a browser with the suspicious parameter to force installing a browser extension without any user interaction.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//T1546.010- Modification of AppInit DLLs registry for persistence
// select * from win_process_events where path like '%\\reg.exe%' and cmdline like '%add%' and cmdline like '%appinit_dlls%';


bool modification_of_apinit_dlls_registry_for_persistence(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\reg.exe") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("appinit_dlls") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected the modification of AppInit DLLs related registry keys for persistence.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

// T1543.003 Creation of new service via CLI

bool creation_of_new_service_via_cli(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (path.find("sc.exe") != std::string::npos && (cmdline.find("create") != std::string::npos || cmdline.find("delete") != std::string::npos || cmdline.find("start") != std::string::npos) && (parent_path.find("cmd.exe") != std::string::npos || parent_path.find("powershell.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detects the creation of new service with the usage of sc.exe via cmd.exe or powershell.exe";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


// T1547.001 Registry run keys modification

bool registry_run_keys_modification(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos || cmdline.find("Microsoft\\Windows\\CurrentVersion\\RunOnce") != std::string::npos || cmdline.find("Microsoft\\Windows\\CurrentVersion\\Explorer\\User") != std::string::npos || cmdline.find("Microsoft\\Windows\\CurrentVersion\\Explorer\\Run") != std::string::npos || cmdline.find("query") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detects the modification of the common persistent registry keys";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1136.002 creation of local or domain account via net utility

bool creation_of_local_or_domain_account(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("add*") != std::string::npos || (cmdline.find("add*") != std::string::npos && cmdline.find("domain") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Creation of local or domain account via the net utility detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

