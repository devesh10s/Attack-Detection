
#include "win_privilege_escalation_rules.h"
#include <sstream>


//T1053.005 - Scheduled Task/Job: Scheduled Task
// select * from win_process_events where path like '%schtasks%' and cmdline like '%schtasks%';

// bool scheduled_task(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

// 	if(std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("schtasks") != std::string::npos && (std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("create") != std::string::npos) && (std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("system32") != std::string::npos || std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("winsxs") != std::string::npos)) // || chrome_extension.entry.permissions.find("://*/"))
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;	
// 	}
	
// 	return false;
// }

bool scheduled_task(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

	if(process_event.entry.path.find("schtasks")!= std::string::npos && cmdline.find("schtasks") != std::string::npos && cmdline.find("create") != std::string::npos && cmdline.find("system") != std::string::npos && cmdline.find("calc.exe") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss << "Win Task Scheduler may be possibly abused to run malicious tasks";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1543.003 - Create or Modify System Process: Windows Service 
//select * from win_process_events where cmdline like'%sc%' and cmdline like '%config%' and cmdline like '%binPath%';

bool create_or_modify_windows_process(const ProcessEvent &process_event, Event &rule_event)
{

	if(process_event.entry.cmdline.find("sc") != std::string::npos && process_event.entry.cmdline.find("config") != std::string::npos && process_event.entry.cmdline.find("binPath") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss << "Win Services Scheduler may be modified for malicious purposes";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}


//T1546.011 - Event Triggered Execution: Application Shimming
// select * from win_process_events where parent_path like '%cmd.exe%' and path like '%sdbinst%' and cmdline like '%sdbinst%';

bool application_shimming(const ProcessEvent &process_event, Event &rule_event)
{

	if(process_event.entry.cmdline.find("sdbinst") != std::string::npos && process_event.entry.path.find("sdbinst.exe") != std::string::npos && process_event.entry.parent_path.find("cmd.exe") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss <<"Privileges escalated by using shims";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}


// T1546.007 - Event Triggered Execution: Netsh Helper DLL
//select * from win_process_events where path like '%netsh.exe%' and cmdline like '%add helper%';

bool netsh_helper_dll(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.path.find("netsh.exe") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss << "Malicious content triggered usign netsh";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}



// T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
// select * from win_process_events where (path like '%reg.exe%' and cmdline like '%HKCU%' and cmdline like '%REG%' and cmdline like '%ADD%') or (path like '%cmd.exe%' and cmdline like '%HKCU%' and cmdline like '%REG%' and cmdline like '%ADD%');


// bool registry_run_keys(const ProcessEvent &process_event, Event &rule_event)
// {

// 	std::string cmdline = process_event.entry.cmdline;


// 	if(std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("hkcu") != std::string::npos && std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("run") != std::string::npos && std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("reg") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;	
// 	}
	
// 	return false;
// }

bool registry_run_keys(const ProcessEvent &process_event, Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;


	if((cmdline.find("HKCU") != std::string::npos && cmdline.find("REG") != std::string::npos && cmdline.find("ADD") != std::string::npos && process_event.entry.path.find("reg.exe") != std::string::npos)
	 ||  cmdline.find("HKCU") != std::string::npos && cmdline.find("REG") != std::string::npos && cmdline.find("cmd.exe") != std::string::npos && cmdline.find("ADD") != std::string::npos && process_event.entry.path.find("cmd.exe") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss << "Malicious program is possibly added to the startup folder";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1134.005 - Access Token Manipulation: SID-History Injection
// select * from win_process_events where cmdline like '%mimikatz%' and cmdline like '%sid::add%' and cmdline like '%sid::patch%';

// bool sid_history_injection(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;

// 	if(std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("mimikatz") != std::string::npos && std::transform(cmdline.begin(), cmdline.end(), cmdline.begin(), ::tolower).find("sid::add") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;	
// 	}
	
// 	return false;l
// }

bool sid_history_injection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if(cmdline.find("mimikatz") != std::string::npos && cmdline.find("sid::add") != std::string::npos && cmdline.find("sid::patch")) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss << "Privileges Escalated through SID-History Injection";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}




//T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking 
// select * from win_process_events where cmdline like '%amsi.dll%' and cmdline like '%copy%' and cmdline like '%APPDATA%'; 

bool dll_search_order_hijacking(const ProcessEvent &process_event,Event &rule_event)
{

	std::string cmdline  = process_event.entry.cmdline;

	if(cmdline.find("amsi.dll")!= std::string::npos && cmdline.find("copy") != std::string::npos && cmdline.find("APPDATA") != std::string::npos){
		std::stringstream ss;

        	ss << "DLL Search Order Hijacking";
        	rule_event.metadata = ss.str();

        	return true;
	}
	return false;
}

//T1055.003 - Process Injection: Thread execution Hijacking
// select * from win_process_events where parent_path like '%powershell.exe%' and cmdline like '%notepad%' and cmdline like '%InjectContext%';

bool thread_execution_hijacking(const ProcessEvent &process_event,Event &rule_event){
	std::string cmdline = process_event.entry.cmdline;
	if(process_event.entry.parent_path.find("powershell.exe") != std::string::npos && cmdline.find("notepad") != std::string::npos && cmdline.find("InjectContext") != std::string::npos){
		std::stringstream ss;

        	ss << "Thread execution Hijacking";
        	rule_event.metadata = ss.str();

        	return true;
	}
	return false;
} 

// T1134.004 - Access Token Manipulation: Parent PID Spoofing
// select * from win_process_events where cmdline like '%iexplore.exe%' and cmdline like '%calc.dll%';

bool pid_parent_spoofing(const ProcessEvent &process_event,Event &rule_event){
	std::string cmdline = process_event.entry.cmdline;
	if(cmdline.find("iexplore.exe") != std::string::npos && cmdline.find("calc.dll") != std::string::npos){
		std::stringstream ss;

        	ss << "Parent PID Spoofing";
        	rule_event.metadata = ss.str();

        	return true;
	}
	return false;
} 


// T1218.003 - System Binary Proxy Execution: CMSTP
// select * from win_process_events where (path like '%cmd.exe%' and cmdline like '%cmstp.exe%') or (path like '%cmstp.exe%' and cmdline like '%cmstp%');

bool cmstp(const ProcessEvent &process_event,Event &rule_event){
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if((path.find("cmd.exe") != std::string::npos && cmdline.find("cmstp.exe") != std::string::npos) || (path.find("cmstp.exe") != std::string::npos && cmdline.find("cmstp.exe") != std::string::npos)){
		std::stringstream ss;

        	ss << "Execution of malicious code using cmstp.exe";
        	rule_event.metadata = ss.str();

        	return true;
	}
	return false;
}

// T1546.008 - Event Triggered Execution: Accessibility Features
// select * from win_process_events where (cmdline like '%icacls.exe%' and cmdline like '%icacls%' and cmdline like '%osk.exe%') or (path like '%takeown%' and cmdline like '%sethc.exe%');

bool event_triggered_execution_accessibility_features(const ProcessEvent &process_event,Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;

	if((path.find("icacls.exe") != std::string::npos && cmdline.find("icacls") != std::string::npos && cmdline.find("osk.exe") != std::string::npos) || (path.find("takeown.exe") != std::string::npos && cmdline.find("sethc.exe") != std::string::npos))
	   {
			 std::stringstream ss;
			 ss<< "Malicious content triggered by accessibility features for escalating privileges";
			 rule_event.metadata = ss.str();
			 return true;
	   }
	   return false;
}

//T1547.005 - Boot or Logon Autostart Execution: Security Support Provider
// select * from win_process_events where path like '%powershell.exe%' and cmdline like '%System\\CurrentControlSet\\Control\\Lsa%'

bool security_support_provider(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.path.find("powershell") != std::string::npos && process_event.entry.cmdline.find("System\\CurrentControlSet\\Control\\Lsa") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Security support providers absued to execute DLLs";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1484.001 - Domain Policy Modification: Group Policy Modification
// select * from win_process_events where (cmdline like '%reg%' and cmdline like '%add%') and (cmdline like '%GroupPolicyRefreshTime%' or cmdline like '%GroupPolicyRefreshTimeOffset%' or cmdline like '%GroupPolicyRefreshTimeDC%');

bool group_policy_modification(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if((cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos) && cmdline.find("GroupPolicyRefreshTime") !=std::string::npos || cmdline.find("GroupPolicyRefreshTimeOffset") != std::string::npos 
	|| cmdline.find("GroupPolicyRefreshTimeDC") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Group Polict objects modified for escalating privileges on domain";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//T1546.012 - Event Triggered Execution: Image File Execution Options Injection
// select * from win_process_events where cmdline '%SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options%';

bool image_file_execution_options_injection (const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.cmdline.find("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options") != std::string::npos){
		std::stringstream ss;
		ss<< "Priveleges elevated by using IFEO debugger";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL
// select * from win_process_events where cmdline like '%Set-ItemProperty%' and cmdline like '%Microsoft\\Windows NT\\CurrentVersion\\Winlogon%' and (cmdline like '%Shell%' or cmdline like '%Userinit%');

bool winlogon_helper_dll(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if(cmdline.find("Set-ItemProperty") != std::string::npos && cmdline.find("Microsoft\\Windows NT\\CurrentVersion\\Winlogon") != std::string::npos && (cmdline.find("Shell") != std::string::npos || cmdline.find("Userinit") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Winlogon features absued to execute DLls ";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//T1546.015 - Event Triggered Execution: Component Object Model Hijacking, COM Hijacking - InprocServer32
// select * from win_process_events where cmdline like '%HKCU:\\SOFTWARE\\Classes\\CLSID%' and cmdline like '%InprocServer32%';

bool com_hijacking_inprocserver32(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.cmdline.find("HKCU:\\SOFTWARE\\Classes\\CLSID") != std::string::npos && process_event.entry.cmdline.find("InprocServer32") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

        	ss << "Registry values under InprocServer32 created";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL, Winlogon Notify Key Logon Persistence
// select * from win_process_events where cmdline like '%Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify%' and cmdline like '%.dll%';

bool winlogon_notify_key_logon(const ProcessEvent &process_event , Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;
	if(cmdline.find("Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify") != std::string::npos && cmdline.find(".dll") != std::string::npos){
		std::stringstream ss;
		ss<< "Winlogon Notify key set to execute a notification package DLL at logon ";
		rule_event.metadata =  ss.str();
		return true;
	}
	return false;
}


// T1546.003 - Powershell WMI Persistence
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%New-CimInstance%' and cmdline like '%-Namespace root/subscription%' and cmdline like '%-ClassName __EventFilter%' and cmdline like '%-Property%' and cmdline like '%-ClassName CommandLineEventConsumer%');

bool powershell_WMI_persistence(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if(cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-CimInstance") != std::string::npos && cmdline.find("-Namespace root/subscription") != std::string::npos && cmdline.find("-ClassName __EventFilter") != std::string::npos && cmdline.find("-Property") != std::string::npos && cmdline.find("-ClassName CommandLineEventConsumer") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Execution of malicious content triggered by a Windows Management Instrumentation (WMI) event subscription";
		rule_event.metadata = ss.str();

		return true;	
	}
	
	return false;
}

//T1546.015 - Powershell Execute COM Object
//select * from win_process_events where cmdline like'%[type]::GetTypeFromCLSID(%';

bool powershell_execute_COM_object(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if(cmdline.find("[type]::GetTypeFromCLSID(") != std::string::npos)
	{
		std::stringstream ss;

        	ss << "PowerShell used to execute COM CLSID";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1134.002 - Suspicious Child Process Created as System
//select * from win_process_events where (cmdline like'%AUTHORI%' || cmdline like'%AUTORI%') and cmdline like'%\\rundll32.exe%' and cmdline like '%DavSetCookie%';

bool suspicious_child_process_created_as_system(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if((cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos) && !(cmdline.find("\\rundll32.exe") != std::string::npos && cmdline.find("DavSetCookie") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected child processes spawned with SYSTEM privileges that can be threatful";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}


//T1134.001 - HackTool - Impersonate Execution
// select * from win_process_events where cmdline like'%impersonate.exe%' || cmdline like'%list%';

bool hacktool_impersonate_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if((cmdline.find("impersonate.exe") != std::string::npos && cmdline.find("list") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Execution of Impersonate tools detected";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1548.002 - Always Install Elevated MSI Spawned Cmd And Powershell
// SELECT * FROM win_process_events WHERE (path LIKE '%cmd.exe%' OR path LIKE '%powershell.exe%' OR path LIKE '%pwsh.exe%') AND (parent_path LIKE '%\\Windows\\Installer\\%' AND parent_path LIKE '%msi%' AND parent_path LIKE '%tmp%');

bool always_install_elevated_MSI_spawned_cmd_and_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if((path.find("cmd.exe") != std::string::npos || path.find("powershell.exe") != std::string::npos || path.find("pwsh.exe") != std::string::npos) && (parent_path.find("\\Windows\\Installer\\") != std::string::npos && parent_path.find("msi") != std::string::npos) && parent_path.find("tmp") != std::string::npos)
	{
		std::stringstream ss;	

        	ss << "Detected Windows Installer service (msiexec.exe) spawning 'cmd' or 'powershell'";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1546.007 - Potential Persistence Via Netsh Helper DLL
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND cmdline LIKE '%add%' AND cmdline LIKE '%helper%');

bool potential_persistence_via_netsh_helper_dll(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if(path.find("\\netsh.exe") != std::string::npos && (cmdline.find("add") != std::string::npos && cmdline.find("helper") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Potential Persistence Via Netsh Helper DLL";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1134.001 - Potential Meterpreter/CobaltStrike Activity

bool potential_meterpreter_cobaltstrikeactivity(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;

	if((parent_path.find("\\services.exe") != std::string::npos) && (cmdline.find("/c") != std::string::npos && cmdline.find("echo") != std::string::npos && cmdline.find("\\pipe\\") != std::string::npos && cmdline.find("rundll32") != std::string::npos && cmdline.find(".dll,a") != std::string::npos && cmdline.find("/p:") != std::string::npos))
	{
		std::stringstream ss;
        	ss << "Getsystem Meterpreter/Cobalt Strike command use detected";
        	rule_event.metadata = ss.str();
        	return true;	
	}
	return false;
}


// T1134.001 - HackTool - SharpImpersonation Execution

bool hacktool_sharpimpersonation_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if((path.find("\\SharpImpersonation.exe") != std::string::npos) && (cmdline.find("user:") != std::string::npos && cmdline.find("binary:") != std::string::npos && cmdline.find("shellcode:") != std::string::npos) || cmdline.find("technique:CreateProcessAsUserW") != std::string::npos || cmdline.find("technique:ImpersonateLoggedOnuser") != std::string::npos)
	{
		std::stringstream ss;
        ss << "SharpImpersonation execution detected";
        rule_event.metadata = ss.str();
        return true;	
	}
	return false;
}


// T1546.002 - Suspicious ScreenSave Change by Reg.exe
//SELECT * FROM win_process_events WHERE path LIKE '%\\reg.exe%' AND (cmdline LIKE '%HKEY_CURRENT_USER\\Control Panel\\Desktop%' OR cmdline LIKE '%HKCU\\Control Panel\\Desktop%') AND ((cmdline LIKE '%/v ScreenSaveActive%' AND cmdline LIKE '%/t REG_SZ%' AND cmdline LIKE '%/d 1%' AND cmdline LIKE '%/f%') OR (cmdline LIKE '%/v ScreenSaveTimeout%' AND cmdline LIKE '%/t REG_SZ%' AND cmdline LIKE '%/d %' AND cmdline LIKE '%/f%') OR (cmdline LIKE '%/v ScreenSaverIsSecure%' AND cmdline LIKE '%/t REG_SZ%' AND cmdline LIKE '%/d 0%' AND cmdline LIKE '%/f%') OR (cmdline LIKE '%/v SCRNSAVE.EXE%' AND cmdline LIKE '%/t REG_SZ%' AND cmdline LIKE '%/d %' AND cmdline LIKE '%.scr%' AND cmdline LIKE '%/f%'));

bool suspicious_screensave_change_by_regexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if(path.find("\\reg.exe") != std::string::npos && (cmdline.find("HKEY_CURRENT_USER\\Control Panel\\Desktop") != std::string::npos || cmdline.find("HKCU\\Control Panel\\Desktop") != std::string::npos) && ((cmdline.find("/v ScreenSaveActive") != std::string::npos && cmdline.find("/t REG_SZ") != std::string::npos && cmdline.find("/d 1") != std::string::npos && cmdline.find("/f") != std::string::npos) || (cmdline.find("/v ScreenSaveTimeout") != std::string::npos && cmdline.find("/t REG_SZ") != std::string::npos && cmdline.find("/d ") != std::string::npos && cmdline.find("/f") != std::string::npos) || (cmdline.find("/v ScreenSaverIsSecure") != std::string::npos && cmdline.find("/t REG_SZ") != std::string::npos && cmdline.find("/d 0") != std::string::npos && cmdline.find("/f") != std::string::npos) || (cmdline.find("/v SCRNSAVE.EXE") != std::string::npos && cmdline.find("/t REG_SZ") != std::string::npos && cmdline.find("/d ") != std::string::npos && cmdline.find(".scr") != std::string::npos && cmdline.find("/f") != std::string::npos)))
	{
		std::stringstream ss;

        	ss << "Detected establishment of persistence by adversary by executing malicious content due user inactivity";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1548 - Regedit as Trusted Installer
// SELECT * FROM win_process_events WHERE path LIKE '%regedit.exe%' AND (parent_path LIKE '%\\TrustedInstaller.exe%' OR parent_path LIKE '%\\ProcessHacker.exe%');

bool regedit_as_trusted_installer(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if(path.find("regedit.exe") != std::string::npos && (parent_path.find("\\TrustedInstaller.exe") != std::string::npos || parent_path.find("\\ProcessHacker.exe") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected regedit suspiciously started as Trusted Installer";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1574.011 - Potential Privilege Escalation via Service Permissions Weakness
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%ControlSet%' AND cmdline LIKE '%services%') AND (cmdline LIKE '%\\ImagePath%' OR cmdline LIKE '%\\FailureCommand%' OR cmdline LIKE '%\\ServiceDll%');

bool potential_privilege_escalation_via_service_permissions_weakness(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if((cmdline.find("ControlSet") != std::string::npos && cmdline.find("services") != std::string::npos) && (cmdline.find("\\ImagePath") != std::string::npos || cmdline.find("\\FailureCommand") != std::string::npos || cmdline.find("\\ServiceDll") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected modification of services configuration in registry";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}


bool hacktool_sharpup_privesc_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if((path.find("\\SharpUp.exe") != std::string::npos) && (cmdline.find("HijackablePaths") != std::string::npos || cmdline.find("UnquotedServicePath") != std::string::npos || cmdline.find("ProcessDLLHijack") != std::string::npos || cmdline.find("ModifiableServiceBinaries") != std::string::npos || cmdline.find("ModifiableScheduledTask") != std::string::npos || cmdline.find("DomainGPPPassword") != std::string::npos || cmdline.find("CachedGPPPassword") != std::string::npos))
	{
		std::stringstream ss;
        	ss << "Use of SharpUp detected !";
        	rule_event.metadata = ss.str();
        	return true;	
	}
	return false;
}


bool hacktool_winpeas_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	
	if(cmdline.find("applicationsinfo") != std::string::npos || cmdline.find("browserinfo") != std::string::npos || cmdline.find("eventsinfo") != std::string::npos || cmdline.find("fileanalysis") != std::string::npos || cmdline.find("filesinfo") != std::string::npos || cmdline.find("processinfo") != std::string::npos || cmdline.find("servicesinfo") != std::string::npos || cmdline.find("windowscreds") != std::string::npos || cmdline.find("https://github.com/carlospolop/PEASS-ng/releases/latest/download/") != std::string::npos || cmdline.find("-linpeas") != std::string::npos)
	{
		std::stringstream ss;
        	ss << "WinPEAS Script presence detected !";
        	rule_event.metadata = ss.str();
        	return true;	
	}
	return false;
}

// T1548.002 - Bypass UAC via Fodhelper.exe
// SELECT * FROM win_process_events WHERE cmdline LIKE '%reg.exe%' AND cmdline LIKE '%\\software\\classes\\ms-settings\\shell\\open\\command%' AND cmdline LIKE '%fodhelper.exe%' AND cmdline LIKE '%/f%';

bool bypass_UAC_via_fodhelper_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("reg.exe") != std::string::npos &&
    cmdline.find("\\software\\classes\\ms-settings\\shell\\open\\command") != std::string::npos &&
    cmdline.find("fodhelper.exe") != std::string::npos &&
    cmdline.find("/f") != std::string::npos)
	{
		std::stringstream ss;

        	ss << "Detected use of Fodhelper.exe to bypass User Account Control to execute privileged processes.";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1548.002 - Bypass UAC via Fodhelper.exe - Powershell
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell.exe%' AND cmdline LIKE '%\\software\\classes\\ms-settings\\shell\\open\\command%' AND cmdline LIKE '%Start-Process%' AND cmdline LIKE '%C:\\Windows\\System32\\fodhelper.exe%';

bool bypass_UAC_via_fodhelper_exe_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos &&
    cmdline.find("\\software\\classes\\ms-settings\\shell\\open\\command") != std::string::npos &&
    cmdline.find("Start-Process") != std::string::npos &&
    cmdline.find("C:\\Windows\\System32\\fodhelper.exe") != std::string::npos)
	{
		std::stringstream ss;

        	ss << "Detected use of Fodhelper.exe via PowerShell to bypass User Account Control to execute privileged processes.";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

// T1548 - UAC Bypass via Windows Firewall Snap-In Hijack
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\mmc.exe%' OR cmdline LIKE '%WF.msc%') AND cmdline LIKE '%\\WerFault.exe%';

bool uac_bypass_via_windows_firewall_snap_in_hijack(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;

	if ((parent_path.find("\\mmc.exe") != std::string::npos || cmdline.find("WF.msc") != std::string::npos) && !(cmdline.find("\\WerFault.exe") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected attempts to bypass UAC by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1574.011 - Abuse of Service Permissions to Hide Services Via Set-Service
//select * from win_process_events where (cmdline like '%-sd %' or cmdline like '%-SecurityDescriptorSddl%') and cmdline like '%Set-Service%' and cmdline like '%DCLCWPDTSD%';

bool abuse_of_service_permission_to_hide_services_via_set_service(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("-sd ") != std::string::npos ||
    cmdline.find("-SecurityDescriptorSddl ") != std::string::npos) &&
    cmdline.find("Set-Service ") != std::string::npos &&
	cmdline.find("DCLCWPDTSD") != std::string::npos)
	{
		std::stringstream ss;

        	ss << "Abuse of Service Permissions to Hide Services Via Set-Service";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1212 - Suspicious NTLM Authentication on the Printer Spooler Service
//select * from win_process_events where path like '%\rundll32.exe%' AND (cmdline like '%C:\\windows\\system32\\davclnt.dll,DavSetCookie%' AND cmdline like '%http%') AND (cmdline like '%spoolss%' OR cmdline like '%srvsvc%' OR cmdline like '%/print/pipe/%');

bool suspicious_nltm_authentication_on_the_printer_spooler_service(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\rundll32.exe") != std::string::npos && (cmdline.find("C:\\windows\\system32\\davclnt.dll,DavSetCookie") != std::string::npos && cmdline.find("http") != std::string::npos) && (cmdline.find("spoolss") != std::string::npos || cmdline.find("srvsvc") != std::string::npos || cmdline.find("/print/pipe/") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1546.015 - Rundll32 Registered COM Objects
//select * from win_process_events where path like '%\\rundll32.exe%' AND (cmdline like '%-sta %' OR cmdline like '%-localserver %') AND (cmdline like '%{%' AND cmdline like '%}%');

bool rundll32_registered_com_objects(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\rundll32.exe") != std::string::npos && (cmdline.find("-sta ") != std::string::npos || cmdline.find("-localserver ") != std::string::npos) && (cmdline.find("{") != std::string::npos && cmdline.find("}") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected loading of malicious registered COM objects";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1134.002 - PUA - AdvancedRun Suspicious Execution
//select * from win_process_events where (cmdline like '%/EXEFilename%' or cmdline like '%/CommandLine%') and (cmdline like '% /RunAs 8 %' or cmdline like '% /RunAs 4 %' or cmdline like '% /RunAs 10 %' or cmdline like '% /RunAs 11 %') and (cmdline like '%/RunAs 8%' or cmdline like '%/RunAs 4%' or cmdline like '%/RunAs 10%' or cmdline like '%/RunAs 11%');

bool pua_advancedrun_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("/EXEFilename") != std::string::npos ||
	cmdline.find("/CommandLine") != std::string::npos) && 
	(cmdline.find(" /RunAs 8 ") != std::string::npos ||
	cmdline.find(" /RunAs 4 ") != std::string::npos || 
	cmdline.find(" /RunAs 10 ") != std::string::npos || 
	cmdline.find(" /RunAs 11 ") != std::string::npos) && 
	(cmdline.find("/RunAs 8") != std::string::npos ||
	cmdline.find("/RunAs 4") != std::string::npos ||
	cmdline.find("/RunAs 10") != std::string::npos ||
	cmdline.find("/RunAs 11") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "PUA - AdvancedRun Suspicious Execution";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1134.002 - PUA - AdvancedRun Execution
//select * from win_process_events where cmdline like '% /EXEFilename%' and cmdline like '% /Run%' and cmdline like '% /WindowState 0%' and cmdline like '% /RunAs%' and cmdline like '% /CommandLine%';

bool pua_advancedrun_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(" /EXEFilename") != std::string::npos &&
	cmdline.find(" /Run") != std::string::npos && 
	cmdline.find(" /WindowState 0") != std::string::npos &&
	cmdline.find(" /RunAs ") != std::string::npos && 
	cmdline.find(" /CommandLine ") != std::string::npos)
	{
		std::stringstream ss;

        	ss << "PUA - AdvancedRun Execution";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1548.002 - Sdclt Child Processes
//select * from win_process_events where parent_path like '%\\sdclt.exe%';

bool sdclt_child_processes(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("\\sdclt.exe") != std::string::npos)
	{
		std::stringstream ss;

        	ss << "Detected sdclt spawning new processes which could be an indicator of sdclt being used for bypass UAC techniques.";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1548 - Abused Debug Privilege by Arbitrary Parent Processes
//SELECT * FROM win_process_events WHERE ((parent_path LIKE '%\\winlogon.exe%' OR parent_path LIKE '%\\services.exe%' OR parent_path LIKE '%\\lsass.exe%' OR parent_path LIKE '%\\csrss.exe%' OR parent_path LIKE '%\\smss.exe%' OR parent_path LIKE '%\\wininit.exe%' OR parent_path LIKE '%\\spoolsv.exe%' OR parent_path LIKE '%\\searchindexer.exe%') AND (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%') AND (path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR path LIKE '%\\cmd.exe%') AND NOT (cmdline LIKE '% route %' AND cmdline LIKE '% ADD %'));


bool abused_debug_privilege_by_arbitrary_parent_processes(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if ((parent_path.find("\\winlogon.exe") != std::string::npos || parent_path.find("\\services.exe") != std::string::npos || parent_path.find("\\lsass.exe") != std::string::npos || parent_path.find("\\csrss.exe") != std::string::npos || parent_path.find("\\smss.exe") != std::string::npos || parent_path.find("\\wininit.exe") != std::string::npos || parent_path.find("\\spoolsv.exe") != std::string::npos || parent_path.find("\\searchindexer.exe") != std::string::npos) && (cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos) && (path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\cmd.exe") != std::string::npos) && !(cmdline.find(" route ") != std::string::npos && cmdline.find(" ADD ") != std::string::npos))
	{
		std::stringstream ss;

        	ss << "Detected unusual child processes by different system processes.";
        	rule_event.metadata = ss.str();

        	return true;	
	}
	
	return false;
}

//T1053.002 - Interactive AT Job
//select * from win_process_events where path like '%at.exe%' and cmdline like '%interactive%';

bool interactive_at_job(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if(path.find("at.exe") !=  std::string::npos && cmdline.find("interactive") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected an interactive AT job that can be used for privilege escalation";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1546.008 - Potential Privilege Escalation Using Symlink Between Osk and Cmd
//SELECT * FROM win_process_events WHERE path LIKE '%\\cmd.exe%' AND cmdline LIKE '%mklink%' AND cmdline LIKE '%\\osk.exe%' AND cmdline LIKE '%\\cmd.exe%';

bool symlink_osk_and_cmd(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\cmd.exe") != std::string::npos && cmdline.find("mklink") != std::string::npos && cmdline.find("\\osk.exe") != std::string::npos && cmdline.find("\\cmd.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected access of an elevated cmd prompt without logging in";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1055 - HackTool - CoercedPotato Execution
//
bool hacktool_coercedPotato(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\CoercedPotato.exe") && cmdline.find(" --exploitId ") != std::string::npos &&
    (cmdline.find("a75d7669db6b2e107a44c4057ff7f7d6") != std::string::npos ||
     cmdline.find("f91624350e2c678c5dcbe5e1f24e22c9") != std::string::npos ||
     cmdline.find("14c81850a079a87e83d50ca41c709a15") != std::string::npos)) {
    	std::stringstream ss;
		ss << "Detected the use of CoercedPotato, a tool for privilege escalation";
		rule_event.metadata = ss.str();
		return true;
}
return false;

}

bool uac_bypass_usinf_wusaexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("wusa.exe") != std::string::npos && (cmdline.find("/extract") != std::string::npos || cmdline.find("/quiet") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detects the usage of wusa.exe in order to bypass UAC.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}