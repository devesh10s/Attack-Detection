#include "win_execution_rules.h"
#include <sstream>

// EXECUTION

// T1053.005 - Scheduled Task/Job: Scheduled Task
//"select path, parent_path, cmdline from win_process_events where (cmdline like '%SCHTASKS%' and (cmdline like '%Create%' or cmdline like '%create%') and (cmdline like '%system32%' or cmdline like '%WinSxS%' or cmdline like '%program files%'));
// ii) schedule task : select * from win_process_events where action=""PROC_CREATE"" and path like ""%at.exe%"" and cmdline like '%at.exe"";"

bool scheduled_task_job(const ProcessEvent &win_process_event, Event &rule_event)
{
	if (win_process_event.entry.cmdline.find("SCHTASKS") != std::string::npos && (win_process_event.entry.cmdline.find("Create") != std::string::npos || win_process_event.entry.cmdline.find("create") != std::string::npos) && (win_process_event.entry.cmdline.find("system32") != std::string::npos || win_process_event.entry.cmdline.find("WinSxS") != std::string::npos || win_process_event.entry.cmdline.find("program files") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Win Task Scheduler may be possibly abused to run malicious tasks";
		rule_event.metadata = ss.str();
		return true;
	}

	// if (win_process_event.entry.action == "PROC_CREATE" && win_process_event.entry.path.find("at.exe") != std::string::npos && win_process_event.entry.path.find("at.exe") != std::string::npos)
	// {
	// 	std::stringstream ss;
	// 	ss << "Win Task Scheduler may be possibly abused to run malicious tasks";
	// 	rule_event.metadata = ss.str();
	// 	return true;
	// }
	// return false;
	return false;
}

// T1106: Native API
/*
i) select path, parent_path, cmdline from win_process_events where action="PROC_CREATE" and cmdline like '%cvtres%' and cmdline like '%NOLOGO%'  order by time desc limit 15;
ii) select path, parent_path, cmdline from win_process_events where parent_path like "%Microsoft.NET\Framework64%csc.exe" and cmdline like "%cvtres.exe /NOLOGO /READONLY%";
iv) select path, parent_path, cmdline from win_process_events where parent_path like "%services.exe" and cmdline like "%.\pipe%";
*/

bool native_api(const ProcessEvent &win_process_event, Event &rule_event)
{
	if (win_process_event.entry.action == "PROC_CREATE" && win_process_event.entry.cmdline.find("cvtres") != std::string::npos && win_process_event.entry.cmdline.find("NOLOGO") != std::string::npos)
	{
		std::stringstream ss;
		ss << "...";
		rule_event.metadata = ss.str();
		return true;
	}

	if ((win_process_event.entry.parent_path.find("Microsoft.NET\\Framework64") != std::string::npos && win_process_event.entry.parent_path.find("csc.exe") != std::string::npos) && win_process_event.entry.cmdline.find("cvtres.exe /NOLOGO /READONLY") != std::string::npos)
	{
		std::stringstream ss;
		ss << "...";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059: Command and Scripting Interpreter
//  select * from win_process_events where action="PROC_CREATE" and path like "%powershell.exe%" and parent_path like "%powershell.exe%" and cmdline like "%IEX%Net.WebClient%";

bool command_and_scripting_interpreter(const ProcessEvent &win_process_event, Event &rule_event)
{
	if (win_process_event.entry.action == "PROC_CREATE" && win_process_event.entry.path.find("powershell.exe") != std::string::npos && win_process_event.entry.parent_path.find("powershell.exe") != std::string::npos && win_process_event.entry.cmdline.find("IEX") != std::string::npos && win_process_event.entry.cmdline.find("Net.WebClient") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Powershell Command may be abused";
		rule_event.metadata = ss.str();
		return true;
	}

	return false;
}

// T1569.002: System Services: Service Execution
//  select * from win_process_events where cmdline like '%sc.exe create%' and cmdline like '%binPath%' and cmdline like '%ARTService%';
bool service_execution(const ProcessEvent &win_process_event, Event &rule_event)
{
	if (win_process_event.entry.cmdline.find("sc.exe create") != std::string::npos && win_process_event.entry.cmdline.find("binPath") != std::string::npos && win_process_event.entry.cmdline.find("ARTService") != std::string::npos)
	{
		rule_event.metadata = "New service created";
		return true;
	}
	return false;
}

// T1059.007 - Command and Scripting Interpreter: JavaScript
//  select * from win_process_events where path like '%wscript%' and cmdline like '%wscript%' and cmdline like '%.js%';

bool command_scripting_interpreter_javascript(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.path.find("wscript") != std::string::npos && process_event.entry.cmdline.find("wscript") != std::string::npos && process_event.entry.cmdline.find(".js") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Javascript executed for malicious purpose";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Command and Scripting Interpreter: PowerShell
// select * from win_process_events where (cmdline like '%mshta.exe%' and cmdline like '%javascript%') or (cmdline like '%SharpHound.ps1%' and cmdline '%write-host%');

bool command_scripting_interpreter_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("mshta.exe") != std::string::npos && cmdline.find("javascript") != std::string::npos) || (cmdline.find("SharpHound.ps1") != std::string::npos && cmdline.find("write-host") != std::string::npos))
	{

		std::stringstream ss;
		ss << "Powershell commands and scripts used for execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.003 - Command and Scripting Interpreter: Windows Command Shell
// select * from win_process_events where (path like '%cmd.exe%' or path like '%powershell.exe%') and (cmdline like '%do start%' and cmdline like '%powershell%');

bool command_scripting_interpreter_win_command_shell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;

	if ((path.find("cmd.exe") != std::string::npos || path.find("powershell.exe")) && (cmdline.find("do start") != std::string::npos && cmdline.find("powershell.exe")))
	{
		std::stringstream ss;
		ss << "Windows command shell used for execution ";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.005 - Command and Scripting Interpreter: Visual Basic
//  select * from win_process_events where path like '%powershell.exe%' and cmdline like '%cscript%' and cmdline like '%powershell.exe%';

bool command_scripting_interpreter_visual_basic(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;

	if (path.find("powershell.exe") && cmdline.find("cscript") != std::string::npos && cmdline.find("powershell.exe"))
	{

		std::stringstream ss;
		ss << " Visual Basic used for execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1204.002 - User Execution: Malicious File
//  select * from win_process_events where path like '%cscript.exe%' and cmdline like '%WScript%' and cmdline like '%cscript%';

bool malicious_file_user_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("cscript.exe") != std::string::npos && cmdline.find("WScript") != std::string::npos && cmdline.find("cscript") != std::string::npos)
	{
		std::stringstream ss;
		ss << " ";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Abuse Nslookup with DNS Records
// select * from win_process_events where (path like '%nslookup.exe%' and (cmdline like '%nslookup.exe%' || cmdline like '%-q=txt%') and (path like '%powershell.exe%' and (cmdline like '%powershell.exe%')

bool abuse_nslookup(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;

	if ((path.find("nslookup.exe") != std::string::npos && (cmdline.find("nslookup.exe") != std::string::npos || cmdline.find("-q=txt") != std::string::npos)) && (path.find("powershell.exe") != std::string::npos && cmdline.find("powershell.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Abused nslookup with DNS records";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1490 - Delete Volume Shadow Copies Via WMI With PowerShell
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%Get-WmiObject%' and cmdline like '%Win32_Shadowcopy%') and (cmdline like '%Delete()%' or cmdline like '%Remove-WmiObject%'))

bool delete_volume_shadow_copies_via_WMI_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Get-WmiObject") != std::string::npos && cmdline.find("Win32_Shadowcopy") != std::string::npos) && (cmdline.find("Delete()") != std::string::npos || cmdline.find("Remove-WmiObject") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Remote powershell created and may be used";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.006, T1059.001 - Remote PowerShell Session (PS Classic)
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Enable-PSRemoting%' and cmdline like '%whoami%' or (cmdline like '%wsmprovhost.exe%' and cmdline like '%ServerRemoteHost%')

bool remote_powershell_session(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && ((cmdline.find("Enable-PSRemoting") != std::string::npos && cmdline.find("whoami") != std::string::npos) || (cmdline.find("wsmprovhost.exe") != std::string::npos && cmdline.find("ServerRemoteHost") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Remote powershell created and may be used";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.003 - Suspicious Non PowerShell WSMAN COM Provider
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%WSMan%' (To be checked again)

bool suspicious_non_powerShell_WSMAN_COM_provider(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("WSMan") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Remote powershell created and may be used";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1136.001 - PowerShell Create Local User
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%WSMan%' (To be checked again)

bool powershell_create_local_user(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-LocalUser") != std::string::npos && cmdline.find("Name") != std::string::npos && cmdline.find("-NoPassword") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Local user created";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Powershell MsXml COM Object
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%New-Object%' and cmdline like '%-ComObject%' and cmdline like '%MsXml2%' and cmdline like '%XmlHttp%');

bool powershell_MsXml_COM_object(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Object") != std::string::npos && cmdline.find("-ComObject") != std::string::npos && cmdline.find("MsXml2") != std::string::npos && cmdline.find("XmlHttp") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PowerShell commands and scripts may be abused for execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - PowerShell Remote Session Creation
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%New-PSSession%' and cmdline like '%-ComputerName%' and cmdline like '%Set-Content%' and cmdline like '%Get-Content%'); (to be checkedd)

bool powershell_remote_session_creation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-PSSession") != std::string::npos && cmdline.find("-ComputerName") != std::string::npos && cmdline.find("Set-Content") != std::string::npos && cmdline.find("Get-Content") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PowerShell remote session created";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1070.004 - Use Remove-Item to Delete File
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Remove-Item%' and cmdline like '%-path%');

bool use_remove_item_to_delete_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Remove-Item") != std::string::npos && cmdline.find("-path") != std::string::npos)
	{
		std::stringstream ss;
		ss << "File deleted using remove-item from temporary directory";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.003 - Powershell Execute Batch Script
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Start-Process%' and (cmdline like '%.bat%' || cmdline like '%.cmd%'));

bool powershell_execute_batch_script(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Start-Process") != std::string::npos && (cmdline.find(".bat") != std::string::npos || cmdline.find(".cmd") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Batch script executed in powershell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1546.003 - Powershell XML Execute Command
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%New-Object%' and cmdline like '%System.Xml.XmlDocument%' && cmdline like '%.Load%');

bool powershell_XML_execute_command(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Object") != std::string::npos && cmdline.find("System.Xml.XmlDocument") != std::string::npos && cmdline.find(".Load") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Powershell XML execute command";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1569.002 - PowerShell Scripts Run by a Services
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Start-Process%' and (cmdline like '%.bat%' || cmdline like '%.cmd%'));

bool powershell_scripts_run_by_services(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Item") != std::string::npos && cmdline.find("pwsh") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PowerShell Scripts Run by Services";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// EXECUTION

// T1059.001 - Alternate PowerShell Hosts
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Citrix\\ConfigSync\\%');

bool alternate_powershell_hosts(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && !(cmdline.find("Citrix\\ConfigSync\\") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Alternate PowerShell Host detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool powershell_called_from_an_executable_version_mismatch(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Citrix\\ConfigSync\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Alternate PowerShell Host detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Suspicious PowerShell Download
// select * from win_process_events where (cmdline like '%Net.WebClient%' and (cmdline like '%.DownloadFile(%' || cmdline like '%.DownloadString(%'));

bool suspicious_powershell_download(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Net.WebClient") != std::string::npos && (cmdline.find(".DownloadFile(") != std::string::npos || cmdline.find(".DownloadString(") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious PowerShell Download";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Suspicious XOR Encoded PowerShell Command Line - PowerShell
// select * from win_process_events where (cmdline like '%bxor%' and cmdline like '%join%' && cmdline like '%char%');

bool suspicious_XOR_encoded_powershell_command_line_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("ConsoleHost") != std::string::npos && cmdline.find("bxor") != std::string::npos && cmdline.find("join") != std::string::npos && cmdline.find("char") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious powershell process including bxor command detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Remote PowerShell Session (PS Module)
// select * from win_process_events where (cmdline like '%= ServerRemoteHost%' and cmdline like '%wsmprovhost.exe%');

bool remote_powershell_session_ps_module(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("= ServerRemoteHost") != std::string::npos && cmdline.find("wsmprovhost.exe") != std::string::npos) && !(path.find("\\Windows\\system32\\\v1.0\\Microsoft.PowerShell.Archive\\Microsoft.PowerShell.Archive.psm1") != std::string::npos ))
	{
		std::stringstream ss;
		ss << "Remote powershell sessions might have been created";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - PowerShell ADRecon Execution
// select * from win_process_events where (cmdline like '%Function Get-ADRExcelComOb%' or cmdline like '%Get-ADRGPO%' or cmdline like '%Get-ADRDomainController%');

bool powershell_ADRecon_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Function Get-ADRExcelComOb") != std::string::npos || cmdline.find("Get-ADRGPO") != std::string::npos || cmdline.find("Get-ADRDomainController") != std::string::npos)
	{
		std::stringstream ss;
		ss << "ADRecon.ps1 script executed";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - PSAsyncShell - Asynchronous TCP Reverse Shell
// select * from win_process_events where cmdline like '%PSAsyncShell%';

bool PSAsyncShell_synchronous_TCP_reverse_shell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("PSAsyncShell") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected use of PSAsyncShell an Asynchronous TCP Reverse Shell to bypass firewalls.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Malicious ShellIntel PowerShell Commandlets
// select * from win_process_events where cmdline like '%Invoke-SMBAutoBrute%' or cmdline like '%Invoke-GPOLinks%';

bool malicious_shellIntel_powershell_commandlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Invoke-SMBAutoBrute") != std::string::npos || cmdline.find("Invoke-GPOLinks") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Malicious ShellIntel PowerShell Commandlets"; // To be reviewed.
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1203 - Dfsvc.EXE Network Connection To Uncommon Ports
// select * from win_process_events where cmdline like '%dfsvc.exe%';
bool Dfsvc_EXE_network_connection_to_uncommon_ports(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	int port = process_event.entry.remote_port;

	if (cmdline.find("dfsvc.exe") != std::string::npos && port != 80 && port != 443 && port != 445)
	{
		std::stringstream ss;
		ss << "Detected network connection from 'dfsvc.exe' to uncommon ports";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1203 - Equation Editor Network Connection
// select * from win_process_events where cmdline like '%eqnedt32.exe%';
bool equation_editor_network_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("eqnedt32.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected network connection from 'eqnedt32.exe'";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1204 - Arbitrary Shell Command Execution Via Settingcontent-Ms
// select * from win_process_events where cmdline like '%.SettingContent-ms%' and cmdline like '%immersivecontrolpanel%';
bool arbitrary_shell_command_execution_via_settingcontent_Ms(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(".SettingContent-ms") != std::string::npos && !(cmdline.find("immersivecontrolpanel") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Shell commands might be executed via Settingcontent-Ms"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Arbitrary Shell Command Execution Via Settingcontent-Ms
// SELECT * FROM win_process_events WHERE (path LIKE '%powershell.exe%' OR path LIKE '%pwsh.exe%' OR path LIKE '%cmd.exe%') AND (cmdline LIKE '%-ur%' AND cmdline LIKE '%-me%' AND cmdline LIKE '%-b%' AND cmdline LIKE '%POST%') AND (cmdline LIKE '%-d%' OR cmdline LIKE '%--data%');

bool potential_data_exfiltration_activity_via_commandLine_tools(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("powershell.exe") != std::string::npos || path.find("pwsh.exe") != std::string::npos || path.find("cmd.exe") != std::string::npos) && (cmdline.find("-ur") != std::string::npos && cmdline.find("-me") != std::string::npos && cmdline.find("-b") != std::string::npos && cmdline.find("POST") != std::string::npos) && (cmdline.find("-d") != std::string::npos || cmdline.find("--data") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected Data exfiltration via web requests through CommandLine Utilities";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1557.001 - HackTool - Impacket Tools Execution

bool hacktool_impact_tools_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("\\goldenPac") != std::string::npos || path.find("\\karmaSMB") != std::string::npos || path.find("\\kintercept") != std::string::npos || path.find("\\ntlmrelayx") != std::string::npos || path.find("\\rpcdump") != std::string::npos || path.find("\\samrdump") != std::string::npos || path.find("\\secretsdump") != std::string::npos || path.find("\\smbexec") != std::string::npos || path.find("\\smbrelayx") != std::string::npos || path.find("\\wmiexec") != std::string::npos || path.find("\\wmipersist") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Different compiled Windows binaries of the impacket toolset simultaneous execution found"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Wsudo Suspicious Execution
// select * from win_process_events where (path like '%\wsudo.exe%' or parent_path like '%\wsudo-bridge.exe%') or (cmdline like '%-u System%' or cmdline like '%-uSystem%' or cmdline like '%-u TrustedInstaller%' or cmdline like '%-uTrustedInstaller%' or cmdline like '% --ti %');

bool wsudo_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((path.find("\\wsudo.exe") != std::string::npos || parent_path.find("\\wsudo-bridge.exe") != std::string::npos) || (cmdline.find("-u System") != std::string::npos || cmdline.find("-uSystem") != std::string::npos || cmdline.find("-u TrustedInstaller") != std::string::npos || cmdline.find("-uTrustedInstaller") != std::string::npos || cmdline.find(" --ti ") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Wsudo tool might be used to execute programs without permission"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1569.002 - Start Windows Service Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% start%');

bool start_windows_service_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" start") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Start Windows Service Via Net.EXE"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}
// T1059 - Python Inline Command Execution
// select * from win_process_events where (path like '%python.exe%' or path like '%python2.exe%' or path like '%python3.exe%') and cmdline like '% -c%' and not (parent_path like '%C:\Program Files\Python%' or parent_path like '%\python.exe%' or cmdline like '%-E -s -m ensurepip -U --default-pip%' or parent_path like '%\AppData\Local\Programs\Microsoft VS Code\Code.exe%');
bool python_inline_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((path.find("python.exe") != std::string::npos || path.find("python2.exe") != std::string::npos || path.find("python3.exe") != std::string::npos) && cmdline.find(" -c") != std::string::npos && !(parent_path.find("C:\\Program Files\\Python") || parent_path.find("\\python.exe") || cmdline.find("-E -s -m ensurepip -U --default-pip") || parent_path.find("\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe")))
	{
		std::stringstream ss;
		ss << "Python might be executed to launch a reverse shell or execute live python code."; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.003 - HackTool - Jlaive In-Memory Assembly Execution

bool hacktool_jlaive_inmemory_assembly_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((path.find("\\attrib.exe") != std::string::npos || path.find("\\xcopy.exe") != std::string::npos) && (parent_path.find("\\cmd.exe") != std::string::npos) && (cmdline.find("powershell.exe") != std::string::npos && cmdline.find(".bat.exe") != std::string::npos && cmdline.find("pwsh.exe") != std::string::npos && cmdline.find("+s") != std::string::npos && cmdline.find("+h") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Jlaive present while executing assemblies in a copied PowerShell"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}
// T1059 - Python Spawning Pretty TTY on Windows
// select * from win_process_events where (path like '%python.exe%' or path like '%python2.exe%' or path like '%python3.exe%') and ((cmdline like '%import pty%' and cmdline like '%.spawn(%') or (cmdline like '%from pty import spawn%'));
bool python_spawn_pretty_tty(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("python.exe") != std::string::npos || path.find("python2.exe") != std::string::npos || path.find("python3.exe") != std::string::npos) && ((cmdline.find("import pty") != std::string::npos && cmdline.find(".spawn(") != std::string::npos) || (cmdline.find("from pty import spawn") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Python might be executed to spawn pretty tty"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1041 - Query Usage To Exfil Data
// select * from win_process_events where path like '%\Windows\System32\query.exe%' and (cmdline like '%session >%' or cmdline like '%process >%');
bool query_usage_to_exfil_data(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\Windows\\System32\\query.exe") != std::string::npos && (cmdline.find("session >") != std::string::npos || cmdline.find("process >") != std::string::npos))
	{
		std::stringstream ss;
		ss << "'Query' system binary might be executed to exfil information"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Elevated System Shell Spawned
// SELECT * FROM win_process_events WHERE (path LIKE '%cmd.exe%' OR path LIKE '%powershell.exe%' OR path LIKE '%pwsh.exe%') AND (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%');

bool elevated_system_shell_spawned(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("cmd.exe") != std::string::npos || path.find("powershell.exe") != std::string::npos || path.find("pwsh.exe") != std::string::npos) && (cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected a shell program such as the Windows command prompt or PowerShell launched with system privileges";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Hidden Powershell in Link File Pattern
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell%' AND cmdline LIKE '%.lnk%';

bool hidden_powershell_in_link_file_pattern(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell") != std::string::npos && cmdline.find(".lnk") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected events that appear when a user click on a link file with a powershell command in it"; // To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.006 - Suspicious File Characteristics Due to Missing Fields
// SELECT * FROM win_process_events WHERE path LIKE '%\\Downloads%' AND cmdline LIKE '%\\?%';

bool suspicious_file_characteristics_due_to_missing_fields(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;

	if (path.find("\\Downloads") != std::string::npos && cmdline.find("\\?") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected Executables in the Downloads folder without FileVersion, Description, Product, Company likely created with py2exe";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Base64 MZ Header In CommandLine
// SELECT * FROM win_process_events WHERE cmdline LIKE '%TVqQAAMAAAAEAAAA%' OR cmdline LIKE '%TVpQAAIAAAAEAA8A%' OR cmdline LIKE '%TVqAAAEAAAAEABAA%' OR cmdline LIKE '%TVoAAAAAAAAAAAAA%' OR cmdline LIKE '%TVpTAQEAAAAEAAAA%';

bool base64_MZ_header_in_CommandLine(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("TVqQAAMAAAAEAAAA") != std::string::npos || cmdline.find("TVpQAAIAAAAEAA8A") != std::string::npos || cmdline.find("TVqAAAEAAAAEABAA") != std::string::npos || cmdline.find("TVoAAAAAAAAAAAAA") != std::string::npos || cmdline.find("TVpTAQEAAAAEAAAA") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected encoded base64 MZ header in the commandline";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.003 - HackTool - Koadic Execution

bool hacktool_koadic_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\cmd.exe") != std::string::npos) && (cmdline.find("/q") != std::string::npos && cmdline.find("/c") != std::string::npos && cmdline.find("chcp") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Command line parameters detected using Koadic hacktool";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1082 - HackTool - PCHunter Execution

bool hacktool_pchunter_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("\\PCHunter64.exe") != std::string::npos || path.find("\\PCHunter32.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious use of PCHunter detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// S0111 - HackTool - Default PowerSploit/Empire Scheduled Task Creation
// flag
bool hacktool_default_powersploit_or_empire_scheduled_task_creation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((parent_path.find("\\powershell.exe") != std::string::npos || parent_path.find("\\pwsh.exe") != std::string::npos) && (path.find("\\schtasks.exe") != std::string::npos) && (cmdline.find("/Create") != std::string::npos && cmdline.find("powershell.exe -NonI") != std::string::npos && cmdline.find("/TN Updater /TR") != std::string::npos) || (cmdline.find("/SC ONLOGON") != std::string::npos || cmdline.find("/SC DAILY /ST") != std::string::npos || cmdline.find("/SC ONIDLE") != std::string::npos || cmdline.find("/SC HOURLY") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Scheduled Task creation via PowerSploit/Empire detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1106 - HackTool - RedMimicry Winnti Playbook Execution

bool hacktool_redmimicry_winnti_playbook_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\cmd.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos) && (cmdline.find("gthread-3.6.dll") != std::string::npos && cmdline.find("\\Windows\\Temp\\tmp.bat") != std::string::npos && cmdline.find("sigcmm-2.4.dll") != std::string::npos))
	{
		std::stringstream ss;
		ss << "RedMimicry Winnti playbook usage detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1557.001 - Potential SMB Relay Attack Tool Execution

bool potential_smb_relay_attack_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("Invoke-Tater") != std::string::npos && cmdline.find("smbrelay") != std::string::npos && cmdline.find("ntlmrelay") != std::string::npos && cmdline.find("cme smb") != std::string::npos && cmdline.find("/ntlm:NTLMhash") != std::string::npos && cmdline.find("Invoke-PetitPotam") != std::string::npos && cmdline.find(".exe -t * -p") != std::string::npos && cmdline.find(".exe -c \"{") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Hacktools used for relay attacks on Windows for privilege escalation";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1106 - Potential WinAPI Calls Via CommandLine
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%AddSecurityPackage%' OR cmdline LIKE '%AdjustTokenPrivileges%' OR cmdline LIKE '%Advapi32%' OR cmdline LIKE '%CloseHandle%' OR cmdline LIKE '%CreateProcessWithToken%' OR cmdline LIKE '%CreatePseudoConsole%' OR cmdline LIKE '%CreateRemoteThread%' OR cmdline LIKE '%CreateThread%' OR cmdline LIKE '%CreateUserThread%' OR cmdline LIKE '%DangerousGetHandle%' OR cmdline LIKE '%DuplicateTokenEx%' OR cmdline LIKE '%EnumerateSecurityPackages%' OR cmdline LIKE '%FreeHGlobal%' OR cmdline LIKE '%FreeLibrary%' OR cmdline LIKE '%GetDelegateForFunctionPointer%' OR cmdline LIKE '%GetLogonSessionData%' OR cmdline LIKE '%GetModuleHandle%' OR cmdline LIKE '%GetProcAddress%' OR cmdline LIKE '%GetProcessHandle%' OR cmdline LIKE '%GetTokenInformation%' OR cmdline LIKE '%ImpersonateLoggedOnUser%' OR cmdline LIKE '%kernel32%' OR cmdline LIKE '%LoadLibrary%' OR cmdline LIKE '%memcpy%' OR cmdline LIKE '%MiniDumpWriteDump%' OR cmdline LIKE '%ntdll%' OR cmdline LIKE '%OpenDesktop%' OR cmdline LIKE '%OpenProcess%' OR cmdline LIKE '%OpenProcessToken%' OR cmdline LIKE '%OpenThreadToken%' OR cmdline LIKE '%OpenWindowStation%' OR cmdline LIKE '%PtrToString%' OR cmdline LIKE '%QueueUserApc%' OR cmdline LIKE '%ReadProcessMemory%' OR cmdline LIKE '%RevertToSelf%' OR cmdline LIKE '%RtlCreateUserThread%' OR cmdline LIKE '%secur32%' OR cmdline LIKE '%SetThreadToken%' OR cmdline LIKE '%VirtualAlloc%' OR cmdline LIKE '%VirtualFree%' OR cmdline LIKE '%VirtualProtect%' OR cmdline LIKE '%WaitForSingleObject%' OR cmdline LIKE '%WriteInt32%' OR cmdline LIKE '%WriteProcessMemory%' OR cmdline LIKE '%ZeroFreeGlobalAllocUnicode%') AND cmdline LIKE '%GetLoadLibraryWAddress32%';

bool potential_winAPI_calls_via_commandLine(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("AddSecurityPackage") != std::string::npos ||
		 cmdline.find("AdjustTokenPrivileges") != std::string::npos ||
		 cmdline.find("Advapi32") != std::string::npos ||
		 cmdline.find("CloseHandle") != std::string::npos ||
		 cmdline.find("CreateProcessWithToken") != std::string::npos ||
		 cmdline.find("CreatePseudoConsole") != std::string::npos ||
		 cmdline.find("CreateRemoteThread") != std::string::npos ||
		 cmdline.find("CreateThread") != std::string::npos ||
		 cmdline.find("CreateUserThread") != std::string::npos ||
		 cmdline.find("DangerousGetHandle") != std::string::npos ||
		 cmdline.find("DuplicateTokenEx") != std::string::npos ||
		 cmdline.find("EnumerateSecurityPackages") != std::string::npos ||
		 cmdline.find("FreeHGlobal") != std::string::npos ||
		 cmdline.find("FreeLibrary") != std::string::npos ||
		 cmdline.find("GetDelegateForFunctionPointer") != std::string::npos ||
		 cmdline.find("GetLogonSessionData") != std::string::npos ||
		 cmdline.find("GetModuleHandle") != std::string::npos ||
		 cmdline.find("GetProcAddress") != std::string::npos ||
		 cmdline.find("GetProcessHandle") != std::string::npos ||
		 cmdline.find("GetTokenInformation") != std::string::npos ||
		 cmdline.find("ImpersonateLoggedOnUser") != std::string::npos ||
		 cmdline.find("kernel32") != std::string::npos ||
		 cmdline.find("LoadLibrary") != std::string::npos ||
		 cmdline.find("memcpy") != std::string::npos ||
		 cmdline.find("MiniDumpWriteDump") != std::string::npos ||
		 cmdline.find("ntdll") != std::string::npos ||
		 cmdline.find("OpenDesktop") != std::string::npos ||
		 cmdline.find("OpenProcess") != std::string::npos ||
		 cmdline.find("OpenProcessToken") != std::string::npos ||
		 cmdline.find("OpenThreadToken") != std::string::npos ||
		 cmdline.find("OpenWindowStation") != std::string::npos ||
		 cmdline.find("PtrToString") != std::string::npos ||
		 cmdline.find("QueueUserApc") != std::string::npos ||
		 cmdline.find("ReadProcessMemory") != std::string::npos ||
		 cmdline.find("RevertToSelf") != std::string::npos ||
		 cmdline.find("RtlCreateUserThread") != std::string::npos ||
		 cmdline.find("secur32") != std::string::npos ||
		 cmdline.find("SetThreadToken") != std::string::npos ||
		 cmdline.find("VirtualAlloc") != std::string::npos ||
		 cmdline.find("VirtualFree") != std::string::npos ||
		 cmdline.find("VirtualProtect") != std::string::npos ||
		 cmdline.find("WaitForSingleObject") != std::string::npos ||
		 cmdline.find("WriteInt32") != std::string::npos ||
		 cmdline.find("WriteProcessMemory") != std::string::npos ||
		 cmdline.find("ZeroFreeGlobalAllocUnicode") != std::string::npos) &&
		cmdline.find("GetLoadLibraryWAddress32") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected the use of WinAPI Functions via the commandline";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Usage Of Web Request Commands And Cmdlets
// SELECT * FROM win_process_events WHERE cmdline LIKE '%[System.Net.WebRequest]::create%' AND cmdline LIKE '%curl%' AND cmdline LIKE '%Invoke-WebRequest%' AND cmdline LIKE '%iwr%' AND cmdline LIKE '%Net.WebClient%' AND cmdline LIKE '%wget%' AND cmdline LIKE '%WinHttp.WinHttpRequest%';

bool usage_of_web_request_commands_and_cmdlets(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("[System.Net.WebRequest]::create") != std::string::npos &&
		cmdline.find("curl ") != std::string::npos &&
		cmdline.find("Invoke-WebRequest") != std::string::npos &&
		cmdline.find("iwr") != std::string::npos &&
		cmdline.find("Net.WebClient") != std::string::npos &&
		cmdline.find("wget") != std::string::npos &&
		cmdline.find("WinHttp.WinHttpRequest") != std::string::npos)
	{
		std::stringstream ss;
		ss << "RedMimicry Winnti playbook usage detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults%' AND cmdline LIKE '%http%' AND cmdline LIKE '% 0%';

bool ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults") != std::string::npos &&
		cmdline.find("http") != std::string::npos &&
		cmdline.find(" 0") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected changes to Internet Explorer's ZoneMap configuration";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Sysprep on AppData Folder
// SELECT * FROM win_process_events WHERE path LIKE '%\\sysprep.exe%' AND cmdline LIKE '%\\AppData%';

bool sysprep_on_appData_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sysprep.exe") != std::string::npos &&
		cmdline.find("\\AppData") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected suspicious sysprep process start with AppData folder as target";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// TA0002 - New Virtual Smart Card Created Via TpmVscMgr.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\tpmvscmgr.exe%' OR cmdline LIKE '%TpmVscMgr.exe%') AND cmdline LIKE '%create%';

bool new_virtual_smart_card_created_via_TpmVscMgr_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\tpmvscmgr.exe") != std::string::npos ||
		 cmdline.find("TpmVscMgr.exe") != std::string::npos) &&
		cmdline.find("create") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected execution of 'Tpmvscmgr.exe' to create a new virtual smart card.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool hacktool_silverc2_implant_activity_pattern(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Process activity patterns as seen being used by Sliver C2 framework implants detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_zipexec_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("/generic:Microsoft_Windows_Shell_ZipFolder:filename=") != std::string::npos && cmdline.find(".zip") != std::string::npos && cmdline.find("/pass:") != std::string::npos && cmdline.find("/user:") != std::string::npos && cmdline.find("/delete") != std::string::npos && cmdline.find("Microsoft_Windows_Shell_ZipFolder:filename=") != std::string::npos && cmdline.find(".zip") != std::string::npos)
	{
		std::stringstream ss;
		ss << "ZipExec detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.003 - Remote Access Tool - ScreenConnect Remote Command Execution
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\ScreenConnect.ClientService.exe%' AND path LIKE '%\cmd.exe%' AND cmdline LIKE '%\TEMP\ScreenConnect\%';

bool remote_access_tool_screenconnect_remote_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("\\ScreenConnect.ClientService.exe") != std::string::npos && path.find("\\cmd.exe") != std::string::npos && cmdline.find("\\TEMP\\ScreenConnect\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detects the execution of a system command via the ScreenConnect RMM service.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Outlook EnableUnsafeClientMailRules Setting Enabled
// select * from win_process_events where cmdline like '%\\Outlook\\Security\\EnableUnsafeClientMailRules%';

bool outlook_enableunsafeclientmailrules_setting_enabled(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\Outlook\\Security\\EnableUnsafeClientMailRules") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Outlook EnableUnsafeClientMailRules Setting Enabled";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Suspicious Remote Child Process From Outlook
// select * from win_process_events where cmdline like '%\\outlook.exe%';

bool suspicious_remote_child_process_from_outlook(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("\\outlook.exe") != std::string::npos && parent_path.find("\\\\\\\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious Remote Child Process From Outlook";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Renamed CURL.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%curl%') AND NOT (path LIKE '%\curl%');

bool renamed_curlexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("curl") != std::string::npos) && !(path.find("\\curl") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of a renamed 'CURL.exe' binary based on the PE metadata fields";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059 - Renamed FTP.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%ftp%') AND NOT (path LIKE '%\ftp.exe%');

bool renamed_ftpexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("ftp") != std::string::npos) && !(path.find("\\ftp.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of a renamed 'ftp.exe' binary based on the PE metadata fields";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1036.003 - Renamed Jusched.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Java Update Scheduler%' OR cmdline LIKE '%Java(TM) Update Scheduler%') AND NOT (path LIKE '%\jusched.exe%');

bool renamed_juschedexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("Java Update Scheduler") != std::string::npos || cmdline.find("Java(TM) Update Scheduler") != std::string::npos) && !(path.find("\\jusched.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of a renamed 'jusched.exe' as seen used by the cobalt group";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1218 - Visual Studio NodejsTools PressAnyKey Renamed Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Microsoft.NodejsTools.PressAnyKey%') AND NOT (path LIKE '%\Microsoft.NodejsTools.PressAnyKey.exe%');

bool visual_studio_nodejstools_pressanykey_renamed_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("Microsoft.NodejsTools.PressAnyKey") != std::string::npos) && !(path.find("\\Microsoft.NodejsTools.PressAnyKey.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected renamed execution of 'Microsoft.NodejsTools.PressAnyKey.exe'.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1218 - Potential Renamed Rundll32 Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%DllRegisterServer%') AND NOT (path LIKE '%\rundll32.exe%');

bool potential_renamed_rundll32_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("DllRegisterServer") != std::string::npos) && !(path.find("\\rundll32.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected that 'DllRegisterServer' is called in the commandline and the image is not rundll32. This could mean that the 'rundll32' utility has been renamed in order to avoid detection";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059 - Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
// SELECT * FROM win_process_events WHERE (path LIKE '%\\VMwareToolBoxCmd.exe%' OR cmdline LIKE '%toolbox-cmd.exe%') AND cmdline LIKE '%script%' AND cmdline LIKE '%set%';

bool potential_persistence_via_VMwareToolBoxCmd_EXE_VM_state_change_script(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\VMwareToolBoxCmd.exe") != std::string::npos || cmdline.find("toolbox-cmd.exe") != std::string::npos) && cmdline.find("script") != std::string::npos && cmdline.find("set") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious Remote Child Process From Outlook";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - VMToolsd Suspicious Child Process
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\vmtoolsd.exe%' AND (path LIKE '%Cmd.Exe%' OR path LIKE '%cscript.exe%' OR path LIKE '%MSHTA.EXE%' OR path LIKE '%PowerShell.EXE%' OR path LIKE '%pwsh.dll%' OR path LIKE '%REGSVR32.EXE%' OR path LIKE '%RUNDLL32.EXE%' OR path LIKE '%wscript.exe%') AND (path LIKE '%\\VMware\\VMware Tools\\poweron-vm-default.bat%' OR path LIKE '%\\VMware\\VMware Tools\\poweroff-vm-default.bat%' OR path LIKE '%\\VMware\\VMware Tools\\resume-vm-default.bat%' OR path LIKE '%\\VMware\\VMware Tools\\suspend-vm-default.bat%'));

bool vmtoolsd_suspicious_child_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (parent_path.find("\\vmtoolsd.exe") != std::string::npos &&
		(path.find("Cmd.Exe") != std::string::npos ||
		 path.find("cscript.exe") != std::string::npos ||
		 path.find("MSHTA.EXE") != std::string::npos ||
		 path.find("PowerShell.EXE") != std::string::npos ||
		 path.find("pwsh.dll") != std::string::npos ||
		 path.find("REGSVR32.EXE") != std::string::npos ||
		 path.find("RUNDLL32.EXE") != std::string::npos ||
		 path.find("wscript.exe") != std::string::npos) &&
		(path.find("\\VMware\\VMware Tools\\poweron-vm-default.bat") != std::string::npos ||
		 path.find("\\VMware\\VMware Tools\\poweroff-vm-default.bat") != std::string::npos ||
		 path.find("\\VMware\\VMware Tools\\resume-vm-default.bat") != std::string::npos ||
		 path.find("\\VMware\\VMware Tools\\suspend-vm-default.bat") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious child process creations of VMware Tools process which may indicate persistence setup. **False Positive: Legitimate use by VM Administrator";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// TA0002 - Wab Execution From Non Default Location
// SELECT * FROM win_process_events WHERE (path LIKE '%\\wab.exe%' OR path LIKE '%\\wabmig.exe%') AND (cmdline LIKE '%C:\\Windows\\WinSxS\\%' OR cmdline LIKE '%C:\\Program Files\\Windows Mail\\%' OR cmdline LIKE '%C:\\Program Files (x86)\\Windows Mail\\%');

bool wab_execution_from_non_default_location(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\wab.exe") != std::string::npos || path.find("\\wabmig.exe") != std::string::npos) && !(cmdline.find("C:\\Windows\\WinSxS\\") != std::string::npos || cmdline.find("C:\\Program Files\\Windows Mail\\") != std::string::npos || cmdline.find("C:\\Program Files (x86)\\Windows Mail\\") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected execution of wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) from non default locations as seen with bumblebee activity";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
// SSELECT * FROM win_process_events WHERE (parent_path LIKE '%\\explorer.exe%' OR path LIKE '%\\cmd.exe%' OR path LIKE '%\\cscript.exe%' OR path LIKE '%\\mshta.exe%' OR path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR path LIKE '%\\wscript.exe%') AND path LIKE '%\\DavWWWRoot\\%';

bool potentially_suspicious_webDAV_LNK_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if ((parent_path.find("\\explorer.exe") != std::string::npos ||
		 path.find("\\cmd.exe") != std::string::npos ||
		 path.find("\\cscript.exe") != std::string::npos ||
		 path.find("\\mshta.exe") != std::string::npos ||
		 path.find("\\powershell.exe") != std::string::npos ||
		 path.find("\\pwsh.exe") != std::string::npos ||
		 path.find("\\wscript.exe") != std::string::npos) &&
		cmdline.find("\\DavWWWRoot\\") != std::string::npos)

	{
		std::stringstream ss;
		ss << "Detected possible execution via LNK file accessed on a WebDAV server.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Suspicious Execution Of PDQDeployRunner
// select * from win_process_events where
// cmdline like '%iex%' or
// cmdline like '%Invoke-%' or
// cmdline like '%DownloadString%' or
// cmdline like '%http%' or
// cmdline like '% -enc%' or
// cmdline like '% -encodedcommand%' or
// cmdline like '%FromBase64String%' or
// cmdline like '% -decode%' or
// cmdline like '% -w hidden%';

// bool suspicious_execution_of_pdqdeployrunner(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;

// 	if (cmdline.find("iex") != std::string::npos ||
// 		cmdline.find("Invoke-") != std::string::npos ||
// 		cmdline.find("DownloadString") != std::string::npos ||
// 		cmdline.find("http") != std::string::npos ||
// 		cmdline.find(" -enc") != std::string::npos ||
// 		cmdline.find(" -encodedcommand") != std::string::npos ||
// 		cmdline.find("FromBase64String") != std::string::npos ||
// 		cmdline.find(" -decode") != std::string::npos ||
// 		cmdline.find(" -w hidden") != std::string::npos)
// 	{
// 		std::stringstream ss;
// 		ss << "Suspicious Execution Of PDQDeployRunner";
// 		rule_event.metadata = ss.str();
// 		return true;
// 	}
// 	return false;
// }

// T1059 - Perl Inline Command Execution
// select * from win_process_events where cmdline like '% -e%';

bool perl_inline_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\perl.exe") != std::string::npos && cmdline.find(" -e") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Perl Inline Command Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Php Inline Command Execution
// select * from win_process_events where cmdline like '% -r%';

bool php_inline_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\php.exe") != std::string::npos && cmdline.find(" -r") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Php Inline Command Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - AADInternals PowerShell Cmdlets Execution
// select * from win_process_events where
// cmdline like '%Add-AADInt%' or
// cmdline like '%ConvertTo-AADInt%' or
// cmdline like '%Disable-AADInt%' or
// cmdline like '%Enable-AADInt%' or
// cmdline like '%Export-AADInt%' or
// cmdline like '%Get-AADInt%' or
// cmdline like '%Grant-AADInt%' or
// cmdline like '%Install-AADInt%' or
// cmdline like '%Invoke-AADInt%' or
// cmdline like '%Join-AADInt%' or
// cmdline like '%New-AADInt%' or
// cmdline like '%Open-AADInt%' or
// cmdline like '%Read-AADInt%' or
// cmdline like '%Register-AADInt%' or
// cmdline like '%Set-AADInt%' or
// cmdline like '%Remove-AADInt%' or
// cmdline like '%Restore-AADInt%' or
// cmdline like '%Search-AADInt%' or
// cmdline like '%Send-AADInt%' or
// cmdline like '%Start-AADInt%' or
// cmdline like '%Update-AADInt%';

bool aadinternals_powershell_cmdlets_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
			path.find("\\pwsh.exe") != std::string::npos &&
			cmdline.find("Add-AADInt") != std::string::npos ||
		cmdline.find("ConvertTo-AADInt") != std::string::npos ||
		cmdline.find("Disable-AADInt") != std::string::npos ||
		cmdline.find("Enable-AADInt") != std::string::npos ||
		cmdline.find("Export-AADInt") != std::string::npos ||
		cmdline.find("Get-AADInt") != std::string::npos ||
		cmdline.find("Grant-AADInt") != std::string::npos ||
		cmdline.find("Install-AADInt") != std::string::npos ||
		cmdline.find("Invoke-AADInt") != std::string::npos ||
		cmdline.find("Join-AADInt") != std::string::npos ||
		cmdline.find("New-AADInt") != std::string::npos ||
		cmdline.find("Open-AADInt") != std::string::npos ||
		cmdline.find("Read-AADInt") != std::string::npos ||
		cmdline.find("Register-AADInt") != std::string::npos ||
		cmdline.find("Set-AADInt") != std::string::npos ||
		cmdline.find("Remove-AADInt") != std::string::npos ||
		cmdline.find("Restore-AADInt") != std::string::npos ||
		cmdline.find("Search-AADInt") != std::string::npos ||
		cmdline.find("Send-AADInt") != std::string::npos ||
		cmdline.find("Start-AADInt") != std::string::npos ||
		cmdline.find("Update-AADInt") != std::string::npos)
	{
		std::stringstream ss;
		ss << "AADInternals PowerShell Cmdlets Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Add Windows Capability Via PowerShell Cmdlet
// select * from win_process_events where
// cmdline like '%Add-WindowsCapability%' and
// cmdline like '%OpenSSH.%';

bool add_windows_capability_via_powershell_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find("Add-WindowsCapability") != std::string::npos &&
		cmdline.find("OpenSSH.") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Add Windows Capability Via PowerShell Cmdlet";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Suspicious Encoded PowerShell Command Line
// select * from win_process_events where
// cmdline like '% -e%' and
//(cmdline like '%.exe -ENCOD%' or
// cmdline like '% BA^J e-%') and
//(cmdline like '% JAB%' or
// cmdline like '% SUVYI%' or
// cmdline like '% SQBFAFgA%' or
// cmdline like '% aQBLAHgA%' or
// cmdline like '% aWV4I%' or
// cmdline like '% IAA%' or
// cmdline like '% IAB%' or
// cmdline like '%UwB%' or
// cmdline like '%cwB%');

bool suspicious_encoded_powershell_command_line(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find(" -e") != std::string::npos &&
		(cmdline.find(".exe -ENCOD") != std::string::npos ||
		 cmdline.find(" BA^J e-") != std::string::npos) &&
		(cmdline.find(" JAB") != std::string::npos ||
		 cmdline.find(" SUVYI") != std::string::npos ||
		 cmdline.find(" SQBFAFgA") != std::string::npos ||
		 cmdline.find(" aQBLAHgA") != std::string::npos ||
		 cmdline.find(" aWV4I") != std::string::npos ||
		 cmdline.find(" IAA") != std::string::npos ||
		 cmdline.find(" IAB") != std::string::npos ||
		 cmdline.find("UwB") != std::string::npos ||
		 cmdline.find("cwB") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious Encoded PowerShell Command Line";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - PowerShell Base64 Encoded IEX Cmdlet
// select * from win_process_events where
// cmdline like '%IEX ([%' or
// cmdline like '%iex ([%' or
// cmdline like '%iex (New%' or
// cmdline like '%IEX (New%' or
// cmdline like '%IEX([%' or
// cmdline like '%iex([%' or
// cmdline like '%iex(New%' or
// cmdline like '%IEX(New%' or
// cmdline like '%IEX(('%' or
// cmdline like '%iex(('%';

bool powershell_base64_encoded_iex_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("IEX ([") != std::string::npos ||
		cmdline.find("iex ([") != std::string::npos ||
		cmdline.find("iex (New") != std::string::npos ||
		cmdline.find("IEX (New") != std::string::npos ||
		cmdline.find("IEX([") != std::string::npos ||
		cmdline.find("iex([") != std::string::npos ||
		cmdline.find("iex(New") != std::string::npos ||
		cmdline.find("IEX(New") != std::string::npos ||
		cmdline.find("IEX(('") != std::string::npos ||
		cmdline.find("iex(('") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PowerShell Base64 Encoded IEX Cmdlet";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - PowerShell Base64 Encoded Invoke Keyword
// select * from win_process_events where
// cmdline like '% -e%' and
//(cmdline like '%SQBuAHYAbwBrAGUALQ%' or
// cmdline like '%kAbgB2AG8AawBlAC0A%' or
// cmdline like '%JAG4AdgBvAGsAZQAtA%' or
// cmdline like '%SW52b2tlL%' or
// cmdline like '%ludm9rZS%' or
// cmdline like '%JbnZva2Ut%');

bool powershell_base64_encoded_invoke_keyword(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find(" -e") != std::string::npos &&
		(cmdline.find("SQBuAHYAbwBrAGUALQ") != std::string::npos ||
		 cmdline.find("kAbgB2AG8AawBlAC0A") != std::string::npos ||
		 cmdline.find("JAG4AdgBvAGsAZQAtA") != std::string::npos ||
		 cmdline.find("SW52b2tlL") != std::string::npos ||
		 cmdline.find("ludm9rZS") != std::string::npos ||
		 cmdline.find("JbnZva2Ut") != std::string::npos))
	{
		std::stringstream ss;
		ss << "PowerShell Base64 Encoded Invoke Keyword";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Potential PowerShell Command Line Obfuscation
// select * from win_process_events where
// cmdline like '%new EventSource("Microsoft.Windows.Sense.Client.Management"% or
// cmdline like '%public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);%';

bool potential_powershell_command_line_obfuscation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("new EventSource(\"Microsoft.Windows.Sense.Client.Management\"") != std::string::npos ||
		cmdline.find("public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Potential PowerShell Command Line Obfuscation";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - PowerShell Execution With Potential Decryption Capabilities
// select * from win_process_events where
// cmdline like '%-Skip%' and
// cmdline like '% ^| %' and
// cmdline like '%-Recurse%' and
// cmdline like '%\\*.lnk%' and
//(cmdline like '%dir %' or
// cmdline like '%gci %' or
// cmdline like '%ls %' or
// cmdline like '%Get-ChildItem %') and
//(cmdline like '%gc %' or
// cmdline like '%cat %' or
// cmdline like '%type %' or
// cmdline like '%Get-Content%');

bool powershell_execution_with_potential_decryption_capabilities(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find("-Skip") != std::string::npos &&
		cmdline.find(" ^| ") != std::string::npos &&
		cmdline.find("-Recurse") != std::string::npos &&
		cmdline.find("\\*.lnk") != std::string::npos &&
		(cmdline.find("dir ") != std::string::npos ||
		 cmdline.find("gci ") != std::string::npos ||
		 cmdline.find("ls ") != std::string::npos ||
		 cmdline.find("Get-ChidItem ") != std::string::npos) &&
		(cmdline.find("gc ") != std::string::npos ||
		 cmdline.find("cat ") != std::string::npos ||
		 cmdline.find("type ") != std::string::npos ||
		 cmdline.find("Get-Content") != std::string::npos))
	{
		std::stringstream ss;
		ss << "PowerShell Execution With Potential Decryption Capabilities";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Renamed PsExec Service Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%psexesvc%') AND NOT (path LIKE '%C:\Windows\PSEXESVC.exe%');

bool renamed_psexec_service_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("psexesvc") != std::string::npos) && !(path.find("C:\\Windows\\PSEXESVC.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected suspicious launch of a renamed version of the PSEXESVC service";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059 - Ruby Inline Command Execution
// SELECT * FROM win_process_events WHERE path LIKE '%\ruby.exe%' AND cmdline LIKE '% -e%';

bool ruby_inline_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\ruby.exe") != std::string::npos && cmdline.find(" -e") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected execution of ruby using the '-e' flag. This is could be used as a way to launch a reverse shell or execute live ruby code.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059 - PowerShell Download and Execution Cradles
// select * from win_process_events where
//((cmdline like '%.DownloadString(%' or
// cmdline like '%.DownloadFile(%' or
// cmdline like '%Invoke-WebRequest%' or
// cmdline like '%iwr%') and
// cmdline like '%;iex $%' or
// cmdline like '%| IEX%' or
// cmdline like '%|IEX%' or
// cmdline like '%I`E`X`%' or
// cmdline like '%I`EX%' or
// cmdline like '%IE`X%' or
// cmdline like '%iex %' or
// cmdline like '%IEX (%' or
// cmdline like '%IEX(%' or
// cmdline like '%Invoke-Expression%'));

// bool powershell_download_and_execution_cradles(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;

// 	if ((cmdline.find(".DownloadString(") != std::string::npos ||
// 		 cmdline.find(".DownloadFile(") != std::string::npos ||
// 		 cmdline.find("Invoke-WebRequest ") != std::string::npos ||
// 		 cmdline.find("iwr ") != std::string::npos) &&
// 		(cmdline.find(";iex $") != std::string::npos ||
// 		 cmdline.find("| IEX") != std::string::npos ||
// 		 cmdline.find("|IEX") != std::string::npos ||
// 		 cmdline.find("I`E`X`") != std::string::npos ||
// 		 cmdline.find("I`EX") != std::string::npos ||
// 		 cmdline.find("IE`X") != std::string::npos ||
// 		 cmdline.find("iex ") != std::string::npos ||
// 		 cmdline.find("IEX (") != std::string::npos ||
// 		 cmdline.find("IEX(") != std::string::npos ||
// 		 cmdline.find("Invoke-Expression") != std::string::npos))
// 	{
// 		std::stringstream ss;

// 		ss << "PowerShell Download and Execution Cradles";
// 		rule_event.metadata = ss.str();

// 		return true;
// 	}

// 	return false;
// }

// T1059.001 - PowerShell Download Pattern
// select * from win_process_events where
//((cmdline like '%string(%' or
// cmdline like '%.file(%') and
// cmdline like '%new-object%' and
// cmdline like '%net.webclient%).%' and
// cmdline like '%download%');

bool powershell_download_pattern(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("string(") != std::string::npos ||
		 cmdline.find(".file(") != std::string::npos) &&
		cmdline.find("new-object") != std::string::npos &&
		cmdline.find("net.webclient).") != std::string::npos &&
		cmdline.find("download") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PowerShell Download Pattern";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

bool java_running_with_remote_debugging(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("transport=dt_socket,address=") != std::string::npos && (cmdline.find("jre1.") != std::string::npos || cmdline.find("jdk1.") != std::string::npos ) && !(cmdline.find("address=127.0.0.1") != std::string::npos || cmdline.find("address=localhost") != std::string::npos))
	{
		std::stringstream ss;
		ss << "JAVA process running with remote debugging allowing more than just localhost to connect detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Suspicious Execution of Powershell with Base64
// select * from win_process_events where
//((cmdline like '% -e%' or
// cmdline like '% -en%' or
// cmdline like '% -enc%' or
// cmdline like '% -enco%' or
// cmdline like '% -ec%') and
// cmdline like '% -Encoding%' and
//(cmdline like '%C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%' and
// cmdline like '%\\gc_worker.exe%'));

bool suspicious_execution_of_powershell_with_base64(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find(" -e") != std::string::npos ||
		 cmdline.find(" -en") != std::string::npos ||
		 cmdline.find(" -enc") != std::string::npos ||
		 cmdline.find(" -enco") != std::string::npos ||
		 cmdline.find(" -ec") != std::string::npos) &&
		!(cmdline.find(" -Encoding") != std::string::npos ||
		(cmdline.find("C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\") != std::string::npos ||
		 cmdline.find("\\gc_worker.exe") != std::string::npos)))
	{
		std::stringstream ss;

		ss << "Suspicious Execution of Powershell with Base64";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Suspicious PowerShell Encoded Command Patterns
// select * from win_process_events where
//((cmdline like '% -e%' or
// cmdline like '% -en%' or
// cmdline like '% -enc%' or
// cmdline like '% -enco%') and
//(cmdline like '%C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%' or
// cmdline like '%\\gc_worker.exe%') and
//(cmdline like '% JAB%' or
// cmdline like '% SUVYI%' or
// cmdline like '% SQBFAFgA%' or
// cmdline like '% aWV4I%' or
// cmdline like '% IAB%' or
// cmdline like '% PAA%' or
// cmdline like '% aQBlAHgA%'));

bool suspicious_powershell_encoded_command_patterns(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find(" -e ") != std::string::npos ||
		 cmdline.find(" -en ") != std::string::npos ||
		 cmdline.find(" -enc ") != std::string::npos ||
		 cmdline.find(" -enco") != std::string::npos) &&
		(cmdline.find("C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\") != std::string::npos ||
		 cmdline.find("\\gc_worker.exe")) &&
		(cmdline.find(" JAB") != std::string::npos ||
		 cmdline.find(" SUVYI") != std::string::npos ||
		 cmdline.find(" SQBFAFgA") != std::string::npos ||
		 cmdline.find(" aWV4I") != std::string::npos ||
		 cmdline.find(" IAB") != std::string::npos ||
		 cmdline.find(" PAA") != std::string::npos ||
		 cmdline.find(" aQBlAHgA") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious PowerShell Encoded Command Patterns";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Powershell Inline Execution From A File
// select * from win_process_events where
//((cmdline like '%iex%' or
// cmdline like '%Invoke-Expression%' or
// cmdline like '%Invoke-Command%' or
// cmdline like '%icm%') and
//(cmdline like '%cat%' or
// cmdline like '%get-content%' or
// cmdline like '%type%') and
// cmdline like '% -raw%');

bool powershell_inline_execution_from_a_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("iex") != std::string::npos ||
		 cmdline.find("Invoke-Expression") != std::string::npos ||
		 cmdline.find("Invoke-Command") != std::string::npos ||
		 cmdline.find("icm") != std::string::npos) &&
		(cmdline.find("cat") != std::string::npos ||
		 cmdline.find("get-content") != std::string::npos ||
		 cmdline.find("type") != std::string::npos) &&
		cmdline.find(" -raw") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Powershell Inline Execution From A File";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Malicious Base64 Encoded PowerShell Keywords in Command Lines
// select * from win_process_events where
// cmdline like '% hidden%';

bool malicious_base64_encoded_powershell_keywords_in_command_lines(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find(" hidden") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Malicious Base64 Encoded PowerShell Keywords in Command Lines";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Suspicious PowerShell IEX Execution Patterns
// select * from win_process_events where
//(cmdline like '%::FromBase64String%' or cmdline like '%.GetString([System.Convert]::%') and
//(cmdline like '%)|iex;$%' or cmdline like '%);iex($%' or cmdline like '%)|iex $%' or cmdline like '% | IEX | %') and
//(cmdline like '% | iex;%' or cmdline like '% | iex %' or cmdline like '% | iex}%' or cmdline like '% | IEX %' or cmdline like '% | IEX -Error%' or cmdline like '% | IEX (new%' or cmdline like '%);IEX %');

bool suspicious_powershell_iex_execution_patterns(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("::FromBase64String") != std::string::npos ||
		 cmdline.find(".GetString([System.Convert]::") != std::string::npos) &&
		(cmdline.find(")|iex;$") != std::string::npos ||
		 cmdline.find(");iex($") != std::string::npos ||
		 cmdline.find(")|iex $") != std::string::npos ||
		 cmdline.find(" | IEX | ") != std::string::npos) &&
		(cmdline.find(" | iex;") != std::string::npos ||
		 cmdline.find(" | iex ") != std::string::npos ||
		 cmdline.find(" | iex}") != std::string::npos ||
		 cmdline.find(" | IEX ") != std::string::npos ||
		 cmdline.find(" | IEX -Error") != std::string::npos ||
		 cmdline.find(" | IEX (new") != std::string::npos ||
		 cmdline.find(");IEX ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious PowerShell IEX Execution Patterns";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Import PowerShell Modules From Suspicious Directories
// select * from win_process_events where
//(cmdline like '%Import-Module "$Env:Temp\\%' or
// cmdline like '%Import-Module ''$Env:Temp\\%' or
// cmdline like '%Import-Module $Env:Temp\\%' or
// cmdline like '%Import-Module "$Env:Appdata\\%' or
// cmdline like '%Import-Module ''$Env:Appdata\\%' or
// cmdline like '%Import-Module $Env:Appdata\\%' or
// cmdline like '%Import-Module C:\\Users\\Public\\%' or
// cmdline like '%ipmo "$Env:Temp\\%' or
// cmdline like '%ipmo ''$Env:Temp\\%' or
// cmdline like '%ipmo $Env:Temp\\%' or
// cmdline like '%ipmo "$Env:Appdata\\%' or
// cmdline like '%ipmo ''$Env:Appdata\\%' or
// cmdline like '%ipmo $Env:Appdata\\%' or
// cmdline like '%ipmo C:\\Users\\Public\\%');

bool import_powershell_modules_from_suspicious_directories(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Import-Module \"$Env:Temp\\") != std::string::npos ||
		cmdline.find("Import-Module '$Env:Temp\\") != std::string::npos ||
		cmdline.find("Import-Module $Env:Temp\\") != std::string::npos ||
		cmdline.find("Import-Module \"$Env:Appdata\\") != std::string::npos ||
		cmdline.find("Import-Module '$Env:Appdata\\") != std::string::npos ||
		cmdline.find("Import-Module $Env:Appdata\\") != std::string::npos ||
		cmdline.find("Import-Module C:\\Users\\Public\\") != std::string::npos ||
		cmdline.find("ipmo \"$Env:Temp\\") != std::string::npos ||
		cmdline.find("ipmo '$Env:Temp\\") != std::string::npos ||
		cmdline.find("ipmo $Env:Temp\\") != std::string::npos ||
		cmdline.find("ipmo \"$Env:Appdata\\") != std::string::npos ||
		cmdline.find("ipmo '$Env:Appdata\\") != std::string::npos ||
		cmdline.find("ipmo $Env:Appdata\\") != std::string::npos ||
		cmdline.find("ipmo C:\\Users\\Public\\") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Import PowerShell Modules From Suspicious Directories";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Non Interactive PowerShell Process Spawned
// SELECT * FROM win_process_events WHERE (path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%') AND (parent_path LIKE '%:\\Windows\\explorer.exe%' OR parent_path LIKE '%:\\Windows\\System32\\CompatTelRunner.exe%' OR parent_path LIKE '%:\\Windows\\SysWOW64\\explorer.exe%' OR parent_path LIKE '%:\\$WINDOWS.~BT\\Sources\\SetupHost.exe%' OR parent_path LIKE '%\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe%' OR parent_path LIKE '%:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_%' OR parent_path LIKE '%\\WindowsTerminal.exe%') AND cmdline LIKE '% --ms-enable-electron-run-as-node %';

bool non_interactive_powershell_process_spawned(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		!(parent_path.find(":\\Windows\\explorer.exe") != std::string::npos &&
		parent_path.find(":\\Windows\\System32\\CompatTelRunner.exe") != std::string::npos &&
		parent_path.find(":\\Windows\\SysWOW64\\explorer.exe") != std::string::npos &&
		parent_path.find(":\\$WINDOWS.~BT\\Sources\\SetupHost.exe") != std::string::npos &&
		parent_path.find("\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe") != std::string::npos &&
		parent_path.find(":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_") != std::string::npos &&
		parent_path.find("\\WindowsTerminal.exe") != std::string::npos &&
		cmdline.find(" --ms-enable-electron-run-as-node ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Non Interactive PowerShell Process Spawned";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Potential PowerShell Obfuscation Via WCHAR

bool potential_powershell_obfuscation_via_wchar(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("(WCHAR)0x") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Potential PowerShell Obfuscation Via WCHAR";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Execution of Powershell Script in Public Folder
// SELECT * FROM your_table WHERE
// cmdline LIKE '%-f C:\\Users\\Public%' OR
// cmdline LIKE '%-f "C:\\Users\\Public%' OR
// cmdline LIKE '%-f %Public%' OR
// cmdline LIKE '%-fi C:\\Users\\Public%' OR
// cmdline LIKE '%-fi "C:\\Users\\Public%' OR
// cmdline LIKE '%-f %Public%' OR
// cmdline LIKE '%-fil C:\\Users\\Public%' OR
// cmdline LIKE '%-fil "C:\\Users\\Public%' OR
// cmdline LIKE '%-fil %Public%' OR
// cmdline LIKE '%-file C:\\Users\\Public%' OR
// cmdline LIKE '%-file "C:\\Users\\Public%' OR
// cmdline LIKE '%-file %Public%';

bool execution_of_powershell_script_in_public_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
			path.find("\\pwsh.exe") != std::string::npos &&
			cmdline.find("-f C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-f \"C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-f %Public%") != std::string::npos ||
		cmdline.find("-fi C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-fi \"C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-f %Public%") != std::string::npos ||
		cmdline.find("-fil C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-fil \"C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-fil %Public%") != std::string::npos ||
		cmdline.find("-file C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-file \"C:\\Users\\Public") != std::string::npos ||
		cmdline.find("-file %Public%") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Execution of Powershell Script in Public Folder";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1059.001 - Potential Powershell ReverseShell Connection
// SELECT * FROM your_table WHERE
// cmdline LIKE '% Net.Sockets.TCPClient%' OR
// cmdline LIKE '%.GetStream(%' OR
// cmdline LIKE '%.Write(%';

bool potential_powershell_reverseshell_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
			path.find("\\pwsh.exe") != std::string::npos &&
			cmdline.find(" Net.Sockets.TCPClient") != std::string::npos ||
		cmdline.find(".GetStream(") != std::string::npos ||
		cmdline.find(".Write(") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Potential Powershell ReverseShell Connection";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

bool computer_password_change_via_ksetupexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\ksetup.exe") != std::string::npos || cmdline.find("/setcomputerpassword") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Password change for the computer's domain account or host principal via 'ksetup.exe' detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool loggedon_user_password_change_via_ksetupexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\ksetup.exe") != std::string::npos || cmdline.find("/ChangePassword") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Password change for the logged-on user's via 'ksetup.exe' detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool windbg_cdb_lolbin_usage(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-c") != std::string::npos || cmdline.find("-cf") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Usage of 'cdb.exe' to launch 64-bit shellcode or arbitrary processes or commands from a debugger script file detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool use_of_fsharp_interpreters(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("fsianycpu.exe") != std::string::npos || cmdline.find("fsi.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Use of FSharp interpreters detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool lolbin_execution_of_the_ftpexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-s:") != std::string::npos || cmdline.find("/s:") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Execution of ftp.exe script execution with the ' - s ' or ' / s ' flag and any child processes ran by ftp.exe detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - MpiExec Lolbin
// select * from win_process_events where
//     cmdline like '%/n 1%' or
//     cmdline like '%-n 1%';

bool mpiexec_lolbin(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("/n 1") != std::string::npos || cmdline.find("-n 1") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detects a certain command line flag combination used by mpiexec.exe LOLBIN from HPC pack that can be used to execute any other binary";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - T1218 - Execute Files with Msdeploy.exe
// select * from win_process_events where
//     cmdline like '%verb:sync%' and
//     cmdline like '%-source:RunCommand%' and
//     cmdline like '%-dest:runCommand%';

bool execute_files_with_msdeployexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("verb:sync") != std::string::npos && cmdline.find("-source:RunCommand") != std::string::npos && cmdline.find("-dest:runCommand") != std::string::npos)
	{
		std::stringstream ss;
		ss << "File execution using the msdeploy.exe lolbin detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Use of OpenConsole
// select * from win_process_events where
//     cmdline like '%OpenConsole%';

bool use_of_openconsole(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (cmdline.find("OpenConsole") != std::string::npos && !(path.find("C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal") != std::string::npos))
	{
		std::stringstream ss;
		ss << "File execution using the msdeploy.exe lolbin detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Use of Pcalua For Execution
// select * from win_process_events where
//     cmdline like '%-a%';

bool use_of_pcalua_for_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-a") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Execition of commands and binaries from the context of The program compatibility assistant detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Execute Code with Pester.bat
// select * from win_process_events where
//     (cmdline like '%Pester%' and
//      cmdline like '%Get-Help%' and
//      cmdline like '%pester%' and
//      cmdline like '%;%') or
//     cmdline like '%help%' or
//     cmdline like '%?%';

bool execute_code_with_pesterbat(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("Pester") != std::string::npos && cmdline.find("Get-Help") != std::string::npos && cmdline.find("pester") != std::string::npos && cmdline.find(";") != std::string::npos) && (cmdline.find("help") != std::string::npos || cmdline.find("?") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Code execution via Pester.bat detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - Execute Code with Pester.bat as Parent
// select * from win_process_events where
//     cmdline like '%\\WindowsPowerShell\\Modules\\Pester%' or
//     cmdline like '%{ Invoke-Pester -EnableExit ;%' or
//     cmdline like '%{ Get-Help "%';

bool execute_code_with_pesterbat_as_parent(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("\\WindowsPowerShell\\Modules\\Pester") != std::string::npos || cmdline.find("{ Invoke-Pester -EnableExit ;") != std::string::npos || cmdline.find("{ Get-Help \"") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Code execution via Pester.bat detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// Suspicious LOLBIN AccCheckConsole

bool suspicious_lolbin_acccheckconsole(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-window") != std::string::npos && cmdline.find(".dll") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious LOLBIN AccCheckConsole execution detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.005 - WScript or CScript Dropper
// SELECT * FROM win_process_events WHERE
//     (path LIKE '%\\wscript.exe%' OR path LIKE '%\\cscript.exe%') AND
//     (cmdline LIKE '%C:\\Users\\%' OR
//      cmdline LIKE '%C:\\ProgramData\\%' OR
//      cmdline LIKE '%.jse%' OR
//      cmdline LIKE '%.vbe%' OR
//      cmdline LIKE '%.js%' OR
//      cmdline LIKE '%.vba%' OR
//      cmdline LIKE '%.vbs%') AND
//     parent_path LIKE '%\\winzip%';
bool wscript_or_cscript_dropper(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	if ((path.find("\\wscript.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos) && (cmdline.find("C:\\Users\\") != std::string::npos || cmdline.find("C:\\ProgramData\\") != std::string::npos || cmdline.find(".jse") != std::string::npos || cmdline.find(".vbe") != std::string::npos || cmdline.find(".js") != std::string::npos || cmdline.find(".vba") != std::string::npos || cmdline.find(".vbs") != std::string::npos) && parent_path.find("\\winzip") != std::string::npos)
	{
		std::stringstream ss;
		ss << "wscript/cscript executions of scripts located in user directories detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.003 - MMC20 Lateral Movement
// SELECT * FROM win_process_events WHERE
//     parent_path LIKE '%\\svchost.exe%' AND
//     cmdline LIKE '%-Embedding%' AND
//     path LIKE '%\\mmc.exe%';
bool mmc20_lateral_movement(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;
	if (parent_path.find("\\svchost.exe") != std::string::npos && cmdline.find("-Embedding") != std::string::npos && path.find("\\mmc.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "MMC20.Application Lateral Movement detectd !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - Potential Suspicious Mofcomp Execution
// SELECT * FROM win_process_events WHERE
//     (
//         parent_path LIKE '%\\cmd.exe%' OR
//         parent_path LIKE '%\\powershell.exe%' OR
//         parent_path LIKE '%\\pwsh.exe%' OR
//         parent_path LIKE '%\\wsl.exe%' OR
//         parent_path LIKE '%\\wscript.exe%' OR
//         parent_path LIKE '%\\cscript.exe%' OR
//         parent_path LIKE '%C:\\Windows\\System32\\wbem\\WmiPrvSE.exe%'
//     ) AND
//     (
//         cmdline LIKE '%\\AppData\\Local\\Temp%' OR
//         cmdline LIKE '%\\Users\\Public\\%' OR
//         cmdline LIKE '%\\WINDOWS\\Temp\\%' OR
//         cmdline LIKE '%\\%temp%\\%' OR
//         cmdline LIKE '%\\%tmp%\\%' OR
//         cmdline LIKE '%\\%appdata%\\%' OR
//         cmdline LIKE '%C:\\Windows\\TEMP\\%' OR
//         cmdline LIKE '%.mof%'
//     ) AND
//     path LIKE '%\\mofcomp.exe%';
// bool potential_suspicious_mofcomp_execution(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;
// 	std::string parent_path = process_event.entry.parent_path;
// 	std::string path = process_event.entry.path;
// 	if ((parent_path.find("\\cmd.exe") != std::string::npos || parent_path.find("\\powershell.exe") != std::string::npos || parent_path.find("\\pwsh.exe") != std::string::npos || parent_path.find("\\wsl.exe") != std::string::npos || parent_path.find("\\wscript.exe") != std::string::npos || parent_path.find("\\cscript.exe") != std::string::npos || parent_path.find("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe") != std::string::npos) && (cmdline.find("\\AppData\\Local\\Temp") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\WINDOWS\\Temp\\") != std::string::npos || cmdline.find("%temp%") != std::string::npos || cmdline.find("%tmp%") != std::string::npos || cmdline.find("%appdata%") != std::string::npos || cmdline.find("C:\\Windows\\TEMP\\") != std::string::npos || cmdline.find(".mof") != std::string::npos) && path.find("\\mofcomp.exe") != std::string::npos)
// 	{
// 		std::stringstream ss;
// 		ss << "MMC20.Application Lateral Movement detectd !";
// 		rule_event.metadata = ss.str();
// 		return true;
// 	}
// 	return false;
// }

bool use_of_forfiles_for_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\forfiles.exe") != std::string::npos) && (cmdline.find("/p") != std::string::npos || cmdline.find("-p") != std::string::npos || cmdline.find("-c") != std::string::npos || cmdline.find("/c") != std::string::npos || cmdline.find("/m") != std::string::npos || cmdline.find("-m") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Use of Forfiles for execution detected ";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool dotnetexe_exec_dll_and_execute_unsigned_code_lolbin(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\dotnet.exe") != std::string::npos) && cmdline.find(".dll") != std::string::npos || cmdline.find(".csproj") != std::string::npos || cmdline.find("\\dotnet.exe") != std::string::npos || cmdline.find(".NET Host") != std::string::npos)
	{
		std::stringstream ss;
		ss << "dotnet.exe will execute any DLL and execute unsigned code";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_cmdl32_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("/vpn") != std::string::npos && cmdline.find("/lan") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious execution of cmdl32 detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool rebuilt_performance_counter_values_via_lodctrexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\lodctr.exe") != std::string::npos) && (cmdline.find("-r") != std::string::npos || cmdline.find("/r") != std::string::npos))
	{
		std::stringstream ss;
		ss << "The execution of 'lodctr.exe' to rebuild the performance counter registry values detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// TA0002 - Suspicious Execution Location Of Wermgr.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\wermgr.exe%' AND !(path LIKE '%C:\\Windows\\System32\\%' OR path LIKE '%C:\\Windows\\SysWOW64\\%' OR path LIKE '%C:\\Windows\\WinSxS\\%');

bool suspicious_execution_location_of_wermgr_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("\\wermgr.exe") != std::string::npos && !(path.find("C:\\Windows\\System32\\") != std::string::npos || path.find("C:\\Windows\\SysWOW64\\") != std::string::npos || path.find("C:\\Windows\\WinSxS\\") != std::string::npos))

	{
		std::stringstream ss;

		ss << "Potential Powershell ReverseShell Connection";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.004 - Suspicious File Download From IP Via Wget.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\wget.exe%' AND (cmdline LIKE '%.ps1%' OR cmdline LIKE '%.ps1\'%' OR cmdline LIKE '%.ps1"%' OR cmdline LIKE '%.dat%' OR cmdline LIKE '%.dat\'%' OR cmdline LIKE '%.dat"%' OR cmdline LIKE '%.msi%' OR cmdline LIKE '%.msi\'%' OR cmdline LIKE '%.msi"%' OR cmdline LIKE '%.bat%' OR cmdline LIKE '%.bat\'%' OR cmdline LIKE '%.bat"%' OR cmdline LIKE '%.exe%' OR cmdline LIKE '%.exe\'%' OR cmdline LIKE '%.exe"%' OR cmdline LIKE '%.vbs%' OR cmdline LIKE '%.vbs\'%' OR cmdline LIKE '%.vbs"%' OR cmdline LIKE '%.vbe%' OR cmdline LIKE '%.vbe\'%' OR cmdline LIKE '%.vbe"%' OR cmdline LIKE '%.hta%' OR cmdline LIKE '%.hta\'%' OR cmdline LIKE '%.hta"%' OR cmdline LIKE '%.dll%' OR cmdline LIKE '%.dll\'%' OR cmdline LIKE '%.dll"%' OR cmdline LIKE '%.psm1%' OR cmdline LIKE '%.psm1\'%' OR cmdline LIKE '%.psm1"%');

bool suspicious_file_download_from_IP_via_wget_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\wget.exe") != std::string::npos && (cmdline.find(".ps1") != std::string::npos || cmdline.find(".ps1'") != std::string::npos || cmdline.find(".ps1\"") != std::string::npos || cmdline.find(".dat") != std::string::npos || cmdline.find(".dat'") != std::string::npos || cmdline.find(".dat\"") != std::string::npos || cmdline.find(".msi") != std::string::npos || cmdline.find(".msi'") != std::string::npos || cmdline.find(".msi\"") != std::string::npos || cmdline.find(".bat") != std::string::npos || cmdline.find(".bat'") != std::string::npos || cmdline.find(".bat\"") != std::string::npos || cmdline.find(".exe") != std::string::npos || cmdline.find(".exe'") != std::string::npos || cmdline.find(".exe\"") != std::string::npos || cmdline.find(".vbs") != std::string::npos || cmdline.find(".vbs'") != std::string::npos || cmdline.find(".vbs\"") != std::string::npos || cmdline.find(".vbe") != std::string::npos || cmdline.find(".vbe'") != std::string::npos || cmdline.find(".vbe\"") != std::string::npos || cmdline.find(".hta") != std::string::npos || cmdline.find(".hta'") != std::string::npos || cmdline.find(".hta\"") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".dll'") != std::string::npos || cmdline.find(".dll\"") != std::string::npos || cmdline.find(".psm1") != std::string::npos || cmdline.find(".psm1'") != std::string::npos || cmdline.find(".psm1\"") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected potentially suspicious file downloads directly from IP addresses using Wget.exe.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.004 - Suspicious File Download From IP Via Wget.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\\wget.exe%' AND (cmdline LIKE '%.githubusercontent.com%' OR cmdline LIKE '%anonfiles.com%' OR cmdline LIKE '%cdn.discordapp.com%' OR cmdline LIKE '%cdn.discordapp.com/attachments/%' OR cmdline LIKE '%ddns.net%' OR cmdline LIKE '%dl.dropboxusercontent.com%' OR cmdline LIKE '%ghostbin.co%' OR cmdline LIKE '%gofile.io%' OR cmdline LIKE '%hastebin.com%' OR cmdline LIKE '%mediafire.com%' OR cmdline LIKE '%mega.nz%' OR cmdline LIKE '%paste.ee%' OR cmdline LIKE '%pastebin.com%' OR cmdline LIKE '%pastebin.pl%' OR cmdline LIKE '%pastetext.net%' OR cmdline LIKE '%privatlab.com%' OR cmdline LIKE '%privatlab.net%' OR cmdline LIKE '%send.exploit.in%' OR cmdline LIKE '%sendspace.com%' OR cmdline LIKE '%storage.googleapis.com%' OR cmdline LIKE '%storjshare.io%' OR cmdline LIKE '%temp.sh%' OR cmdline LIKE '%transfer.sh%' OR cmdline LIKE '%ufile.io%');

bool suspicious_file_download_from_file_sharing_domain_via_wget_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\wget.exe") != std::string::npos && (cmdline.find(".githubusercontent.com") != std::string::npos || cmdline.find("anonfiles.com") != std::string::npos || cmdline.find("cdn.discordapp.com") != std::string::npos || cmdline.find("cdn.discordapp.com/attachments/") != std::string::npos || cmdline.find("ddns.net") != std::string::npos || cmdline.find("dl.dropboxusercontent.com") != std::string::npos || cmdline.find("ghostbin.co") != std::string::npos || cmdline.find("gofile.io") != std::string::npos || cmdline.find("hastebin.com") != std::string::npos || cmdline.find("mediafire.com") != std::string::npos || cmdline.find("mega.nz") != std::string::npos || cmdline.find("paste.ee") != std::string::npos || cmdline.find("pastebin.com") != std::string::npos || cmdline.find("pastebin.pl") != std::string::npos || cmdline.find("pastetext.net") != std::string::npos || cmdline.find("privatlab.com") != std::string::npos || cmdline.find("privatlab.net") != std::string::npos || cmdline.find("send.exploit.in") != std::string::npos || cmdline.find("sendspace.com") != std::string::npos || cmdline.find("storage.googleapis.com") != std::string::npos || cmdline.find("storjshare.io") != std::string::npos || cmdline.find("temp.sh") != std::string::npos || cmdline.find("transfer.sh") != std::string::npos || cmdline.find("ufile.io") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected potentially suspicious file downloads from file sharing domains using wget.exe";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Change PowerShell Policies to an Insecure Level
// SELECT * FROM win_process_events WHERE
//(cmdline LIKE '% -executionpolicy %' OR
// cmdline LIKE '% -ep %' OR
// cmdline LIKE '% -exec %') AND
//(cmdline LIKE '%Unrestricted%' OR
// cmdline LIKE '%bypass%' OR
// cmdline LIKE '%RemoteSigned%') AND
//(cmdline LIKE '%C:\\Program Files%' OR
// cmdline LIKE '%C:\\ProgramData%' OR
// cmdline LIKE '%\\AppData\\Roaming\\Code\\%');

bool change_powershell_policies_to_an_insecure_level(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find(" -executionpolicy ") != std::string::npos ||
		 cmdline.find(" -ep ") != std::string::npos ||
		 cmdline.find(" -exec ") != std::string::npos) &&
		(cmdline.find("Unrestricted") != std::string::npos ||
		 cmdline.find("bypass") != std::string::npos ||
		 cmdline.find("RemoteSigned") != std::string::npos) &&
		(cmdline.find("C:\\Program Files") != std::string::npos ||
		 cmdline.find("C:\\ProgramData") != std::string::npos ||
		 cmdline.find("\\AppData\\Roaming\\Code\\") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Change PowerShell Policies to an Insecure Level";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Potentially Suspicious PowerShell Child Processes
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%\\Program Files\\Amazon\\WorkspacesConfig\\Scripts\\%';

bool potentially_suspicious_powershell_child_processes(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("\\Program Files\\Amazon\\WorkspacesConfig\\Scripts\\") != std::string::npos &&
		 cmdline.find("\\Program Files\\Amazon\\WorkspacesConfig\\Scripts\\") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Potentially Suspicious PowerShell Child Processes";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Suspicious PowerShell Download and Execute Pattern
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%IEX ((New-Object Net.WebClient).DownloadString%' OR
// cmdline LIKE '%IEX (New-Object Net.WebClient).DownloadString%' OR
// cmdline LIKE '%IEX((New-Object Net.WebClient).DownloadString%' OR
// cmdline LIKE '%IEX(New-Object Net.WebClient).DownloadString%' OR
// cmdline LIKE '% -command (New-Object System.Net.WebClient).DownloadFile(%' OR
// cmdline LIKE '% -c (New-Object System.Net.WebClient).DownloadFile(%';

bool suspicious_powershell_download_and_execute_pattern(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("IEX ((New-Object Net.WebClient).DownloadString") != std::string::npos ||
		 cmdline.find("IEX (New-Object Net.WebClient).DownloadString") != std::string::npos ||
		 cmdline.find("IEX((New-Object Net.WebClient).DownloadString") != std::string::npos ||
		 cmdline.find("IEX(New-Object Net.WebClient).DownloadString") != std::string::npos ||
		 cmdline.find(" -command (New-Object System.Net.WebClient).DownloadFile(") != std::string::npos ||
		 cmdline.find(" -c (New-Object System.Net.WebClient).DownloadFile(") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious PowerShell Download and Execute Pattern";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Suspicious PowerShell Parent Process
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%/c powershell%' OR
// cmdline LIKE '%/c pwsh%';

bool suspicious_powershell_parent_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("/c powershell") != std::string::npos ||
		cmdline.find("/c pwsh") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Suspicious PowerShell Parent Process";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - PowerShell Script Run in AppData
// SELECT * FROM win_process_events WHERE
//(cmdline LIKE '%Local\\%' OR cmdline LIKE '%Roaming\\%') AND
//(cmdline LIKE '%powershell.exe%' OR
// cmdline LIKE '%\\powershell%' OR
// cmdline LIKE '%\\pwsh%' OR
// cmdline LIKE '%pwsh.exe%') AND
// cmdline LIKE '%/c %' AND
// cmdline LIKE '%\\AppData\\%';

bool powershell_script_run_in_appdata(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("Local\\") != std::string::npos ||
		 cmdline.find("Roaming\\") != std::string::npos) &&
		(cmdline.find("powershell.exe") != std::string::npos ||
		 cmdline.find("\\powershell") != std::string::npos ||
		 cmdline.find("\\pwsh") != std::string::npos ||
		 cmdline.find("pwsh.exe") != std::string::npos) &&
		cmdline.find("/c ") != std::string::npos &&
		cmdline.find("\\AppData\\") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PowerShell Script Run in AppData";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Suspicious XOR Encoded PowerShell Command
// select * from win_process_events where
// cmdline like '%bxor%' and
//(cmdline like '%ForEach%' or
// cmdline like '%for(%' or
// cmdline like '%for %' or
// cmdline like '%-join %' or
// cmdline like '%-join\'' or
// cmdline like '%-join\"%' or
// cmdline like '%-join`%' or
// cmdline like '%::Join%' or
// cmdline like '%[char]%');

bool suspicious_xor_encoded_powershell_command(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find("bxor") != std::string::npos &&
		(cmdline.find("ForEach") != std::string::npos ||
		 cmdline.find("for(") != std::string::npos ||
		 cmdline.find("for ") != std::string::npos ||
		 cmdline.find("-join ") != std::string::npos ||
		 cmdline.find("-join'") != std::string::npos ||
		 cmdline.find("-join\"") != std::string::npos ||
		 cmdline.find("-join`") != std::string::npos ||
		 cmdline.find("::Join") != std::string::npos ||
		 cmdline.find("[char]") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious XOR Encoded PowerShell Command";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Potential ShellDispatch.DLL Functionality Abuse
// select * from win_process_events where path like '%\rundll32.exe%' and cmdline like '%RunDll_ShellExecuteW%';

bool potential_shelldispatchdll_functionality_abuse(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\rundll32.exe") != std::string::npos && cmdline.find("RunDll_ShellExecuteW") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected potential 'ShellDispatch.dll' functionality abuse to execute arbitrary binaries via 'ShellExecute'";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1562.001 - Service StartupType Change Via Sc.EXE
// select * from win_process_events where path like '%\sc.exe%' and (cmdline like '% config %' and cmdline like '%start%') and (cmdline like '%disabled%' or cmdline like '%demand%');

bool service_startuptype_change_via_scexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && (cmdline.find(" config ") != std::string::npos && cmdline.find("start") != std::string::npos) && (cmdline.find("disabled") != std::string::npos || cmdline.find("demand") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the use of 'sc.exe' to change the startup type of a service to 'disabled' or 'demand'";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059 - Add New Download Source To Winget
// SELECT * FROM win_process_events WHERE (path LIKE '%winget%' OR path LIKE '%winget.exe%') AND cmdline LIKE '%source%' AND cmdline LIKE '%add%';

bool add_new_download_source_to_winget(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("winget") != std::string::npos || path.find("winget.exe") != std::string::npos) && cmdline.find("source") != std::string::npos && cmdline.find("add") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059 - Add Insecure Download Source To Winget
// SELECT * FROM win_process_events WHERE (path LIKE '%winget%' OR path LIKE '%winget.exe%') AND cmdline LIKE '%source%' AND cmdline LIKE '%add%' AND cmdline LIKE '%http://%';

bool add_insecure_download_source_to_winget(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("winget") != std::string::npos || path.find("winget.exe") != std::string::npos) && cmdline.find("source") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("http://") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected usage of winget to add a new insecure (http) download source.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059 - Add Insecure Download Source To Winget
// SELECT * FROM win_process_events WHERE (path LIKE '%winget%' OR path LIKE '%winget.exe%') AND cmdline LIKE '%source%' AND cmdline LIKE '%add%' AND cmdline LIKE '%://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}%';

bool add_potential_suspicious_new_download_source_to_winget(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("winget") != std::string::npos || path.find("winget.exe") != std::string::npos) && cmdline.find("source") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected usage of winget to add new potentially suspicious download sources.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1203 - Potentially Suspicious Child Process Of WinRAR.EXE
// SELECT * FROM win_process_events WHERE parent_path LIKE '%WinRAR.exe%' AND (path LIKE '%.dmp%' OR path LIKE '%.dump%' OR path LIKE '%.hdmp%');

bool potentially_suspicious_child_process_of_winRAR_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.cmdline;

	if (parent_path.find("WinRAR.exe") != std::string::npos && (path.find(".dmp") != std::string::npos || path.find(".dump") != std::string::npos || path.find(".hdmp") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected potentially suspicious child processes of WinRAR.exe.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - New Process Created Via Wmic.EXE
// SELECT * FROM win_process_events WHERE cmdline LIKE '%wmic%' AND cmdline LIKE '%process%' AND cmdline LIKE '%call%' AND cmdline LIKE '%create%';

bool new_process_created_via_Wmic_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("wmic") != std::string::npos && cmdline.find("process") != std::string::npos && cmdline.find("call") != std::string::npos && cmdline.find("create") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected new process creation using WMIC via the 'process call create' flag.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Computer System Reconnaissance Via Wmic.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%wmic%' AND cmdline LIKE '%computersystem%';

bool computer_system_reconnaissance_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("wmic") != std::string::npos && cmdline.find("computersystem") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected execution of wmic utility with the 'computersystem' flag in order to obtain information about the machine such as the domain, username, model, etc.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Hardware Model Reconnaissance Via Wmic.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%wmic%' AND cmdline LIKE '%csproduct%';

bool hardware_model_reconnaissance_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("wmic") != std::string::npos && cmdline.find("csproduct") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected the execution of WMIC with the 'csproduct' which is used to obtain information such as hardware models and vendor information.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1569.002 - PUA - NirCmd Execution As LOCAL SYSTEM
// select * from win_process_events where
// cmdline like '% runassystem %';

bool pua_nircmd_execution_as_local_system(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(" runassystem ") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PUA - NirCmd Execution As LOCAL SYSTEM";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1569.002 - PUA - NirCmd Execution
// select * from win_process_events where
//((cmdline like '% execmd %' or
// cmdline like '%.exe script %' or
// cmdline like '%.exe shexec%' or
// cmdline like '% runinteractive %') and
//(cmdline like '% exec %' or
// cmdline like '% exec2 %') and
//(cmdline like '% show %' or
// cmdline like '% hide %'));

bool pua_nircmd_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\NirCmd.exe") != std::string::npos &&
		(cmdline.find(" execmd ") != std::string::npos ||
		 cmdline.find(".exe script ") != std::string::npos ||
		 cmdline.find(".exe shexec") != std::string::npos ||
		 cmdline.find(" runinteractive ") != std::string::npos) &&
		(cmdline.find(" exec ") != std::string::npos ||
		 cmdline.find(" exec2 ") != std::string::npos) &&
		(cmdline.find(" show ") != std::string::npos ||
		 cmdline.find(" hide ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "PUA - NirCmd Execution";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1569.002 - PUA - NSudo Execution
// select * from win_process_events where
//(cmdline like '%-U:S%' or
// cmdline like '%-U:T%' or
// cmdline like '%-U:E%' or
// cmdline like '%-P:E%' or
// cmdline like '%-M:S%' or
// cmdline like '%-M:H%' or
// cmdline like '%-U=S%' or
// cmdline like '%-U=T%' or
// cmdline like '%-U=E%' or
// cmdline like '%-P=E%' or
// cmdline like '%-M=S%' or
// cmdline like '%-M=H%' or
// cmdline like '%-ShowWindowMode:Hide%');

bool pua_nsudo_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\NSudo.exe") != std::string::npos &&
			path.find("\\NSudoLC.exe") != std::string::npos &&
			path.find("\\NSudoLG.exe") != std::string::npos &&
			cmdline.find("-U:S ") != std::string::npos ||
		cmdline.find("-U:T ") != std::string::npos ||
		cmdline.find("-U:E ") != std::string::npos ||
		cmdline.find("-P:E ") != std::string::npos ||
		cmdline.find("-M:S ") != std::string::npos ||
		cmdline.find("-M:H ") != std::string::npos ||
		cmdline.find("-U=S ") != std::string::npos ||
		cmdline.find("-U=T ") != std::string::npos ||
		cmdline.find("-U=E ") != std::string::npos ||
		cmdline.find("-P=E ") != std::string::npos ||
		cmdline.find("-M=S ") != std::string::npos ||
		cmdline.find("-M=H ") != std::string::npos ||
		cmdline.find("-ShowWindowMode:Hide") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PUA - NSudo Execution";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1569.002 - PUA - RunXCmd Execution
// select * from win_process_events where
// cmdline like '%/exec=%' and
//(cmdline like '% /account=system %' or
// cmdline like '% /account=ti %');

bool pua_runxcmd_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("/exec=") != std::string::npos &&
		(cmdline.find(" /account=system ") != std::string::npos ||
		 cmdline.find(" /account=ti ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "PUA - RunXCmd Execution";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
// select * from win_process_events where
// cmdline like '% service get %' and
// cmdline like '%name,displayname,pathname,startmode%';

bool potential_unquoted_service_path_reconnaissance_via_wmicexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\WMIC.exe") != std::string::npos &&
		cmdline.find(" service get ") != std::string::npos &&
		cmdline.find("name,displayname,pathname,startmode") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Potential Unquoted Service Path Reconnaissance Via Wmic.EXE";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - WMIC Remote Command Execution
// select * from win_process_events where
// cmdline like '%/node:%' and
//(cmdline like '%/node:127.0.0.1%' or
// cmdline like '%/node:localhost%');

bool wmic_remote_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\WMIC.exe") != std::string::npos &&
		cmdline.find("/node:") != std::string::npos &&
		(cmdline.find("/node:127.0.0.1 ") != std::string::npos ||
		 cmdline.find("/node:localhost ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "WMIC Remote Command Execution";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Service Started/Stopped Via Wmic.EXE
// select * from win_process_events where
//((cmdline like '% service %' or
// cmdline like '% call %') and
//(cmdline like '%stopservice%' or
// cmdline like '%startservice%'));

bool service_started_stopped_via_wmicexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\WMIC.exe") != std::string::npos &&
		(cmdline.find(" service ") != std::string::npos ||
		 cmdline.find(" call ") != std::string::npos) &&
		(cmdline.find("stopservice") != std::string::npos ||
		 cmdline.find("startservice") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Service Started/Stopped Via Wmic.EXE";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Potential SquiblyTwo Technique Execution
// select * from win_process_events where
// cmdline like '%format:%' and
// cmdline like '%http%';

bool potential_squiblytwo_technique_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\wmic.exe") != std::string::npos &&
		cmdline.find("format:") != std::string::npos &&
		cmdline.find("http") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Potential SquiblyTwo Technique Execution";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Suspicious WMIC Execution Via Office Process
// select * from win_process_events where
// cmdline like '%process%' and
// cmdline like '%create%' and
// cmdline like '%call%' and
//(cmdline like '%regsvr32%' or
// cmdline like '%rundll32%' or
// cmdline like '%msiexec%' or
// cmdline like '%mshta%' or
// cmdline like '%verclsid%' or
// cmdline like '%wscript%' or
// cmdline like '%cscript%');

bool suspicious_wmic_execution_via_office_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("process") != std::string::npos &&
		cmdline.find("create") != std::string::npos &&
		cmdline.find("call") != std::string::npos &&
		(cmdline.find("regsvr32") != std::string::npos ||
		 cmdline.find("rundll32") != std::string::npos ||
		 cmdline.find("msiexec") != std::string::npos ||
		 cmdline.find("mshta") != std::string::npos ||
		 cmdline.find("verclsid") != std::string::npos ||
		 cmdline.find("wscript") != std::string::npos ||
		 cmdline.find("cscript") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious WMIC Execution Via Office Process";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Schtasks Execution AppData Folder
// select * from win_process_events where path like '%\schtasks.exe%' and (cmdline like '%/Create%' and cmdline like '%/RU%' and cmdline like '%/TR%' and cmdline like '%C:\Users\%' and cmdline like '%\AppData\Local\%') and (cmdline like '%NT AUT%' or cmdline like '% SYSTEM %') and not (parent_path like '%\AppData\Local\Temp\%' and parent_path like '%TeamViewer_.exe%' and path like '%\schtasks.exe%' and cmdline like '%/TN TVInstallRestore%');

bool suspicious_schtasks_execution_appdata_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("/Create") != std::string::npos && cmdline.find("/RU") != std::string::npos && cmdline.find("/TR") != std::string::npos && cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("\\AppData\\Local\\") != std::string::npos) && (cmdline.find("NT AUT") != std::string::npos || cmdline.find(" SYSTEM ") != std::string::npos) && !(parent_path.find("\\AppData\\Local\\Temp\\") != std::string::npos && parent_path.find("TeamViewer_.exe") != std::string::npos && path.find("\\schtasks.exe") != std::string::npos && cmdline.find("/TN TVInstallRestore") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the creation of a schtask that executes a file from 'C:\\Users\\<USER>\\AppData\\Local'";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Modification Of Scheduled Tasks
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '% /Change %' AND cmdline LIKE '% /TN %' AND (cmdline LIKE '%\AppData\Local\Temp%' OR cmdline LIKE '%\AppData\Roaming\%' OR cmdline LIKE '%\Users\Public\%' OR cmdline LIKE '%\WINDOWS\Temp\%' OR cmdline LIKE '%\Desktop\%' OR cmdline LIKE '%\Downloads\%' OR cmdline LIKE '%\Temporary Internet%' OR cmdline LIKE '%C:\ProgramData\%' OR cmdline LIKE '%C:\Perflogs\%' OR cmdline LIKE '%\%ProgramData\%%' OR cmdline LIKE '%\%appdata\%%' OR cmdline LIKE '%\%comspec\%%' OR cmdline LIKE '%\%localappdata\%%'))AND (cmdline LIKE '%regsvr32%' OR cmdline LIKE '%rundll32%' OR cmdline LIKE '%cmd /c %' OR cmdline LIKE '%cmd /k %' OR cmdline LIKE '%cmd /r %' OR cmdline LIKE '%cmd.exe /c %' OR cmdline LIKE '%cmd.exe /k %' OR cmdline LIKE '%cmd.exe /r %' OR cmdline LIKE '%powershell%' OR cmdline LIKE '%mshta%' OR cmdline LIKE '%wscript%' OR cmdline LIKE '%cscript%' OR cmdline LIKE '%certutil%' OR cmdline LIKE '%bitsadmin%' OR cmdline LIKE '%bash.exe%' OR cmdline LIKE '%bash %' OR cmdline LIKE '%scrcons%' OR cmdline LIKE '%wmic %' OR cmdline LIKE '%forfiles%' OR cmdline LIKE '%scriptrunner%' OR cmdline LIKE '%hh.exe%' OR cmdline LIKE '%hh %');

bool suspicious_modification_of_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find(" /Change ") != std::string::npos && cmdline.find(" /TN ") != std::string::npos) && (cmdline.find("\\AppData\\Local\\Temp") != std::string::npos || cmdline.find("\\AppData\\Roaming\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\WINDOWS\\Temp\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Temporary Internet") != std::string::npos || cmdline.find("C:\\ProgramData\\") != std::string::npos || cmdline.find("C:\\Perflogs\\") != std::string::npos || cmdline.find("%ProgramData%") != std::string::npos || cmdline.find("%%appdata%") != std::string::npos || cmdline.find("%%comspec%") != std::string::npos || cmdline.find("%%localappdata%") != std::string::npos) && (cmdline.find("regsvr32") != std::string::npos || cmdline.find("rundll32") != std::string::npos || cmdline.find("cmd /c ") != std::string::npos || cmdline.find("cmd /k ") != std::string::npos || cmdline.find("cmd /r ") != std::string::npos || cmdline.find("cmd.exe /c ") != std::string::npos || cmdline.find("cmd.exe /k ") != std::string::npos || cmdline.find("cmd.exe /r ") != std::string::npos || cmdline.find("powershell") != std::string::npos || cmdline.find("mshta") != std::string::npos || cmdline.find("wscript") != std::string::npos || cmdline.find("cscript") != std::string::npos || cmdline.find("certutil") != std::string::npos || cmdline.find("bitsadmin") != std::string::npos || cmdline.find("bash.exe") != std::string::npos || cmdline.find("bash ") != std::string::npos || cmdline.find("scrcons") != std::string::npos || cmdline.find("wmic ") != std::string::npos || cmdline.find("wmic.exe") != std::string::npos || cmdline.find("forfiles") != std::string::npos || cmdline.find("scriptrunner") != std::string::npos || cmdline.find("hh.exe") != std::string::npos || cmdline.find("hh ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected an attacker trying to modify an already existing scheduled tasks to run from a suspicious location";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Scheduled Task Creation Involving Temp Folder
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '% /create %' AND cmdline LIKE '% /sc once %' AND cmdline LIKE '%\Temp\%');

bool suspicious_scheduled_task_creation_involving_temp_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find(" /create ") != std::string::npos && cmdline.find(" /sc once ") != std::string::npos && cmdline.find("\\Temp\\") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the creation of scheduled tasks that involves a temporary folder";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Scheduled Task Creation
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND cmdline LIKE '% /create %' AND NOT (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%');

bool scheduled_task_creation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && cmdline.find(" /create ") != std::string::npos && !(cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the creation of scheduled tasks in user session";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Schtasks From Suspicious Folders
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND cmdline LIKE '% /create %' AND (cmdline LIKE '%powershell%' OR cmdline LIKE '%pwsh%' OR cmdline LIKE '%cmd /c%' OR cmdline LIKE '%cmd /k%' OR cmdline LIKE '%cmd /r%' OR cmdline LIKE '%cmd.exe /c%' OR cmdline LIKE '%cmd.exe /k%' OR cmdline LIKE '%cmd.exe /r%') AND (cmdline LIKE '%C:\ProgramData\%' OR cmdline LIKE '%\%ProgramData\%%');

bool schtasks_from_suspicious_folders(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && cmdline.find(" /create ") != std::string::npos && (cmdline.find("powershell") != std::string::npos || cmdline.find("pwsh") != std::string::npos || cmdline.find("cmd /c ") != std::string::npos || cmdline.find("cmd /k ") != std::string::npos || cmdline.find("cmd /r ") != std::string::npos || cmdline.find("cmd.exe /c ") != std::string::npos || cmdline.find("cmd.exe /k ") != std::string::npos || cmdline.find("cmd.exe /r ") != std::string::npos) && (cmdline.find("C:\\ProgramData\\") != std::string::npos || cmdline.find("%ProgramData%") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected scheduled task creations that have suspicious action command and folder combinations";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Scheduled Task Name As GUID
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND cmdline LIKE '% /Create %' AND (cmdline LIKE '%/TN "{%' OR cmdline LIKE '%/TN '{%' OR cmdline LIKE '%/TN {%') AND (cmdline LIKE '%}"%' OR cmdline LIKE '%}'%' OR cmdline LIKE '%} %');

bool suspicious_scheduled_task_name_as_guid(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && cmdline.find(" /Create ") != std::string::npos && (cmdline.find("/TN \"{") != std::string::npos || cmdline.find("/TN '{") != std::string::npos || cmdline.find("/TN {") != std::string::npos) && (cmdline.find("}\"") != std::string::npos || cmdline.find("}'") != std::string::npos || cmdline.find("} ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected creation of a scheduled task with a GUID like name";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Uncommon One Time Only Scheduled Task At 00:00
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '%wscript%' OR cmdline LIKE '%vbscript%' OR cmdline LIKE '%cscript%' OR cmdline LIKE '%wmic %' OR cmdline LIKE '%wmic.exe%' OR cmdline LIKE '%regsvr32.exe%' OR cmdline LIKE '%powershell%' OR cmdline LIKE '%\AppData\%') AND (cmdline LIKE '%once%' AND cmdline LIKE '%00:00%');

bool uncommon_one_time_only_scheduled_task_at_0000(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("wscript") != std::string::npos || cmdline.find("vbscript") != std::string::npos || cmdline.find("cscript") != std::string::npos || cmdline.find("wmic ") != std::string::npos || cmdline.find("wmic.exe") != std::string::npos || cmdline.find("regsvr32.exe") != std::string::npos || cmdline.find("powershell") != std::string::npos || cmdline.find("\\AppData\\") != std::string::npos) && (cmdline.find("once") != std::string::npos && cmdline.find("00:00") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected scheduled task creation events that include suspicious actions, and run once at 00:00";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Add Scheduled Task Parent
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND cmdline LIKE '% /Create %' AND (parent_path LIKE '%\AppData\Local\%' OR parent_path LIKE '%\AppData\Roaming\%' OR parent_path LIKE '%\Temporary Internet%' OR parent_path LIKE '%\Users\Public\%') AND NOT (cmdline LIKE '%update_task.xml%' OR cmdline LIKE '%unattended.ini%');

bool suspicious_add_scheduled_task_parent(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("\\schtasks.exe") != std::string::npos && cmdline.find(" /Create ") != std::string::npos && (parent_path.find("\\AppData\\Local\\") != std::string::npos || parent_path.find("\\AppData\\Roaming\\") != std::string::npos || parent_path.find("\\Temporary Internet") != std::string::npos || parent_path.find("\\Users\\Public\\") != std::string::npos) && (cmdline.find("update_task.xml") != std::string::npos || cmdline.find("unattended.ini") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected suspicious scheduled task creations from a parent stored in a temporary folder";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Potential Persistence Via Powershell Search Order Hijacking - Task
// SELECT * FROM win_process_events WHERE parent_path LIKE '%C:\WINDOWS\System32\svchost.exe%' AND (cmdline LIKE '%-k netsvcs%' AND cmdline LIKE '%-s Schedule%') AND (cmdline LIKE '% -windowstyle hidden%' OR cmdline LIKE '% -w hidden%' OR cmdline LIKE '% -ep bypass%' OR cmdline LIKE '% -noni%');

bool potential_persistence_via_powershell_search_order_hijacking_task(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("C:\\WINDOWS\\System32\\svchost.exe") != std::string::npos && (cmdline.find("-k netsvcs") != std::string::npos && cmdline.find("-s Schedule") != std::string::npos) && (cmdline.find(" -windowstyle hidden") != std::string::npos || cmdline.find(" -w hidden") != std::string::npos || cmdline.find(" -ep bypass") != std::string::npos || cmdline.find(" -noni") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected suspicious powershell execution via a schedule task where the command ends with an suspicious flags.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Scheduled Task Executing Encoded Payload from Registry
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND cmdline LIKE '%/Create%' AND (cmdline LIKE '%FromBase64String%' OR cmdline LIKE '%encodedcommand%') AND (cmdline LIKE '%Get-ItemProperty%' OR cmdline LIKE '% gp %') AND (cmdline LIKE '%HKCU:%' OR cmdline LIKE '%HKLM:%' OR cmdline LIKE '%registry::%' OR cmdline LIKE '%HKEY_%');

bool scheduled_task_executing_encoded_payload_from_registry(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && cmdline.find("/Create") != std::string::npos && (cmdline.find("FromBase64String") != std::string::npos || cmdline.find("encodedcommand") != std::string::npos) && (cmdline.find("Get-ItemProperty") != std::string::npos || cmdline.find(" gp ") != std::string::npos) && (cmdline.find("HKCU:") != std::string::npos || cmdline.find("HKLM:") != std::string::npos || cmdline.find("registry::") != std::string::npos || cmdline.find("HKEY_") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the creation of a schtask that potentially executes a base64 encoded payload stored in the Windows Registry using PowerShell.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Scheduled Task Executing Payload from Registry
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND cmdline LIKE '%/Create%' AND (cmdline LIKE '%Get-ItemProperty%' OR cmdline LIKE '% gp %') AND (cmdline LIKE '%HKCU:%' OR cmdline LIKE '%HKLM:%' OR cmdline LIKE '%registry::%' OR cmdline LIKE '%HKEY_%') AND NOT (cmdline LIKE '%FromBase64String%' OR cmdline LIKE '%encodedcommand%');

bool scheduled_task_executing_payload_from_registry(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && cmdline.find("/Create") != std::string::npos && (cmdline.find("Get-ItemProperty") != std::string::npos || cmdline.find(" gp ") != std::string::npos) && (cmdline.find("HKCU:") != std::string::npos || cmdline.find("HKLM:") != std::string::npos || cmdline.find("registry::") != std::string::npos || cmdline.find("HKEY_") != std::string::npos) && !(cmdline.find("FromBase64String") != std::string::npos || cmdline.find("encodedcommand") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the creation of a schtask that potentially executes a payload stored in the Windows Registry using PowerShell.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Schtasks Schedule Type With High Privileges
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '% ONLOGON %' OR cmdline LIKE '% ONSTART %' OR cmdline LIKE '% ONCE %' OR cmdline LIKE '% ONIDLE %') AND (cmdline LIKE '%NT AUT%' OR cmdline LIKE '% SYSTEM%' OR cmdline LIKE '%HIGHEST%');

bool suspicious_schtasks_schedule_type_with_high_privileges(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find(" ONLOGON ") != std::string::npos || cmdline.find(" ONSTART ") != std::string::npos || cmdline.find(" ONCE ") != std::string::npos || cmdline.find(" ONIDLE ") != std::string::npos) && (cmdline.find("NT AUT") != std::string::npos || cmdline.find(" SYSTEM") != std::string::npos || cmdline.find("HIGHEST") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected scheduled task creations or modification to be run with high privileges on a suspicious schedule type.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Schtasks Schedule Types
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '% ONLOGON %' OR cmdline LIKE '% ONSTART %' OR cmdline LIKE '% ONCE %' OR cmdline LIKE '% ONIDLE %') AND NOT (cmdline LIKE '%NT AUT%' OR cmdline LIKE '% SYSTEM%' OR cmdline LIKE '%HIGHEST%');

bool suspicious_schtasks_schedule_types(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find(" ONLOGON ") != std::string::npos || cmdline.find(" ONSTART ") != std::string::npos || cmdline.find(" ONCE ") != std::string::npos || cmdline.find(" ONIDLE ") != std::string::npos) && !(cmdline.find("NT AUT") != std::string::npos || cmdline.find(" SYSTEM") != std::string::npos || cmdline.find("HIGHEST") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected scheduled task creations or modification on a suspicious schedule type.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Script Event Consumer Spawning Process
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\scrcons.exe%' AND (path LIKE '%\svchost.exe%' OR path LIKE '%\dllhost.exe%' OR path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%' OR path LIKE '%\cscript.exe%' OR path LIKE '%\wscript.exe%' OR path LIKE '%\schtasks.exe%' OR path LIKE '%\regsvr32.exe%' OR path LIKE '%\mshta.exe%' OR path LIKE '%\rundll32.exe%' OR path LIKE '%\msiexec.exe%' OR path LIKE '%\msbuild.exe%');

bool script_event_consumer_spawning_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("\\scrcons.exe") != std::string::npos && (path.find("\\svchost.exe") != std::string::npos || path.find("\\dllhost.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos || path.find("\\schtasks.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\msiexec.exe") != std::string::npos || path.find("\\msbuild.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected a suspicious child process of Script Event Consumer.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Uncommon Child Processes Of SndVol.exe
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\SndVol.exe%' AND NOT (path LIKE '%\rundll32.exe%' AND cmdline LIKE '% shell32.dll,Control_RunDLL %');

bool uncommon_child_processes_of_sndvolexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (parent_path.find("\\SndVol.exe") != std::string::npos && !(path.find("\\rundll32.exe") != std::string::npos && cmdline.find(" shell32.dll,Control_RunDLL ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected potentially uncommon child processes of SndVol.exe";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1203 - Suspicious Spool Service Child Process
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\spoolsv.exe%' AND (path LIKE '%\gpupdate.exe%' OR path LIKE '%\whoami.exe%' OR path LIKE '%\nltest.exe%' OR path LIKE '%\taskkill.exe%' OR path LIKE '%\wmic.exe%' OR path LIKE '%\taskmgr.exe%' OR path LIKE '%\sc.exe%' OR path LIKE '%\findstr.exe%' OR path LIKE '%\curl.exe%' OR path LIKE '%\wget.exe%' OR path LIKE '%\certutil.exe%' OR path LIKE '%\bitsadmin.exe%' OR path LIKE '%\accesschk.exe%' OR path LIKE '%\wevtutil.exe%' OR path LIKE '%\bcdedit.exe%' OR path LIKE '%\fsutil.exe%' OR path LIKE '%\cipher.exe%' OR path LIKE '%\schtasks.exe%' OR path LIKE '%\write.exe%' OR path LIKE '%\wuauclt.exe%' OR path LIKE '%\systeminfo.exe%' OR path LIKE '%\reg.exe%' OR path LIKE '%\query.exe%') OR ((path LIKE '%\net.exe%' OR path LIKE '%\net1.exe%') AND NOT (cmdline LIKE '%start%')) OR (path LIKE '%\cmd.exe%' AND NOT (cmdline LIKE '%.spl%' OR cmdline LIKE '%route add%' OR cmdline LIKE '%program files%')) OR (path LIKE '%\netsh.exe%' AND NOT (cmdline LIKE '%add portopening%' OR cmdline LIKE '%rule name%')) OR ((path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%') AND NOT (cmdline LIKE '%.spl%')) OR (path LIKE '%\rundll32.exe%' AND cmdline LIKE '%rundll32.exe%'));

bool suspicious_spool_service_child_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (parent_path.find("spoolsv.exe") != std::string::npos && ((path.find("\\gpupdate.exe") != std::string::npos || path.find("\\whoami.exe") != std::string::npos || path.find("\\nltest.exe") != std::string::npos || path.find("\\taskkill.exe") != std::string::npos || path.find("\\wmic.exe") != std::string::npos || path.find("\\taskmgr.exe") != std::string::npos || path.find("\\sc.exe") != std::string::npos || path.find("\\findstr.exe") != std::string::npos || path.find("\\curl.exe") != std::string::npos || path.find("\\wget.exe") != std::string::npos || path.find("\\certutil.exe") != std::string::npos || path.find("\\bitsadmin.exe") != std::string::npos || path.find("\\accesschk.exe") != std::string::npos || path.find("\\wevtutil.exe") != std::string::npos || path.find("\\bcdedit.exe") != std::string::npos || path.find("\\fsutil.exe") != std::string::npos || path.find("\\cipher.exe") != std::string::npos || path.find("\\schtasks.exe") != std::string::npos || path.find("\\write.exe") != std::string::npos || path.find("\\wuauclt.exe") != std::string::npos || path.find("\\systeminfo.exe") != std::string::npos || path.find("\\reg.exe") != std::string::npos || path.find("\\query.exe") != std::string::npos) || ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && !(cmdline.find("start") != std::string::npos)) || (path.find("\\cmd.exe") != std::string::npos && !(cmdline.find(".spl") != std::string::npos || cmdline.find("route add") != std::string::npos || cmdline.find("program files") != std::string::npos)) || (path.find("\\netsh.exe") != std::string::npos && !(cmdline.find("add portopening") != std::string::npos || cmdline.find("rule name") != std::string::npos)) || ((path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos) && !(cmdline.find(".spl") != std::string::npos)) || (path.find("\\rundll32.exe") != std::string::npos && cmdline.find("rundll32.exe") != std::string::npos)))

	{
		std::stringstream ss;

		ss << "Detected suspicious print spool service child processes.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Suspicious Process Created Via Wmic.EXE
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%process %' AND cmdline LIKE '%call %' AND cmdline LIKE '%create %') AND (cmdline LIKE '%rundll32%' OR cmdline LIKE '%bitsadmin%' OR cmdline LIKE '%regsvr32%' OR cmdline LIKE '%cmd.exe /c %' OR cmdline LIKE '%cmd.exe /k %' OR cmdline LIKE '%cmd.exe /r %' OR cmdline LIKE '%cmd /c %' OR cmdline LIKE '%cmd /k %' OR cmdline LIKE '%cmd /r %' OR cmdline LIKE '%powershell%' OR cmdline LIKE '%pwsh%' OR cmdline LIKE '%certutil%' OR cmdline LIKE '%cscript%' OR cmdline LIKE '%wscript%' OR cmdline LIKE '%mshta%' OR cmdline LIKE '%\Users\Public\%' OR cmdline LIKE '%\Windows\Temp\%' OR cmdline LIKE '%\AppData\Local\%' OR cmdline LIKE '%\%temp\%%' OR cmdline LIKE '%\%tmp\%%' OR cmdline LIKE '%\%ProgramData\%%' OR cmdline LIKE '%\%appdata\%%' OR cmdline LIKE '%\%comspec\%%' OR cmdline LIKE '%\%localappdata\%%'));

bool suspicious_process_created_via_wmicexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("process ") != std::string::npos && cmdline.find("call ") != std::string::npos && cmdline.find("create ") != std::string::npos) && (cmdline.find("rundll32") != std::string::npos || cmdline.find("bitsadmin") != std::string::npos || cmdline.find("regsvr32") != std::string::npos || cmdline.find("cmd.exe /c ") != std::string::npos || cmdline.find("cmd.exe /k ") != std::string::npos || cmdline.find("cmd.exe /r ") != std::string::npos || cmdline.find("cmd /c ") != std::string::npos || cmdline.find("cmd /k ") != std::string::npos || cmdline.find("cmd /r ") != std::string::npos || cmdline.find("powershell") != std::string::npos || cmdline.find("pwsh") != std::string::npos || cmdline.find("certutil") != std::string::npos || cmdline.find("cscript") != std::string::npos || cmdline.find("wscript") != std::string::npos || cmdline.find("mshta") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Local\\") != std::string::npos || cmdline.find("%%temp%") != std::string::npos || cmdline.find("%tmp%") != std::string::npos || cmdline.find("%ProgramData%") != std::string::npos || cmdline.find("%%appdata%") != std::string::npos || cmdline.find("%%comspec%") != std::string::npos || cmdline.find("%%localappdata%") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected WMIC executing 'process call create' with suspicious calls to processes";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Application Terminated Via Wmic.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\WMIC.exe%' AND (cmdline LIKE '%call%' AND cmdline LIKE '%terminate%');

bool application_terminated_via_wmicexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\WMIC.exe") != std::string::npos && (cmdline.find("call") != std::string::npos && cmdline.find("terminate") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected call to the 'terminate' function via wmic in order to kill an application";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Application Removed Via Wmic.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\WMIC.exe%' AND (cmdline LIKE '%call%' AND cmdline LIKE '%uninstall%');

bool application_removed_via_wmicexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\WMIC.exe") != std::string::npos && (cmdline.find("call") != std::string::npos && cmdline.find("uninstall") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected uninstallation of an application with wmic";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\WmiPrvSE.exe%' AND (path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%');

bool potential_wmi_lateral_movement_wmiprvse_spawned_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (parent_path.find("\\WmiPrvSE.exe") != std::string::npos && (path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected Powershell as a child of the WmiPrvSE process which could be a sign of lateral movement via WMI.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1047 - Suspicious WmiPrvSE Child Process
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\wbem\WmiPrvSE.exe%' AND (path LIKE '%\certutil%' OR path LIKE '%\cscript.exe%' OR path LIKE '%\mshta.exe%' OR path LIKE '%\msiexec.exe%' OR path LIKE '%\regsvr32.exe%' OR path LIKE '%\rundll32.exe%' OR path LIKE '%\verclsid.exe%' OR path LIKE '%\wscript.exe%' OR (path LIKE '%\cmd.exe%' AND (cmdline LIKE '%cscript%' OR cmdline LIKE '%mshta%' OR cmdline LIKE '%powershell%' OR cmdline LIKE '%pwsh%' OR cmdline LIKE '%regsvr32%' OR cmdline LIKE '%rundll32%' OR cmdline LIKE '%wscript%'))) AND NOT (path LIKE '%\WerFault.exe%') AND NOT (path LIKE '%\WmiPrvSE.exe%'));

bool suspicious_wmiprvse_child_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (parent_path.find("\\wbem\\WmiPrvSE.exe") != std::string::npos && ((path.find("\\certutil.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\msiexec.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\verclsid.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos) || (path.find("\\cmd.exe") != std::string::npos && (cmdline.find("cscript") != std::string::npos || cmdline.find("mshta") != std::string::npos || cmdline.find("powershell") != std::string::npos || cmdline.find("pwsh") != std::string::npos || cmdline.find("regsvr32") != std::string::npos || cmdline.find("rundll32") != std::string::npos || cmdline.find("wscript") != std::string::npos))) && !(path.find("\\WerFault.exe") != std::string::npos) && !(path.find("\\WmiPrvSE.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected suspicious and uncommon child processes of WmiPrvSE.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059 - Suspicious Greedy Compression Using Rar.EXE
// SELECT * FROM win_process_events WHERE ((path LIKE '%\rar.exe%') OR (cmdline LIKE '%.exe a %' OR cmdline LIKE '% a -m%')) AND ((cmdline LIKE '% -hp%' AND cmdline LIKE '% -r %') AND (cmdline LIKE '% C:\\\*.%' OR cmdline LIKE '% C:\\\\\*.%' OR cmdline LIKE '% C:\Users\Public\%' OR cmdline LIKE '% \%public\%%' OR cmdline LIKE '% C:\Windows\%' OR cmdline LIKE '% C:\PerfLogs\%' OR cmdline LIKE '% C:\Temp%' OR cmdline LIKE '% C:\$Recycle.bin\%'));

bool suspicious_greedy_compression_using_rarexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (((path.find("\\rar.exe") != std::string::npos) || (cmdline.find(".exe a ") != std::string::npos || cmdline.find(" a -m") != std::string::npos)) && ((cmdline.find(" -hp") != std::string::npos && cmdline.find(" -r ") != std::string::npos) && (cmdline.find(" C:\\\\\\*.") != std::string::npos || cmdline.find(" C:\\\\\\\\\\*.") != std::string::npos || cmdline.find(" C:\\Users\\Public\\") != std::string::npos || cmdline.find(" %%public%") != std::string::npos || cmdline.find(" C:\\Windows\\") != std::string::npos || cmdline.find(" C:\\PerfLogs\\") != std::string::npos || cmdline.find(" C:\\Temp") != std::string::npos || cmdline.find(" C:\\$Recycle.bin\\") != std::string::npos)))
	{
		std::stringstream ss;

		ss << "Detected RAR usage that created an archive from a suspicious folder";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Suspicious Command Patterns In Scheduled Task Creation
//  SELECT * FROM win_process_events WHERE (((path LIKE '%\schtasks.exe%' AND cmdline LIKE '/Create%') AND (((cmdline LIKE '%/sc minute%' OR cmdline LIKE '%/ru system%') AND (cmdline LIKE '%cmd /c%' OR cmdline LIKE '%cmd /k%' OR cmdline LIKE '%cmd /r%' OR cmdline LIKE '%cmd.exe /c%' OR cmdline LIKE '%cmd.exe /k%' OR cmdline LIKE '%cmd.exe /r%')) OR (cmdline LIKE '% -decode%' OR cmdline LIKE '% -enc%' OR cmdline LIKE '% -w hidden%' OR cmdline LIKE '% bypass%' OR cmdline LIKE '% IEX%' OR cmdline LIKE '%.DownloadData%' OR cmdline LIKE '%.DownloadFile%' OR cmdline LIKE '%.DownloadString%' OR cmdline LIKE '%/c start /min%' OR cmdline LIKE '%FromBase64String%' OR cmdline LIKE '%mshta http%' OR cmdline LIKE '%mshta.exe http%') OR ((cmdline LIKE '%\AppData\%' AND cmdline LIKE '%\%AppData\%%' AND cmdline LIKE '%\%Temp\%%' AND cmdline LIKE '%\%tmp\%%' AND cmdline LIKE 'C:\Windows\Temp\%') AND (cmdline LIKE '%/xml C:\Users\%' AND cmdline LIKE '%cscript%' AND cmdline LIKE '%curl%' AND cmdline LIKE '%wscript%')))));

bool suspicious_command_patterns_in_scheduled_task_creation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\schtasks.exe") != std::string::npos && cmdline.find("/Create ") != std::string::npos) && (((cmdline.find("/sc minute ") != std::string::npos || cmdline.find("/ru system ") != std::string::npos) && (cmdline.find("cmd /c") != std::string::npos || cmdline.find("cmd /k") != std::string::npos || cmdline.find("cmd /r") != std::string::npos || cmdline.find("cmd.exe /c ") != std::string::npos || cmdline.find("cmd.exe /k ") != std::string::npos || cmdline.find("cmd.exe /r ") != std::string::npos)) || (cmdline.find(" -decode ") != std::string::npos || cmdline.find(" -enc ") != std::string::npos || cmdline.find(" -w hidden ") != std::string::npos || cmdline.find(" bypass ") != std::string::npos || cmdline.find(" IEX") != std::string::npos || cmdline.find(".DownloadData") != std::string::npos || cmdline.find(".DownloadFile") != std::string::npos || cmdline.find(".DownloadString") != std::string::npos || cmdline.find("/c start /min ") != std::string::npos || cmdline.find("FromBase64String") != std::string::npos || cmdline.find("mshta http") != std::string::npos || cmdline.find("mshta.exe http") != std::string::npos) || ((cmdline.find("\\AppData\\") != std::string::npos && cmdline.find("%%AppData%") != std::string::npos && cmdline.find("%Temp%") != std::string::npos && cmdline.find("%tmp%") != std::string::npos && cmdline.find("C:\\Windows\\Temp\\") != std::string::npos) && (cmdline.find("/xml C:\\Users\\") != std::string::npos && cmdline.find("cscript") != std::string::npos && cmdline.find("curl") != std::string::npos && cmdline.find("wscript") != std::string::npos))))
	{
		std::stringstream ss;

		ss << "Detected scheduled task creation using 'schtasks' that contain potentially suspicious or uncommon commands";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1053.005 - Schtasks Creation Or Modification With SYSTEM Privileges
//  SELECT * FROM win_process_events WHERE (path LIKE '%\schtasks.exe%' AND (cmdline LIKE '% /change %' OR cmdline LIKE '% /create %')) AND (cmdline LIKE '%/ru %') AND (cmdline LIKE '%NT AUT%' OR cmdline LIKE '% SYSTEM %') AND NOT (path LIKE '%\schtasks.exe%' AND (cmdline LIKE '%/TN TVInstallRestore%' AND cmdline LIKE '%\TeamViewer_.exe%')) AND NOT (cmdline LIKE '%/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR %' OR cmdline LIKE '%\Program Files (x86)\Avira\System Speedup\setup\avira_speedup_setup.exe%' OR cmdline LIKE '%/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART" /RL HIGHEST%');

bool schtasks_creation_or_modification_with_system_privileges(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\schtasks.exe") != std::string::npos && (cmdline.find(" /change ") != std::string::npos || cmdline.find(" /create ") != std::string::npos)) && (cmdline.find("/ru ") != std::string::npos) && (cmdline.find("NT AUT") != std::string::npos || cmdline.find(" SYSTEM ") != std::string::npos) && !(path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("/TN TVInstallRestore") != std::string::npos && cmdline.find("\\TeamViewer_.exe") != std::string::npos)) && !(cmdline.find("/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR ") != std::string::npos || cmdline.find("\\Program Files (x86)\\Avira\\System Speedup\\setup\\avira_speedup_setup.exe") != std::string::npos || cmdline.find("/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected scheduled task creation using 'schtasks' that contain potentially suspicious or uncommon commands";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Potential Powershell ReverseShell Connection
// SELECT * FROM win_process_events WHERE ((path LIKE '%powershell.exe%' OR path LIKE '%pwsh.exe%') AND (cmdline LIKE '%Net.Sockets.TCPClient%' AND cmdline LIKE '%.GetStream(%' AND cmdline LIKE '%.Write(%'));
// False Positive: In rare administrative cases, this function might be used to check network connectivity

bool potential_powershell_reverseShell_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("powershell.exe") != std::string::npos || path.find("pwsh.exe") != std::string::npos) && (cmdline.find("Net.Sockets.TCPClient") != std::string::npos && cmdline.find(".GetStream(") != std::string::npos && cmdline.find(".Write(") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected usage of the 'TcpClient' class. Which can be abused to establish remote connections and reverse-shell.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1059.001 - Suspicious File Execution From Internet Hosted WebDav Share
// SELECT * FROM win_process_events WHERE path LIKE '%\\cmd.exe%' AND cmdline LIKE '%net use http%' AND cmdline LIKE '%& start /b %' AND cmdline LIKE '%\\DavWWWRoot\\%' AND (cmdline LIKE '%.exe %' OR cmdline LIKE '%.dll %' OR cmdline LIKE '%.bat %' OR cmdline LIKE '%.vbs %' OR cmdline LIKE '%.ps1 %');

bool file_execution_internet_hosted_webdav_share(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\cmd.exe") != std::string::npos && cmdline.find(" net use http") != std::string::npos && cmdline.find("& start /b ") != std::string::npos && cmdline.find("\\DavWWWRoot\\") != std::string::npos && (cmdline.find(".exe ") != std::string::npos || cmdline.find(".dll ") != std::string::npos || cmdline.find(".bat ") != std::string::npos || cmdline.find(".vbs ") != std::string::npos || cmdline.find(".ps1 ") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected usage of net use command to mount a WebDav server";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - Suspicious CMD Shell Output Redirect
// SELECT * FROM win_process_events WHERE (path LIKE '%\\cmd.exe%' AND ((cmdline LIKE '%> \\Users\\Public\\%' OR cmdline LIKE '%APPDATA%\\%' OR cmdline LIKE '%> %TEMP%\\%' OR cmdline LIKE '%> %TMP%\\%' OR cmdline LIKE '%USERPROFILE%\\%' OR cmdline LIKE '%> C:\\Temp\\%' OR cmdline LIKE '%> C:\\Users\\Public\\%' OR cmdline LIKE '%> C:\\Windows\\Temp\\%' OR cmdline LIKE '>%\\Users\\Public\\%' OR cmdline LIKE '%APPDATA%\\%' OR cmdline LIKE '>%TEMP%\\%' OR cmdline LIKE '>%TMP%\\%' OR cmdline LIKE '>%USERPROFILE%\\%' OR cmdline LIKE '>C:\\Temp\\%' OR cmdline LIKE '>C:\\Users\\Public\\%' OR cmdline LIKE '>C:\\Windows\\Temp\\%') AND (cmdline LIKE '% >%' OR cmdline LIKE '%"%' OR cmdline LIKE '%'>%') AND (cmdline LIKE '%C:\\Users\\%' AND cmdline LIKE '%\\AppData\\Local\\%')));

bool cmd_shell_output_redirect(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\cmd.exe") != std::string::npos && (cmdline.find("> \\Users\\Public\\") != std::string::npos || cmdline.find("APPDATA%\\") != std::string::npos || cmdline.find("> %TEMP%\\") != std::string::npos || cmdline.find("> %TMP%\\") != std::string::npos || cmdline.find("USERPROFILE%\\") != std::string::npos || cmdline.find("> C:\\Temp\\") != std::string::npos || cmdline.find("> C:\\Users\\Public\\") != std::string::npos || cmdline.find("> C:\\Windows\\Temp\\") != std::string::npos || cmdline.find(">\\Users\\Public\\") != std::string::npos || cmdline.find("APPDATA%\\") != std::string::npos || cmdline.find(">%TEMP%\\") != std::string::npos || cmdline.find(">%TMP%\\") != std::string::npos || cmdline.find("USERPROFILE%\\") != std::string::npos || cmdline.find(">C:\\Temp\\") != std::string::npos || cmdline.find(">C:\\Users\\Public\\") != std::string::npos || cmdline.find(">C:\\Windows\\Temp\\") != std::string::npos) && (cmdline.find(" >") != std::string::npos || cmdline.find("\">") != std::string::npos || cmdline.find("'>") != std::string::npos) && (cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("\\AppData\\Local\\") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected inline Windows shell commands redirecting output via the > symbol to a suspicious location";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Unusual Parent Process For Cmd.EXE
//
bool suspicious_parent_process_cmd(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	if (path.find("\\cmd.exe") != std::string::npos && (parent_path.find("\\csrss.exe") != std::string::npos || parent_path.find("\\ctfmon.exe") != std::string::npos || parent_path.find("\\dllhost.exe") != std::string::npos || parent_path.find("\\epad.exe") != std::string::npos || parent_path.find("\\FlashPlayerUpdateService.exe") != std::string::npos || parent_path.find("\\GoogleUpdate.exe") != std::string::npos || parent_path.find("\\jucheck.exe") != std::string::npos || parent_path.find("\\jusched.exe") != std::string::npos || parent_path.find("\\LogonUI.exe") != std::string::npos || parent_path.find("\\lsass.exe") != std::string::npos || parent_path.find("\\regsvr32.exe") != std::string::npos || parent_path.find("\\SearchIndexer.exe") != std::string::npos || parent_path.find("\\SearchProtocolHost.exe") != std::string::npos || parent_path.find("\\SIHClient.exe") != std::string::npos || parent_path.find("\\sihost.exe") != std::string::npos || parent_path.find("\\slui.exe") != std::string::npos || parent_path.find("\\spoolsv.exe") != std::string::npos || parent_path.find("\\sppsvc.exe") != std::string::npos || parent_path.find("\\taskhostw.exe") != std::string::npos || parent_path.find("\\unsecapp.exe") != std::string::npos || parent_path.find("\\WerFault.exe") != std::string::npos || parent_path.find("\\wergmgr.exe") != std::string::npos || parent_path.find("\\wlanext.exe") != std::string::npos || parent_path.find("\\WUDFHost.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious parent process for cmd.exe";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}
// T1127 - Suspicious Use of CSharp Interactive Console
//
bool suspicious_csharp_interactive_console(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	if (path.find("\\csi.exe") != std::string::npos && (parent_path.find("\\powershell.exe") != std::string::npos || parent_path.find("\\pwsh.exe") != std::string::npos || parent_path.find("\\powershell_ise.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected the execution of CSharp interactive console by PowerShell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Potential Cookies Session Hijacking
//
bool cookies_session_hijacking(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("curl.exe") != std::string::npos && cmdline.find("--cookie-jar") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected execution of curl.exe with the -c flag in order to save cookie data.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Curl Web Request With Potential Custom User-Agent
//
bool curl_web_req_custom_user_agent(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("curl.exe") != std::string::npos && cmdline.find("User-Agent:") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected download or exfiltration data via curl";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - Potentially Suspicious Child Process Of DiskShadow.EXE
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\diskshadow.exe%' AND (path LIKE '%\\certutil.exe%' OR path LIKE '%\\cscript.exe%' OR path LIKE '%\\mshta.exe%' OR path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR path LIKE '%\\regsvr32.exe%' OR path LIKE '%\\rundll32.exe%' OR path LIKE '%\\wscript.exe%'));

bool suspicious_child_diskshadow(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	if (parent_path.find("\\diskshadow.exe") != std::string::npos && (path.find("\\certutil.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - Diskshadow Script Mode - Execution From Potential Suspicious Location
// SELECT * FROM win_process_events WHERE (path LIKE '%\\diskshadow.exe%' AND (cmdline LIKE '%/s %' OR cmdline LIKE '%-s %') AND (cmdline LIKE '%:\\Temp\\%' OR cmdline LIKE '%:\\Windows\\Temp\\%' OR cmdline LIKE '%\\AppData\\Local\\%' OR cmdline LIKE '%\\AppData\\Roaming\\%' OR cmdline LIKE '%\\ProgramData\\%' OR cmdline LIKE '%\\Users\\Public\\%'));

bool diskshadow_script_mode_suspicious_location(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("\\diskshadow.exe") != std::string::npos && (cmdline.find("/s ") != std::string::npos || cmdline.find("-s ") != std::string::npos) && (cmdline.find(":\\Temp\\") != std::string::npos || cmdline.find(":\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Local\\") != std::string::npos || cmdline.find("\\AppData\\Roaming\\") != std::string::npos || cmdline.find("\\ProgramData\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos))
	{
		std::stringstream ss;
		ss << "";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1543.003 - Potential Discovery Activity Via Dnscmd.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\dnscmd.exe%' AND (cmdline LIKE '%/enumrecords%' OR cmdline LIKE '%/enumzones%' OR cmdline LIKE '%/ZonePrint%' OR cmdline LIKE '%/info%'));

bool discovery_activity_dnscmd(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("\\dnscmd.exe") != std::string::npos && (cmdline.find("/enumrecords") != std::string::npos || cmdline.find("/enumzones") != std::string::npos || cmdline.find("/ZonePrint") != std::string::npos || cmdline.find("/info") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected an attempt to leverage dnscmd.exe to enumerate the DNS zones of a domain";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - Potentially Over Permissive Permissions Granted Using Dsacls.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\dsacls.exe%' AND cmdline LIKE '% /G %' AND (cmdline LIKE '%GR%' OR cmdline LIKE '%GE%' OR cmdline LIKE '%GW%' OR cmdline LIKE '%GA%' OR cmdline LIKE '%WP%' OR cmdline LIKE '%WD%'));

bool permissive_permissions_granted_dsacls(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("\\dsacls.exe") != std::string::npos && cmdline.find(" /G ") != std::string::npos && (cmdline.find("GR") != std::string::npos || cmdline.find("GE") != std::string::npos || cmdline.find("GW") != std::string::npos || cmdline.find("GA") != std::string::npos || cmdline.find("WP") != std::string::npos || cmdline.find("WD") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected usage of Dsacls to grant over permissive permissions";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - Potential Password Spraying Attempt Using Dsacls.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\dsacls.exe%' AND cmdline LIKE '%/user:%' AND cmdline LIKE '%/passwd:%');

bool potential_password_spraying_attempt_dsacls(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("\\dsacls.exe") != std::string::npos && cmdline.find("/user:") != std::string::npos && cmdline.find("/passwd:") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected possible password spraying attempts using Dsacls";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Fsutil Behavior Set SymlinkEvaluation
//
bool fsutil_behaviour_set_symlinkevaluation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("\\fsutil.exe") != std::string::npos && cmdline.find("behavior") != std::string::npos && cmdline.find("SymlinkEvaluation") != std::string::npos && cmdline.find("set") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected fsutil to set SymlinkEvaluation";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// TA002 - File Decryption Using Gpg4win
//
bool file_decryption_gpg4win(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\gpg.exe") != std::string::npos || path.find("\\gpg2.exe") != std::string::npos) && cmdline.find("-d") != std::string::npos && cmdline.find("passphrase") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected usage of Gpg4win to decrypt files";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// TA002 - File ENcryption Using Gpg4win
//
bool file_encryption_gpg4win(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\gpg.exe") != std::string::npos || path.find("\\gpg2.exe") != std::string::npos) && cmdline.find("-c") != std::string::npos && cmdline.find("passphrase") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected usage of Gpg4win to encrypt files";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// TA002 - File Encryption/Decryption Via Gpg4win From Suspicious Locations
//
bool file_encryption_decryption_gpg4win_locations(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\gpg.exe") != std::string::npos || path.find("\\gpg2.exe") != std::string::npos) && cmdline.find("-passphrase") != std::string::npos && (cmdline.find(":\\PerfLogs\\") != std::string::npos || cmdline.find(":\\Temp\\") != std::string::npos || cmdline.find(":\\Users\\Public\\") != std::string::npos || cmdline.find(":\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Roaming\\") != std::string::npos))

	{
		std::stringstream ss;
		ss << "Detected usage of Gpg4win to encrypt/decrypt files located in potentially suspicious locations";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - HackTool - Bloodhound/Sharphound Execution
//
bool hacktool_bloodhound_sharphound(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\Bloodhound.exe") != std::string::npos || path.find("\\SharpHound.exe") != std::string::npos) &&
			(cmdline.find(" -CollectionMethod All ") != std::string::npos ||
			 cmdline.find(" --CollectionMethods Session ") != std::string::npos ||
			 cmdline.find(" --Loop --Loopduration ") != std::string::npos ||
			 cmdline.find(" --PortScanTimeout ") != std::string::npos ||
			 cmdline.find(".exe -c All -d ") != std::string::npos ||
			 cmdline.find("Invoke-Bloodhound") != std::string::npos ||
			 cmdline.find("Get-BloodHoundData") != std::string::npos) ||
		(cmdline.find(" -JsonFolder ") != std::string::npos && cmdline.find(" -ZipFileName ") != std::string::npos) ||
		(cmdline.find(" DCOnly ") != std::string::npos && cmdline.find(" --NoSaveCache ") != std::string::npos))
	{

		std::stringstream ss;
		ss << "Detected command line parameters used by Bloodhound and Sharphound hack tools";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}
// T1059.003 - Operator Bloopers Cobalt Strike Commands
//
bool operator_bloopers_cobalt_strike_commands(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("cmd.exe") != std::string::npos && (cmdline.find("psinject") != std::string::npos || cmdline.find("spawnas") != std::string::npos || cmdline.find("make_token") != std::string::npos || cmdline.find("remote-exec") != std::string::npos || cmdline.find("rev2self") != std::string::npos || cmdline.find("dcsync") != std::string::npos || cmdline.find("logonpasswords") != std::string::npos || cmdline.find("execute-assembly") != std::string::npos || cmdline.find("getsystem") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected use of Cobalt Strike commands accidentally entered in the CMD shell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.003 - Operator Bloopers Cobalt Strike Modules
//
bool operator_bloopers_cobalt_strike_modules(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (path.find("cmd.exe") != std::string::npos && (cmdline.find("Invoke-UserHunter") != std::string::npos || cmdline.find("Invoke-ShareFinder") != std::string::npos || cmdline.find("Invoke-Kerberoast") != std::string::npos || cmdline.find("Invoke-SMBAutoBrute") != std::string::npos || cmdline.find("Invoke-Nightmare") != std::string::npos || cmdline.find("zerologon") != std::string::npos || cmdline.find("av_query") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected use of Cobalt Strike commands accidentally entered in the CMD shell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059 - Potential CobaltStrike Process Patterns
//
bool cobaltstrike_process_pattern(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string cmdline = process_event.entry.cmdline;
	if ((parent_path.find("\\runonce.exe") != std::string::npos || parent_path.find("\\dllhost.exe") != std::string::npos) && (cmdline.find("cmd.exe /c echo") != std::string::npos && cmdline.find("> \\\\.\\pipe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected potential process patterns related to Cobalt Strike beacon activity";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1059.001 - HackTool - Covenant PowerShell Launcher
//
bool hacktool_convenant_powershell_launcher(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-Sta") != std::string::npos && cmdline.find("-Nop") != std::string::npos &&
			cmdline.find("-Window") != std::string::npos && cmdline.find("Hidden") != std::string::npos &&
			(cmdline.find("-Command") != std::string::npos || cmdline.find("-EncodedCommand") != std::string::npos) ||
		(cmdline.find("sv o (New-Object IO.MemorySteam);sv d ") != std::string::npos ||
		 cmdline.find("mshta file.hta") != std::string::npos ||
		 cmdline.find("GruntHTTP") != std::string::npos ||
		 cmdline.find("-EncodedCommand cwB2ACAAbwAgA") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious command lines used in Covenant luanchers";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1218 - WSL Child Process Anomaly medium
//
bool wsl_child_process_anomaly(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	if ((parent_path.find("\\wsl.exe") != std::string::npos ||
		 parent_path.find("\\wslhost.exe") != std::string::npos) &&
			((path.find("\\calc.exe") != std::string::npos ||
			 path.find("\\cmd.exe") != std::string::npos ||
			 path.find("\\cscript.exe") != std::string::npos ||
			 path.find("\\mshta.exe") != std::string::npos ||
			 path.find("\\powershell.exe") != std::string::npos ||
			 path.find("\\pwsh.exe") != std::string::npos ||
			 path.find("\\regsvr32.exe") != std::string::npos ||
			 path.find("\\rundll32.exe") != std::string::npos ||
			 path.find("\\wscript.exe") != std::string::npos) ||
		(path.find("\\AppData\\Local\\Temp\\") != std::string::npos ||
		 path.find("C:\\Users\\Public\\") != std::string::npos ||
		 path.find("C:\\Windows\\Temp\\") != std::string::npos ||
		 path.find("C:\\Temp\\") != std::string::npos ||
		 path.find("\\Downloads\\") != std::string::npos ||
		 path.find("\\Desktop\\") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Detected uncommon or suspicious child processes spawning from a WSL process";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


//Qakbot - rundll32 execution of Qakbot in non-standard file extension

bool qakbot_rundll32_non_standard(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
	if (path.find("rundll32.exe") != std::string::npos &&
    !(cmdline.find(".dll") != std::string::npos || 
      cmdline.find(".cpl") != std::string::npos || 
      cmdline.find(".ax") != std::string::npos || 
      cmdline.find(".ocx") != std::string::npos || 
      cmdline.find(".inf") != std::string::npos ||
	  cmdline.find(".DLL") != std::string::npos || 
      cmdline.find(".CPL") != std::string::npos || 
      cmdline.find(".AX") != std::string::npos || 
      cmdline.find(".OCX") != std::string::npos || 
      cmdline.find(".INF") != std::string::npos)) {
    std::stringstream ss;
		ss << " Detected the mid-stage execution of Qakbot from rundll32 executing another Qakbot with a non-standard file extension";
		rule_event.metadata = ss.str();
		return true;
}
return false;

}

// T1136.001 - DarkGate Persistence
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\net.exe%' OR path LIKE '%\\net1.exe%') AND (cmdline LIKE '%user%' AND cmdline LIKE '%add%' AND cmdline LIKE '%DarkGate%' AND cmdline LIKE '%SafeMode%'));

bool darkgate_persistence(const ProcessEvent &process_event, Event &rule_event)
{

    if ((process_event.entry.path.find("\\net.exe") != std::string::npos ||
         process_event.entry.path.find("\\net1.exe") != std::string::npos) &&
        (process_event.entry.cmdline.find("user") != std::string::npos &&
         process_event.entry.cmdline.find("add") != std::string::npos &&
         process_event.entry.cmdline.find("DarkGate") != std::string::npos &&
         process_event.entry.cmdline.find("SafeMode") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected creation of local users via the net.exe command with the name of 'DarkGate'";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1218.010 - Emotet - Parent-Child process tree execution
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%excel.exe%' AND path LIKE '%regsvr32.exe%');

bool emotet_parent_child_process_tree_execution(const ProcessEvent &process_event, Event &rule_event)
{

    if (process_event.entry.parent_path.find("excel.exe") != std::string::npos and process_event.entry.path.find("regsvr32.exe") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the parent-child process tree from Emotet";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1047 - Impacket - Execution
// SELECT * FROM win_process_events WHERE ((parent_path LIKE '%wmiprvse.exe%' OR parent_path LIKE '%services.exe%') AND path LIKE '%cmd.exe%' AND (cmdline LIKE '%/Q%' OR cmdline LIKE '%echo%' OR cmdline LIKE '%&1%'));

bool impacket_execution(const ProcessEvent &process_event, Event &rule_event)
{

    if ((process_event.entry.parent_path.find("wmiprvse.exe") != std::string::npos || process_event.entry.parent_path.find("services.exe") != std::string::npos) && process_event.entry.path.find("cmd.exe") != std::string::npos && (process_event.entry.cmdline.find("/Q") != std::string::npos || process_event.entry.cmdline.find("echo") != std::string::npos || process_event.entry.cmdline.find("&1") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the process wmiprvse.exe responsible for WMI on target host, or services.exe spawning cmd.exe";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// TA0006 - Mimikatz execution of common modules
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%sekurlsa::logonpasswords%' OR cmdline LIKE '%lsadump::sam%' OR cmdline LIKE '%sekurlsa::minidump%');

bool mimikatz_execution_of_common_modules(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.cmdline.find("sekurlsa::logonpasswords") != std::string::npos || process_event.entry.cmdline.find("lsadump::sam") != std::string::npos || process_event.entry.cmdline.find("sekurlsa::minidump") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the most common Mimikatz modules in command line";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1573 - Pikabot - C2
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\rundll32.exe%' AND (path LIKE '%\\SearchFilterHost.exe%' OR path LIKE '%\\SearchProtocolHost.exe%' OR path LIKE '%\\sndvol.exe%' OR path LIKE '%\\wermgr.exe%' OR path LIKE '%\\wwahost.exe%'));

bool pikabot_C2(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.parent_path.find("\\rundll32.exe") != std::string::npos &&
        (process_event.entry.path.find("\\SearchFilterHost.exe") != std::string::npos || process_event.entry.path.find("\\SearchProtocolHost.exe") != std::string::npos || process_event.entry.path.find("\\sndvol.exe") != std::string::npos || process_event.entry.path.find("\\wermgr.exe") != std::string::npos || process_event.entry.path.find("\\wwahost.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of rundll32 that leads to an external network connection. The malware Pikabot has been seen to use this technique.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

//3LOSH, AsyncRAT, Execution, T1059.001 - Execution tree of 3LOSH malware to spawn AsyncRAT
bool asyncrat_3losh_malware(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("wscript.exe") != std::string::npos && path.find("powershell.exe") != std::string::npos && (cmdline.find("iex") != std::string::npos || cmdline.find(".invoke") != std::string::npos || cmdline.find("invoke-expression") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution pattern related to 3LOSH spawning AsyncRAT";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

//Cobalt Strike - Usage of common named pipes
bool cobalt_strike_common_pipes(const ProcessEvent &process_event, Event &rule_event)
{
        std::string action = process_event.entry.action;
        std::string target_path = process_event.entry.target_path;
    if (action.find("FILE_WRITE") != std::string::npos && (target_path.find("pipe\\msagent_") != std::string::npos || target_path.find("pipe\\interprocess_") != std::string::npos || target_path.find("pipe\\lsarpc_") != std::string::npos || target_path.find("pipe\\srvsvc_") != std::string::npos || target_path.find("pipe\\wkssvc_") != std::string::npos || target_path.find("pipe\\netlogon_") != std::string::npos || target_path.find("pipe\\samr_") != std::string::npos || target_path.find("pipe\\msse-") != std::string::npos || target_path.find("pipe\\status_") != std::string::npos || target_path.find("pipe\\postex") != std::string::npos || target_path.find("pipe\\mojo_") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the usage of common named pipes used by Cobalt Strike.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}
//Cobalt Strike - Usage of DLL search order hijacking to spawn SQL Server Client Config utility
bool cobalt_strike_sql_server_client_config(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("rundll32.exe") != std::string::npos && path.find("cliconfg.exe") !=std::string::npos )
    {
        std::stringstream ss;
        ss << "Detected the usage of DLL search order hijacking used by CS to bypass UAC by spawning SQL server client config utility";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}
//Cobalt Strike - Usage of GetSystem feature via SYSTEM token impersonation.
//
bool cobalt_strike_getsystem(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (path.find("cmd.exe") != std::string::npos && cmdline.find("echo *\\\\.\\pipe\\*") !=std::string::npos )
    {
        std::stringstream ss;
        ss << " Detected the usage of GetSystem feature from CS via SYSTEM token impersonation";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

//Darkgate - C2, T1105 Autoit3.exe file creation by uncommon process
//(((process_name:Autoit3.exe OR original_filename:AutoIt3.exe) AND (parent_name:cmd.exe OR parent_name:KeyScramblerLogon.exe OR parent_name:msiexec.exe)) AND -(path:":\Program\ Files\ (x86)\AutoIt3\AutoIt3.exe" OR path:":\Program\ Files\AutoIt3\AutoIt3.exe"))
bool darkgate_autoit3_uncommon_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (cmdline.find("Autoit3.exe") != std::string::npos && (parent_path.find("cmd.exe") != std::string::npos || parent_path.find("KeyScramblerLogon.exe") !=std::string::npos || parent_path.find("msiexec.exe") !=std::string::npos) && !(path.find("\\Program\\Files\\(x86)\\AutoIt3\\AutoIt3.exe") != std::string::npos || path.find("\\Program\\Files\\AutoIt3\\AutoIt3.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of the legitimate Autoit3 utility from a suspicious parent process and location";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1047 - WinRM usage
// SELECT * FROM process_events WHERE parent_path LIKE '%wmiprvse.exe%' AND NOT (path LIKE '%msiexec.exe%' OR path LIKE '%ccmdump.exe%' OR path LIKE '%werfault.exe%');

bool winrm_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("wmiprvse.exe") != std::string::npos && !(path.find("msiexec.exe") != std::string::npos || path.find("ccmdump.exe") != std::string::npos || path.find("werfault.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected WinRM usage";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1047 - Process creation via WMI usage
// SELECT * FROM process_events WHERE path LIKE '%wmic.exe%' AND cmdline LIKE '%process%' AND cmdline LIKE '%create%';

bool process_creation_via_wmi_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("WMIC.exe") != std::string::npos && cmdline.find("process") != std::string::npos && cmdline.find("create") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Process creation via WMI usage";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1204.002 - Suspicious processes spawned by Office or user application
// SELECT * FROM process_events WHERE (path LIKE '%cmd.exe%' OR path LIKE '%powershell.exe%' OR path LIKE '%cscript.exe%' OR path LIKE '%wscript.exe%' OR path LIKE '%bitsadmin.exe%' OR path LIKE '%certutil.exe%' OR path LIKE '%curl.exe%' OR path LIKE '%mshta.exe%' OR path LIKE '%rundll32.exe%' OR path LIKE '%regsvr32.exe%' OR path LIKE '%schtasks.exe%' OR path LIKE '%wmic.exe%') AND (parent_path LIKE '%winword.exe%' OR parent_path LIKE '%excel.exe%' OR parent_path LIKE '%wordpad.exe%' OR parent_path LIKE '%visio.exe%' OR parent_path LIKE '%powerpnt.exe%' OR parent_path LIKE '%onenote.exe%' OR parent_path LIKE '%mspub.exe%');

bool suspicious_processes_spawned_by_office_or_user_application(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if ((path.find("cmd.exe") != std::string::npos || path.find("powershell.exe") != std::string::npos || path.find("cscript.exe") != std::string::npos || path.find("wscript.exe") != std::string::npos || path.find("bitsadmin.exe") != std::string::npos || path.find("certutil.exe") != std::string::npos || path.find("curl.exe") != std::string::npos || path.find("mshta.exe") != std::string::npos || path.find("rundll32.exe") != std::string::npos || path.find("regsvr32.exe") != std::string::npos || path.find("schtasks.exe") != std::string::npos || path.find("wmic.exe") != std::string::npos) && (parent_path.find("winword.exe") != std::string::npos || parent_path.find("excel.exe") != std::string::npos || parent_path.find("wordpad.exe") != std::string::npos || parent_path.find("visio.exe") != std::string::npos || parent_path.find("powerpnt.exe") != std::string::npos || parent_path.find("onenote.exe") != std::string::npos || parent_path.find("mspub.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Suspicious processes spawned by Office or user application";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1569.002 - Suspcious sc.exe spawned by CLI
// SELECT * FROM process_events WHERE (path LIKE '%sc.exe%') AND (parent_path LIKE '%cmd.exe%' OR parent_path LIKE '%powershell.exe%');

bool suspicious_sc_exe_spawned_by_cli(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if ((path.find("sc.exe") != std::string::npos) && (parent_path.find("cmd.exe") != std::string::npos || parent_path.find("powershell.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Suspcious sc.exe spawned by CLI";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}