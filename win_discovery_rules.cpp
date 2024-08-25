#include "win_discovery_rules.h"
#include <sstream>

// DISCOVERY

// T1615: Group Policy Discovery
// select path, parent_path, cmdline  from win_process_events where cmdline like '%gpresult%' or cmdline like '%Get-DomainGPO%' or cmdline like '%GPOAudit%' or cmdline like '%GPORemoteAccessPolicy%' or cmdline like '%Get-GPO%';

bool group_policy_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("gpresult") != std::string::npos || cmdline.find("Get-DomainGPO") != std::string::npos || cmdline.find("GPOAudit") != std::string::npos || cmdline.find("GPORemoteAccessPolicy") != std::string::npos || cmdline.find("Get-GPO") != std::string::npos)
	{
		rule_event.metadata = "Group policies may be discovered";
		return true;
	}
	return false;
}

// T1087.002 -  Account Discovery: Domain Account
//  select * from win_process_events where (path like '%powershell%' or path like '%net.exe%') and (cmdline like '%net user%' or cmdline like '%net  group%');

bool account_discovery_domain_account(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;

	if ((path.find("powershell.exe") != std::string::npos || path.find("net.exe") != std::string::npos) && (cmdline.find("net user") != std::string::npos || cmdline.find("net  group") != std::string::npos))
	{

		std::stringstream ss;
		ss << "Attempt to get listing of domain accounts";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1217 - Browser Information Discovery
//  select * from win_process_events where (cmdline like '%where%' and cmdline like '%Bookmarks%') or (cmdline like '%where%' and cmdline like '%places.sqlite%');

bool browser_information_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("where") != std::string::npos && cmdline.find("Bookmarks") != std::string::npos) || (cmdline.find("where") != std::string::npos && cmdline.find("places.sqlite") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Information about browsers enumerated";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1082 - System Information Discovery
//  select * from win_process_events where path like '%reg.exe%' and cmdline like '%reg%' and cmdline like '%query%' and cmdline like '%SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum%';
// bool system_information_discovery(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;
// 	std::string path = process_event.entry.path;

// 	if (path.find("reg.exe") != std::string::npos && cmdline.find("reg") != std::string::npos && cmdline.find("query") != std::string::npos && cmdline.find("SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum") != std::string::npos)
// 	{
// 		std::stringstream ss;
// 		ss << "Information about the system compromised";
// 		rule_event.metadata = ss.str();
// 		return true;
// 	}
// 	return false;
// }

// T1482 - Domain Trust Discovery
//  select * from win_process_events where (cmdline like '%forest%' and cmdline like '%userdomain%') or cmdline like '%Get-ForestTrust%' or cmdline like '%Get-DomainTrust%';

bool domain_trust_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("forest") != std::string::npos && cmdline.find("userdomain") != std::string::npos) || cmdline.find("Get-ForestTrust") != std::string::npos || cmdline.find("Get-DomainTrust") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Attempt to gather information using domain trust relationships";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1083 - File and Directory Discovery
//  select * from win_process_events where cmdline like '%folderarray%' and cmdline like '%Get-ChildItem%';

bool file_and_directory_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("folderarray") != std::string::npos && cmdline.find("Get-ChildItem") != std::string::npos)
	{
		std::stringstream ss;
		ss << "";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1518.001 - Software Discovery: Security Software Discovery
//  select * from win_process_events where (path like '%findstr%' and cmdline like '%findstr%' and cmdline like '%virus%') or (path like '%cmd.exe%' and cmdline like '%netsh.exe%' and cmdline like '%tasklist%' and cmdline like '%findstr%' and cmdline like '%virus%');
bool win_security_software_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("findstr.exe") != std::string::npos && cmdline.find("findstr") != std::string::npos && cmdline.find("virus") != std::string::npos) || (path.find("cmd.exe") != std::string::npos && cmdline.find("netsh.exe") != std::string::npos && cmdline.find("tasklist.exe") != std::string::npos && cmdline.find("findstr") != std::string::npos && cmdline.find("virus") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Information from security software discovery used for malicious purpose";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1614.001 - System Location Discovery: System Language Discovery, Discover System Language with chcp

bool discover_system_language_chcp(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("chcp.com") != std::string::npos && cmdline.find("chcp") != std::string::npos)
	{
		std::stringstream ss;
		ss << "System language identified using chcp";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1049 - Use Get-NetTCPConnection
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Get-NetTCPConnection%'

bool use_get_net_tcp_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("gpresult") != std::string::npos || cmdline.find("Get-DomainGPO") != std::string::npos || cmdline.find("GPOAudit") != std::string::npos || cmdline.find("GPORemoteAccessPolicy") != std::string::npos || cmdline.find("Get-GPO") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Group policies may be discovered";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1069.001 - Suspicious Get Local Groups Information
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%get-localgroup%' and cmdline like '%Get-LocalGroupMember%'
bool suspicious_get_local_groups_information(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("get-localgroup") != std::string::npos && cmdline.find("Get-LocalGroupMember") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Local groups information may have been discovered";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1018 - DirectorySearcher Powershell Exploitation
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%New-Object%' and cmdline like '%System.DirectoryServices.DirectorySearcher%'
bool directorySearcher_powershell_exploitation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("get-localgroup") != std::string::npos && cmdline.find("Get-LocalGroupMember") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Local groups information may have been discovered";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1018 - Active Directory Computers Enumeration with Get-AdComputer
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Get-AdComputer%' and cmdline like '%-Filter%'
bool active_directory_computers_enumeration_with_get_AdComputer(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-AdComputer") != std::string::npos && cmdline.find("-Filter") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Enumerate Computers within Active Directory.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1069.002 - Active Directory Computers Enumeration with Get-AdGroup
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Get-AdComputer%' and cmdline like '%-Filter%'
bool active_directory_computers_enumeration_with_get_AdGroup(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-AdGroup") != std::string::npos && cmdline.find("-Filter") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Enumerate Groups within Active Directory";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1518.001 - Security Software Discovery by Powershell
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%get-process%' and cmdline like '%.Description%' and cmdline like '%-like%' and (cmdline like '%*virus*%' or cmdline like '%*defender*%' or cmdline like '%*cylance*%' or cmdline like '%*mc*%'));
bool security_software_discovery_by_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("get-process") != std::string::npos && cmdline.find(".Description") != std::string::npos && cmdline.find("-like") != std::string::npos && (cmdline.find("*virus*") != std::string::npos || cmdline.find("*defender*") != std::string::npos || cmdline.find("*cylance*") != std::string::npos || cmdline.find("*mc*") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Listing of security software, configurations, defensive tools, and sensors that are installed on a system might be extracted";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1518 - Detected Windows Software Discovery - PowerShell
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Get-ItemProperty%' and cmdline like '%:\\SOFTWARE%' and cmdline like '%select-object%' and cmdline like '%format-table%');
bool windows_software_discovery_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-ItemProperty") != std::string::npos && cmdline.find(":\\SOFTWARE") != std::string::npos && cmdline.find("select-object") != std::string::npos && cmdline.find("format-table") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected windows software";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1201 - Password Policy Discovery With Get-AdDefaultDomainPasswordPolicy
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%get-addefaultdomainpasswordpolicy%');
bool password_policy_discovery_with_Get_AdDefaultDomainPasswordPolicy(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("get-addefaultdomainpasswordpolicy") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detailed information about the password policy is exposed";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1033 - Suspicious PowerShell Get Current User
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%[System.Environment]::UserName%' and cmdline like '%[System.Security.Principal.WindowsIdentity]::GetCurrent()%');
bool suspicious_powershell_get_current_user(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("[System.Environment]::UserName") != std::string::npos && cmdline.find("[System.Security.Principal.WindowsIdentity]::GetCurrent()") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Primary user has been discovered";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1057 - Suspicious Process Discovery With Get-Process
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Get-Process%');
bool suspicious_process_discovery_with_get_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-Process") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Powershell discovered with get-process, information about running processes on the system might be exposed";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1120 - Powershell Suspicious Win32_PnPEntity
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Get-WMIObject%' and cmdline like '%Win32_PnPEntity%');
bool powershell_suspicious_win32_PnPEntity(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-WMIObject") != std::string::npos && cmdline.find("Win32_PnPEntity") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Information about attached peripheral devices and components connected to a computer system might be exposed";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// DISCOVERY RULES

// T1069.001 - Suspicious Get Information for SMB Share - PowerShell Module
// select path, parent_path, cmdline  from win_process_events where cmdline like '%get-smbshare%';

bool suspicious_get_information_for_SMB_share_powershell_module(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("get-smbshare") != std::string::npos)
	{
		rule_event.metadata = "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information"; // To be reviewed
		return true;
	}
	return false;
}

// T1069.002 - Get-ADUser Enumeration Using UserAccountControl Flags
// select * from win_process_events where cmdline like '%Get-ADUser%' and cmdline like '%-Filter%' and cmdline like '%useraccountcontrol%';

bool get_ADUser_enumeration_using_UserAccountControl_flags(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Get-ADUser") != std::string::npos && cmdline.find("-Filter") != std::string::npos && cmdline.find("useraccountcontrol") != std::string::npos)
	{
		rule_event.metadata = "Get-ADUser Enumeration Using UserAccountControl Flags"; // To be reviewed
		return true;
	}
	return false;
}

// T1033 - Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell
// select * from win_process_events where cmdline like '%Get-ADComputer%' and cmdline like '%-Filter%';

bool computer_discovery_and_export_via_get_ADComputer_cmdlet_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Get-ADComputer") != std::string::npos && cmdline.find("-Filter") != std::string::npos)
	{
		rule_event.metadata = "Computer Discovery And Export Via Get-ADComputer Cmdlet"; // To be reviewed
		return true;
	}
	return false;
}

// T1083 - Powershell Sensitive File Discovery
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%-recurse%' and cmdline like '%get-childitem%' and cmdline like '%gci%';

bool powershell_sensitive_file_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("-recurse") != std::string::npos && cmdline.find("get-childitem") != std::string::npos && cmdline.find("gci") != std::string::npos)
	{
		rule_event.metadata = "Files and folders on the machine have been exposed.";
		return true;
	}
	return false;
}

// T1069.001 - AD Groups Or Users Enumeration Using PowerShell - ScriptBlock
// select * from win_process_events where cmdline like '%get-aduser%' and cmdline like '%-f%' and cmdline like '%-pr%';

bool ad_groups_or_users_enumeration_using_powershell_scriptblock(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("get-aduser") != std::string::npos && cmdline.find("-f") != std::string::npos && cmdline.find("-pr") != std::string::npos)
	{
		rule_event.metadata = "Domain-level groups and permission settings have been discovered.";
		return true;
	}
	return false;
}

// T1087.001 - Suspicious Group And Account Reconnaissance Activity Using Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or cmdline like '%\\net1.exe%') and (((cmdline like '% group%' or cmdline like '% localgroup%') and (cmdline like '%domain admins%' or cmdline like '%administrator%' or cmdline like '%administrateur%' or cmdline like '%enterprise admins%' or cmdline like '%Exchange Trusted Subsystem%' or cmdline like '%Remote Desktop Users%' or cmdline like '%Utilisateurs du Bureau à distance%' or cmdline like '%Usuarios de escritorio remoto%') and not cmdline like '%/add%') or (cmdline like '%accounts%' and cmdline like '%/do%)));

bool suspicious_group_and_account_reconnaissance_activity_using_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || cmdline.find("\\net1.exe") != std::string::npos) && (((cmdline.find(" group") != std::string::npos || cmdline.find(" localgroup") != std::string::npos) && (cmdline.find("domain admins") != std::string::npos || cmdline.find(" administrator") != std::string::npos || cmdline.find(" administrateur") != std::string::npos || cmdline.find("enterprise admins") != std::string::npos || cmdline.find("Exchange Trusted Subsystem") != std::string::npos || cmdline.find("Remote Desktop Users") != std::string::npos || cmdline.find("Utilisateurs du Bureau à distance") != std::string::npos || cmdline.find("Usuarios de escritorio remoto") != std::string::npos) && !(cmdline.find("/add") != std::string::npos)) || (cmdline.find("accounts") != std::string::npos && cmdline.find("/do") != std::string::npos)))
	{
		rule_event.metadata = "Suspicious Group And Account Reconnaissance Activity Using Net.EXE";
		return true;
	}
	return false;
}

// T1049 - System Network Connections Discovery Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and (cmdline like '% use%' or cmdline like '% sessions%'));

bool system_network_connections_discovery_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && (cmdline.find(" use") != std::string::npos || cmdline.find(" sessions") != std::string::npos))
	{
		rule_event.metadata = "System Network Connections Discovery Via Net.EXE";
		return true;
	}
	return false;
}

// T1018 - Share And Session Enumeration Using Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and (cmdline like '%view%' or cmdline like '%\\\\\\\\%'));

bool share_and_session_enumeration_using_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && (cmdline.find("view") != std::string::npos || cmdline.find("\\\\\\\\") != std::string::npos))
	{
		rule_event.metadata = "Share And Session Enumeration Using Net.EXE";
		return true;
	}
	return false;
}

// T1018 - Adidnsdump Execution
// select * from win_process_events where cmdline like '%adidnsdump%' and path like '%\python.exe%';
bool adidnsdump_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\python.exe") != std::string::npos && cmdline.find("adidnsdump") != std::string::npos)
	{
		rule_event.metadata = "Execution of Adidnsdump tool has been detected to Query/modify DNS records";
		return true;
	}
	return false;
}

// T1007 - Net.exe Execution
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and (cmdline like '% group%' or cmdline like '% localgroup%' or cmdline like '% user%' or cmdline like '% view%' or cmdline like '% share%' or cmdline like '% accounts%' or cmdline like '% stop%' or cmdline like '% start%'));

bool net_exe_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && (cmdline.find(" group") != std::string::npos || cmdline.find(" localgroup") != std::string::npos || cmdline.find(" user") != std::string::npos || cmdline.find(" view") != std::string::npos || cmdline.find(" share") != std::string::npos || cmdline.find(" accounts") != std::string::npos || cmdline.find(" stop") != std::string::npos || cmdline.find(" start") != std::string::npos))
	{
		rule_event.metadata = "Net.exe Execution";
		return true;
	}
	return false;
}

// T1016 - Suspicious Firewall Configuration Discovery Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' OR cmdline LIKE '%netsh%' AND cmdline LIKE '%show%' AND cmdline LIKE '%firewall%' AND (cmdline LIKE '%config%' OR cmdline LIKE '%state%' OR cmdline LIKE '%rule%' OR cmdline LIKE '%name=all%'));

bool suspicious_firewall_configuration_discovery_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\netsh.exe") != std::string::npos && cmdline.find("netsh") != std::string::npos && cmdline.find("show") != std::string::npos && cmdline.find("firewall") != std::string::npos && (cmdline.find("config") != std::string::npos || cmdline.find("state") != std::string::npos || cmdline.find("rule") != std::string::npos || cmdline.find("name=all") != std::string::npos))
	{
		rule_event.metadata = "Suspicious Firewall Configuration Discovery Via Netsh.EXE";
		return true;
	}
	return false;
}

// T1040 - New Network Trace Capture Started Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND cmdline LIKE '%trace%' AND cmdline LIKE '%start%');

bool new_network_trace_capture_started_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\netsh.exe") != std::string::npos && cmdline.find("trace") != std::string::npos && cmdline.find("start") != std::string::npos)
	{
		rule_event.metadata = "New Network Trace Capture Started Via Netsh.EXE";
		return true;
	}
	return false;
}

// T1615 - Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS
// SELECT * FROM win_process_events WHERE cmdline LIKE '%gatherNetworkInfo.vbs%' AND (path LIKE '%\\cscript.exe%' OR path LIKE '%\\wscript.exe%');

bool suspicious_reconnaissance_activity_via_GatherNetworkInfo_VBS(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	{
		rule_event.metadata = "Detected execution of a built-in script that could be used to gather information about the target machine.";
		return true;
	}
	return false;
}

// T1033 - Local Accounts Discovery
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/c%' AND cmdline LIKE '%whoami%' AND cmdline LIKE '%wmic%' AND cmdline LIKE '%useraccount%' AND cmdline LIKE '%get%' AND cmdline LIKE '%quser%' AND cmdline LIKE '%qwinsta%' AND cmdline LIKE '%/F%';

bool local_accounts_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("/c") != std::string::npos && cmdline.find("whoami") != std::string::npos && cmdline.find("wmic") != std::string::npos && cmdline.find("useraccount") != std::string::npos && cmdline.find("get") != std::string::npos && cmdline.find("quser") != std::string::npos && cmdline.find("qwinsta") != std::string::npos && cmdline.find("/F") != std::string::npos)
	{
		rule_event.metadata = "Local accounts, System Owner/User discovery has been done using operating systems utilities";
		return true;
	}
	return false;
}

// T1016 - Suspicious Network Command
// SELECT * FROM win_process_events WHERE cmdline LIKE '%ipconfig /all%' AND cmdline LIKE '%netsh%' AND cmdline LIKE '%show interface%' AND cmdline LIKE '%arp -a%' AND cmdline LIKE '%nbtstat%' AND cmdline LIKE '%net config%';

bool suspicious_network_command(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("ipconfig /all") != std::string::npos && cmdline.find("netsh") != std::string::npos && cmdline.find("show interface") != std::string::npos && cmdline.find("arp -a") != std::string::npos && cmdline.find("nbtstat") != std::string::npos && cmdline.find("net config") != std::string::npos)
	{
		rule_event.metadata = "Details about the network configuration and settings of systems might be discovered";
		return true;
	}
	return false;
}

// T1018 - Suspicious Scan Loop Network
// SELECT * FROM win_process_events WHERE cmdline LIKE '%localip%' AND cmdline LIKE '%ipconfig%' AND (cmdline LIKE '%for%' OR cmdline LIKE '%foreach%') AND cmdline LIKE '%nslookup%' AND cmdline LIKE '%$ip%';

bool suspicious_scan_loop_network(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("localip") != std::string::npos && cmdline.find("ipconfig") != std::string::npos && (cmdline.find("for") != std::string::npos || cmdline.find("foreach") != std::string::npos) && cmdline.find("nslookup") != std::string::npos && cmdline.find("$ip") != std::string::npos)
	{
		rule_event.metadata = "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system"; // To be reviewed
		return true;
	}
	return false;
}

// T1082 - Suspicious Query of MachineGUID
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND cmdline LIKE '%SOFTWARE\Microsoft\Cryptography%' AND cmdline LIKE '%/v %' AND cmdline LIKE '%MachineGuid%';

bool suspicious_query_of_machineguid(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\reg.exe") != std::string::npos && cmdline.find("SOFTWARE\\Microsoft\\Cryptography") != std::string::npos && cmdline.find("/v ") != std::string::npos && cmdline.find("MachineGuid") != std::string::npos)
	{
		rule_event.metadata = "Detected use of reg.exe to get MachineGuid information";
		return true;
	}
	return false;
}

// T1012 - Potential Configuration And Service Reconnaissance Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND cmdline LIKE '%query%' AND (cmdline LIKE '%currentVersion\windows%' OR cmdline LIKE '%winlogon\%' OR cmdline LIKE '%currentVersion\shellServiceObjectDelayLoad%' OR cmdline LIKE '%currentVersion\run%' OR cmdline LIKE '%currentVersion\policies\explorer\run%' OR cmdline LIKE '%currentcontrolset\services%');

bool configuration_and_service_reconnaissance_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\reg.exe") != std::string::npos && cmdline.find("query") != std::string::npos && (cmdline.find("currentVersion\\windows") != std::string::npos || cmdline.find("winlogon\\") != std::string::npos || cmdline.find("currentVersion\\shellServiceObjectDelayLoad") != std::string::npos || cmdline.find("currentVersion\\run") != std::string::npos || cmdline.find("currentVersion\\policies\\explorer\\run") != std::string::npos || cmdline.find("currentcontrolset\\services") != std::string::npos))
	{
		rule_event.metadata = "Detected use of reg.exe to query reconnaissance information from the registry";
		return true;
	}
	return false;
}

// T1027 - Obfuscated IP Download
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%Invoke-WebRequest%' AND cmdline LIKE '%iwr%' AND cmdline LIKE '%wget%' AND cmdline LIKE '%curl%' AND cmdline LIKE '%DownloadFile%' AND cmdline LIKE '%DownloadString%') AND (cmdline LIKE '%//0x%' OR cmdline LIKE '%.0x%' OR cmdline LIKE '%.00x%') AND (cmdline LIKE '%http://%2e%'));

bool obfuscated_IP_download(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("Invoke-WebRequest") != std::string::npos &&
		 cmdline.find("iwr ") != std::string::npos &&
		 cmdline.find("wget ") != std::string::npos &&
		 cmdline.find("curl ") != std::string::npos &&
		 cmdline.find("DownloadFile") != std::string::npos &&
		 cmdline.find("DownloadString") != std::string::npos) &&
		(cmdline.find("//0x") != std::string::npos ||
		 cmdline.find(".0x") != std::string::npos ||
		 cmdline.find(".00x") != std::string::npos) &&
		(cmdline.find("http://%") != std::string::npos &&
		 cmdline.find("%2e") != std::string::npos))
	{
		rule_event.metadata = "Detected use of obfuscated version of an IP address";
		return true;
	}
	return false;
}

// T1027 - Obfuscated IP Download
// SELECT * FROM win_process_events WHERE cmdline LIKE '%.exe whoami%';

bool whoami_as_parameter(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find(".exe whoami") != std::string::npos)
	{
		rule_event.metadata = "Detected a suspicious process command line that uses whoami as first parameter";
		return true;
	}
	return false;
}

// HackTool - SharpLDAPmonitor Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/user:%' AND cmdline LIKE '%/pass:%' AND cmdline LIKE '%/dcip:%';

bool hacktool_sharpldapmonitor_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\SharpLDAPmonitor.exe") != std::string::npos) && cmdline.find("/user:") != std::string::npos && cmdline.find("/pass:") != std::string::npos && cmdline.find("/dcip:") != std::string::npos)
	{
		rule_event.metadata = "SharpLDAPmonitor execution detected !";
		return true;
	}
	return false;
}

// T1069.001 - Permission Check Via Accesschk.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%AccessChk%' AND (cmdline LIKE '%uwcqv%' OR cmdline LIKE '%kwsu%' OR cmdline LIKE '%qwsu%' OR cmdline LIKE '%uwdqs%');

bool permission_check_via_accesschk_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("AccessChk") != std::string::npos &&
		(cmdline.find("uwcqv ") != std::string::npos ||
		 cmdline.find("kwsu ") != std::string::npos ||
		 cmdline.find("qwsu ") != std::string::npos ||
		 cmdline.find("uwdqs ") != std::string::npos))
	{
		rule_event.metadata = "Detected a suspicious process command line that uses whoami as first parameter";
		return true;
	}
	return false;
}

// T1518 - Detected Windows Software Discovery
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND cmdline LIKE '%query%' AND cmdline LIKE '%\software\%' AND cmdline LIKE '%/v%' AND cmdline LIKE '%svcversion%';

bool detected_windows_software_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\reg.exe") != std::string::npos && cmdline.find("query") != std::string::npos && cmdline.find("\\software\\") != std::string::npos && cmdline.find("/v") != std::string::npos && cmdline.find("svcversion") != std::string::npos)
	{
		rule_event.metadata = "Detected an attempt to enumerate software";
		return true;
	}
	return false;
}

bool hacktool_sharpldapwhoami_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\SharpLdapWhoami.exe") != std::string::npos) && cmdline.find("/method:ntlm") != std::string::npos && cmdline.find("/method:kerb") != std::string::npos && cmdline.find("/method:nego") != std::string::npos && cmdline.find("/m:nego") != std::string::npos && cmdline.find("/m:ntlm") != std::string::npos && cmdline.find("/m:kerb") != std::string::npos)
	{
		rule_event.metadata = "SharpLdapWhoami Detected !";
		return true;
	}
	return false;
}

bool hacktool_sharpview_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\SharpView.exe") != std::string::npos) && (cmdline.find("Add-RemoteConnection") != std::string::npos || cmdline.find("Convert-ADName") != std::string::npos || cmdline.find("ConvertFrom-SID") != std::string::npos || cmdline.find("ConvertFrom-UACValue") != std::string::npos || cmdline.find("Convert-SidToName") != std::string::npos || cmdline.find("Export-PowerViewCSV") != std::string::npos || cmdline.find("Find-DomainObjectPropertyOutlier") != std::string::npos || cmdline.find("Find-DomainProcess") != std::string::npos || cmdline.find("Find-DomainShare") != std::string::npos || cmdline.find("Find-DomainUserEvent") != std::string::npos || cmdline.find("Find-DomainUserLocation") != std::string::npos || cmdline.find("Find-ForeignGroup") != std::string::npos || cmdline.find("Find-ForeignUser") != std::string::npos || cmdline.find("Find-GPOComputerAdmin") != std::string::npos || cmdline.find("Find-GPOLocation") != std::string::npos || cmdline.find("Find-Interesting") != std::string::npos || cmdline.find("Find-LocalAdminAccess") != std::string::npos || cmdline.find("Find-ManagedSecurityGroups") != std::string::npos || cmdline.find("Get-CachedRDPConnection") != std::string::npos || cmdline.find("Get-DFSshare") != std::string::npos || cmdline.find("Get-DomainComputer") != std::string::npos || cmdline.find("Get-DomainController") != std::string::npos || cmdline.find("Get-DomainDFSShare") != std::string::npos || cmdline.find("Get-DomainDNSRecord") != std::string::npos || cmdline.find("Get-DomainFileServer") != std::string::npos || cmdline.find("Get-DomainForeign") != std::string::npos || cmdline.find("Get-DomainGPO") != std::string::npos || cmdline.find("Get-DomainGroup") != std::string::npos || cmdline.find("Get-DomainGUIDMap") != std::string::npos || cmdline.find("Get-DomainManagedSecurityGroup") != std::string::npos || cmdline.find("Get-DomainObject") != std::string::npos || cmdline.find("Get-DomainOU") != std::string::npos || cmdline.find("Get-DomainPolicy") != std::string::npos || cmdline.find("Get-DomainSID") != std::string::npos || cmdline.find("Get-DomainSite") != std::string::npos || cmdline.find("Get-DomainSPNTicket") != std::string::npos || cmdline.find("Get-DomainSubnet") != std::string::npos || cmdline.find("Get-DomainTrust") != std::string::npos || cmdline.find("Get-DomainUserEvent") != std::string::npos || cmdline.find("Get-ForestDomain") != std::string::npos || cmdline.find("Get-ForestGlobalCatalog") != std::string::npos || cmdline.find("Get-ForestTrust") != std::string::npos || cmdline.find("Get-GptTmpl") != std::string::npos || cmdline.find("Get-GroupsXML") != std::string::npos || cmdline.find("Get-LastLoggedOn") != std::string::npos || cmdline.find("Get-LoggedOnLocal") != std::string::npos || cmdline.find("Get-NetComputer") != std::string::npos || cmdline.find("Get-NetDomain") != std::string::npos || cmdline.find("Get-NetFileServer") != std::string::npos || cmdline.find("Get-NetForest") != std::string::npos || cmdline.find("Get-NetGPO") != std::string::npos || cmdline.find("Get-NetGroupMember") != std::string::npos || cmdline.find("Get-NetLocalGroup") != std::string::npos || cmdline.find("Get-NetLoggedon") != std::string::npos || cmdline.find("Get-NetOU") != std::string::npos || cmdline.find("Get-NetProcess") != std::string::npos || cmdline.find("Get-NetRDPSession") != std::string::npos || cmdline.find("Get-NetSession") != std::string::npos || cmdline.find("Get-NetShare") != std::string::npos || cmdline.find("Get-NetSite") != std::string::npos || cmdline.find("Get-NetSubnet") != std::string::npos || cmdline.find("Get-NetUser") != std::string::npos || cmdline.find("Get-PathAcl") != std::string::npos || cmdline.find("Get-PrincipalContext") != std::string::npos || cmdline.find("Get-RegistryMountedDrive") != std::string::npos || cmdline.find("Get-RegLoggedOn") != std::string::npos || cmdline.find("Get-WMIRegCachedRDPConnection") != std::string::npos || cmdline.find("Get-WMIRegLastLoggedOn") != std::string::npos || cmdline.find("Get-WMIRegMountedDrive") != std::string::npos || cmdline.find("Get-WMIRegProxy") != std::string::npos || cmdline.find("Invoke-ACLScanner") != std::string::npos || cmdline.find("Invoke-CheckLocalAdminAccess") != std::string::npos || cmdline.find("Invoke-Kerberoast") != std::string::npos || cmdline.find("Invoke-MapDomainTrust") != std::string::npos || cmdline.find("Invoke-RevertToSelf") != std::string::npos || cmdline.find("Invoke-Sharefinder") != std::string::npos || cmdline.find("Invoke-UserImpersonation") != std::string::npos || cmdline.find("Remove-DomainObjectAcl") != std::string::npos || cmdline.find("Remove-RemoteConnection") != std::string::npos || cmdline.find("Request-SPNTicket") != std::string::npos || cmdline.find("Set-DomainObject") != std::string::npos || cmdline.find("Test-AdminAccess") != std::string::npos))
	{
		rule_event.metadata = "SharpLdapWhoami Detected !";
		return true;
	}
	return false;
}

// T1087 - Suspicious Use of PsLogList
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\psloglist.exe%' OR path LIKE '%\\psloglist64.exe%') AND (cmdline LIKE '% security%' OR cmdline LIKE '% application%' OR cmdline LIKE '% system%') AND (cmdline LIKE '% -d%' OR cmdline LIKE '% /d%' OR cmdline LIKE '% -x%' OR cmdline LIKE '% /x%' OR cmdline LIKE '% -s%' OR cmdline LIKE '% /s%' OR cmdline LIKE '% -c%' OR cmdline LIKE '% /c%' OR cmdline LIKE '% -g%' OR cmdline LIKE '% /g%'));

bool suspicious_use_of_PsLogList(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\psloglist.exe") != std::string::npos ||
		 path.find("\\psloglist64.exe") != std::string::npos) &&
		(cmdline.find(" security") != std::string::npos ||
		 cmdline.find(" application") != std::string::npos ||
		 cmdline.find(" system") != std::string::npos) &&
		(cmdline.find(" -d") != std::string::npos ||
		 cmdline.find(" /d") != std::string::npos ||
		 cmdline.find(" -x") != std::string::npos ||
		 cmdline.find(" /x") != std::string::npos ||
		 cmdline.find(" -s") != std::string::npos ||
		 cmdline.find(" /s") != std::string::npos ||
		 cmdline.find(" -c") != std::string::npos ||
		 cmdline.find(" /c") != std::string::npos ||
		 cmdline.find(" -g") != std::string::npos ||
		 cmdline.find(" /g") != std::string::npos))
	{
		rule_event.metadata = "Detected an attempt to enumerate software";
		return true;
	}
	return false;
}

// T1082 - System Information Discovery
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%systeminfo%' AND cmdline LIKE '%reg query%') OR (cmdline LIKE '%system_profiler%' AND cmdline LIKE '%-al%');

bool system_information_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("systeminfo") != std::string::npos &&
		 cmdline.find("reg query") != std::string::npos) ||
		(cmdline.find("system_profiler") != std::string::npos &&
		 cmdline.find("-al") != std::string::npos))
	{
		rule_event.metadata = "Detected usage of the 'systeminfo' command to retrieve information";
		return true;
	}
	return false;
}

// T1057 - Suspicious Tasklist Discovery Command
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%tasklist%' OR cmdline LIKE '%tasklist.exe%');

bool suspicious_tasklist_discovery_command(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("tasklist") != std::string::npos ||
		cmdline.find("tasklist.exe") != std::string::npos)
	{
		rule_event.metadata = "Detected an attempt to get information about running processes on a system";
		return true;
	}
	return false;
}

// T1040 - Harvesting Of Wifi Credentials Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND  cmdline LIKE '%wlan%' AND cmdline LIKE '% s%' AND cmdline LIKE '% p%' AND cmdline LIKE '% k%' AND cmdline LIKE '%=clear%');

bool harvesting_of_wifi_credentials_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\netsh.exe") != std::string::npos &&
		cmdline.find("wlan") != std::string::npos &&
		cmdline.find(" s") != std::string::npos &&
		cmdline.find(" p") != std::string::npos &&
		cmdline.find(" k") != std::string::npos &&
		cmdline.find("=clear") != std::string::npos)
	{
		rule_event.metadata = "Harvesting Of Wifi Credentials Via Netsh.EXE";
		return true;
	}
	return false;
}

// T1016 - Nltest.EXE Execution
// select * from win_process_events where path like '%nltestrk.exe%';

bool nltest_exe_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("nltestrk.exe") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Nltest.EXE Execution";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1016 - Potential Recon Activity Via Nltest.EXE
// select * from win_process_events where cmdline like '%/server%' and cmdline like '%/query%' and cmdline like '%/dclist%' and cmdline like '%/parentdomain%' and cmdline like '%/domain_trusts%' and cmdline like '%/all_trusts%' and cmdline like '%/trusted_domains%' and cmdline like '%/user%';

bool potential_recon_activity_via_nltest_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("nltest.exe") != std::string::npos &&
		cmdline.find("/server") != std::string::npos &&
		cmdline.find("/query") != std::string::npos &&
		cmdline.find("/dclist") != std::string::npos &&
		cmdline.find("/parentdomain") != std::string::npos &&
		cmdline.find("/domain_trusts") != std::string::npos &&
		cmdline.find("/all_trusts") != std::string::npos &&
		cmdline.find("/trusted_domains") != std::string::npos &&
		cmdline.find("/user") != std::string::npos)
	{
		rule_event.metadata = "Potential Recon Activity Via Nltest.EXE";
		return true;
	}
	return false;
}

// T1087 - Network Reconnaissance Activity
// select * from win_process_events where cmdline like '%nslookup%' and cmdline like '%_ldap._tcp.dc._msdcs.%';

bool network_reconnaissance_activity(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("nslookup") != std::string::npos &&
		cmdline.find("_ldap._tcp.dc._msdcs.") != std::string::npos)
	{
		rule_event.metadata = "Network Reconnaissance Activity";
		return true;
	}
	return false;
}

// T1124 - Discovery of a System Time
// SELECT * FROM win_process_events WHERE ((path LIKE '%\net.exe%' OR path LIKE '%\net1.exe%') AND cmdline LIKE '%time%') OR (path LIKE '%\w32tm.exe%' AND cmdline LIKE '%tz%');

bool discovery_of_a_system_time(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find("time") != std::string::npos) || (path.find("\\w32tm.exe") != std::string::npos && cmdline.find("tz") != std::string::npos))
	{
		rule_event.metadata = "Detected use of various commands to query a system time.";
		return true;
	}
	return false;
}

// T1018 - Renamed AdFind Execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%domainlist%' OR cmdline LIKE '%trustdmp%' OR cmdline LIKE '%dcmodes%' OR cmdline LIKE '%adinfo%' OR cmdline LIKE '% dclist %' OR cmdline LIKE '%computer_pwdnotreqd%' OR cmdline LIKE '%objectcategory=%' OR cmdline LIKE '%-subnets -f%' OR cmdline LIKE '%name="Domain Admins"%' OR cmdline LIKE '%-sc u:%' OR cmdline LIKE '%domainncs%' OR cmdline LIKE '%dompol%' OR cmdline LIKE '% oudmp %' OR cmdline LIKE '%subnetdmp%' OR cmdline LIKE '%gpodmp%' OR cmdline LIKE '%fspdmp%' OR cmdline LIKE '%users_noexpire%' OR cmdline LIKE '%computers_active%' OR cmdline LIKE '%computers_pwdnotreqd%') OR (cmdline LIKE '%bca5675746d13a1f246e2da3c2217492%' OR cmdline LIKE '%53e117a96057eaf19c41380d0e87f1c2%' OR cmdline LIKE '%IMPHASH=BCA5675746D13A1F246E2DA3C2217492%' OR cmdline LIKE '%IMPHASH=53E117A96057EAF19C41380D0E87F1C2%') OR (cmdline LIKE '%AdFind.exe%')) AND NOT (path LIKE '%\AdFind.exe%');

bool renamed_adfind_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (((cmdline.find("domainlist") != std::string::npos || cmdline.find("trustdmp") != std::string::npos || cmdline.find("dcmodes") != std::string::npos || cmdline.find("adinfo") != std::string::npos || cmdline.find(" dclist ") != std::string::npos || cmdline.find("computer_pwdnotreqd") != std::string::npos || cmdline.find("objectcategory=") != std::string::npos || cmdline.find("-subnets -f") != std::string::npos || cmdline.find("name='Domain Admins'") != std::string::npos || cmdline.find("-sc u:") != std::string::npos || cmdline.find("domainncs") != std::string::npos || cmdline.find("dompol") != std::string::npos || cmdline.find(" oudmp ") != std::string::npos || cmdline.find("subnetdmp") != std::string::npos || cmdline.find("gpodmp") != std::string::npos || cmdline.find("fspdmp") != std::string::npos || cmdline.find("users_noexpire") != std::string::npos || cmdline.find("computers_active") != std::string::npos || cmdline.find("computers_pwdnotreqd") != std::string::npos) || (cmdline.find("bca5675746d13a1f246e2da3c2217492") != std::string::npos || cmdline.find("53e117a96057eaf19c41380d0e87f1c2") != std::string::npos || cmdline.find("IMPHASH=BCA5675746D13A1F246E2DA3C2217492") != std::string::npos || cmdline.find("IMPHASH=53E117A96057EAF19C41380D0E87F1C2") != std::string::npos) || (cmdline.find("AdFind.exe") != std::string::npos)) && !(path.find("\\AdFind.exe") != std::string::npos))
	{
		rule_event.metadata = "Detected the use of a renamed Adfind.exe.";
		return true;
	}
	return false;
}

// Rule triggering, to be checked
// // T1124 - Use of W32tm as Timer
// // SELECT * FROM win_process_events WHERE cmdline LIKE '%W32tm%' AND cmdline LIKE '%/stripchart%' AND cmdline LIKE '%/computer:%' AND cmdline LIKE '%/period:%' AND cmdline LIKE '%/dataonly%' AND cmdline LIKE '%/samples:%';

// bool use_of_W32tm_as_timer(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;
// 	if (cmdline.find("W32tm") != std::string::npos &&
// 		cmdline.find("/stripchart") != std::string::npos &&
// 		cmdline.find("/computer:") != std::string::npos &&
// 		cmdline.find("/period:") != std::string::npos &&
// 		cmdline.find("/dataonly") != std::string::npos &&
// 		cmdline.find("/samples:") != std::string::npos)

// 	{
// 		rule_event.metadata = "Detected W32tm acting as a delay mechanism.";
// 		return true;
// 	}
// 	return false;
// }

// T1016 - Potential Active Directory Enumeration Using AD Module
// select * from win_process_events where
//(cmdline like '%Import-Module%' or
// cmdline like '%ipmo%') and
// cmdline like '%Microsoft.ActiveDirectory.Management.dll%';

bool potential_active_directory_enumeration_using_ad_module(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("Import-Module") != std::string::npos ||
		 cmdline.find("ipmo") != std::string::npos) &&
		cmdline.find("Microsoft.ActiveDirectory.Management.dll") != std::string::npos)
	{
		rule_event.metadata = "Potential Active Directory Enumeration Using AD Module";
		return true;
	}
	return false;
}

// T1033 - Computer Discovery And Export Via Get-ADComputer Cmdlet
// select * from win_process_events where
// cmdline like '%Get-ADComputer%' and
// cmdline like '% -Filter \*%' and
//(cmdline like '% > %' or
// cmdline like '% | Select%' or
// cmdline like '%Out-File%' or
// cmdline like '%Set-Content%' or
// cmdline like '%Add-Content%');

bool computer_discovery_and_export_via_get_adcomputer_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find("Get-ADComputer ") != std::string::npos &&
		cmdline.find(" -Filter \\*") != std::string::npos &&
		(cmdline.find(" > ") != std::string::npos ||
		 cmdline.find(" | Select") != std::string::npos ||
		 cmdline.find("Out-File") != std::string::npos ||
		 cmdline.find("Set-Content") != std::string::npos ||
		 cmdline.find("Add-Content") != std::string::npos))
	{
		rule_event.metadata = "Computer Discovery And Export Via Get-ADComputer Cmdlet";
		return true;
	}
	return false;
}

// T1033 - Renamed Whoami Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%whoami%') AND NOT (path LIKE '%\whoami.exe%');

bool renamed_whoami_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("whoami") != std::string::npos) && !(path.find("\\whoami.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of whoami that has been renamed to a different name to avoid detection";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1087.001 - Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
// select * from win_process_events where
// cmdline like '%Get-LocalGroupMember%' and
//(cmdline like '%domain admins%' or
// cmdline like '% administrator%' or
// cmdline like '% administrateur%' or
// cmdline like '%enterprise admins%' or
// cmdline like '%Exchange Trusted Subsystem%' or
// cmdline like '%Remote Desktop Users%' or
// cmdline like '%Utilisateurs du Bureau à distance%' or
// cmdline like '%Usuarios de escritorio remoto%');

bool suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("Get-LocalGroupMember ") != std::string::npos) &&
		(cmdline.find("domain admins") != std::string::npos ||
		 cmdline.find(" administrator") != std::string::npos ||
		 cmdline.find(" administrateur") != std::string::npos ||
		 cmdline.find("enterprise admins") != std::string::npos ||
		 cmdline.find("Exchange Trusted Subsystem") != std::string::npos ||
		 cmdline.find("Remote Desktop Users") != std::string::npos ||
		 cmdline.find("Utilisateurs du Bureau à distance") != std::string::npos ||
		 cmdline.find("Usuarios de escritorio remoto") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// TA0007 - Potential Recon Activity Using Wevtutil //ID TO be reviewed
// SELECT * FROM win_process_events WHERE path LIKE '%\\wevtutil.exe%' AND (cmdline LIKE '%qe%' OR cmdline LIKE '%query-events%') AND (cmdline LIKE '%Microsoft-Windows-TerminalServices-LocalSessionManager/Operational%' OR cmdline LIKE '%Microsoft-Windows-Terminal-Services-RemoteConnectionManager/Operational%');

bool potential_recon_activity_using_wevtutil(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\wevtutil.exe") != std::string::npos) && (cmdline.find("qe") != std::string::npos || cmdline.find("query-events") != std::string::npos) && (cmdline.find("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational") != std::string::npos || cmdline.find("Microsoft-Windows-Terminal-Services-RemoteConnectionManager/Operational") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected usage of the wevtutil utility to perform reconnaissance.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1217 - Suspicious Where Execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%\\wevtutil.exe%' AND (cmdline LIKE '%places.sqlite%' OR cmdline LIKE '%cookies.sqlite%' OR cmdline LIKE '%formhistory.sqlite%' OR cmdline LIKE '%logins.json%' OR cmdline LIKE '%key4.db%' OR cmdline LIKE '%key3.db%')) OR (cmdline LIKE '%\\wevtutil.exe%' AND (cmdline LIKE '%History%' OR cmdline LIKE '%Bookmarks%' OR cmdline LIKE '%Cookies%' OR cmdline LIKE '%Login Data%')));

bool suspicious_where_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("\\where.exe") != std::string::npos && (cmdline.find("places.sqlite") != std::string::npos || cmdline.find("cookies.sqlite") != std::string::npos || cmdline.find("formhistory.sqlite") != std::string::npos || cmdline.find("logins.json") != std::string::npos || cmdline.find("key4.db") != std::string::npos || cmdline.find("key3.db") != std::string::npos)) || (cmdline.find("\\where.exe") != std::string::npos && (cmdline.find("History") != std::string::npos || cmdline.find("Bookmarks") != std::string::npos || cmdline.find("Cookies") != std::string::npos || cmdline.find("Login Data") != std::string::npos)))
	{
		std::stringstream ss;

		ss << "Detected adversaries enumerating browser bookmarks to learn more about compromised hosts which may reveal personal information.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1033 - Suspicious Whoami.EXE Execution From Privileged Process
// SELECT * FROM win_process_events WHERE path LIKE '%whoami%' AND (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%' OR cmdline LIKE '%TrustedInstaller%');

bool suspicious_whoami_EXE_execution_from_privileged_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("whoami") != std::string::npos && (cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos || cmdline.find("TrustedInstaller") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of 'whoami.exe' by privileged accounts that are often abused by threat actors.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1033 - Suspicious Whoami.EXE Execution From Privileged Process
// SELECT * FROM win_process_events WHERE path LIKE '%whoami%' AND (cmdline LIKE '%/groups%' OR cmdline LIKE '%-groups%');

bool group_membership_reconnaissance_via_whoami_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("whoami") != std::string::npos && (cmdline.find("/groups") != std::string::npos || cmdline.find("-groups") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1615 - Potential Reconnaissance Activity Via GatherNetworkInfo.VBS
//  select * from win_process_events where
//      cmdline like '%gatherNetworkInfo.vbs%' or
//      cmdline like '%wscript%' or
//      cmdline like '%cscript%';

bool potential_reconnaissance_activity_via_gathernetworkinfovbs(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("gatherNetworkInfo.vbs") != std::string::npos || cmdline.find("wscript") != std::string::npos || cmdline.find("cscript") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Execution of the built-in script located in 'C:\\Windows\\System32\\gatherNetworkInfo.vbs'. Which can be used to gather information about the target machine detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1615 - Potential Reconnaissance Activity Via GatherNetworkInfo.VBS
//  select * from win_process_events where
//      cmdline like '%gatherNetworkInfo.vbs%' or
//      cmdline like '%wscript%' or
//      cmdline like '%cscript%';

// bool potential_reconnaissance_activity_via_gathernetworkinfovbs(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;
// 	if (cmdline.find("gatherNetworkInfo.vbs") != std::string::npos || cmdline.find("wscript") != std::string::npos || cmdline.find("cscript") != std::string::npos)
// 	{
// 		std::stringstream ss;
// 		ss << "Execution of the built-in script located in 'C:\\Windows\\System32\\gatherNetworkInfo.vbs'. Which can be used to gather information about the target machine detected !";
// 		rule_event.metadata = ss.str();
// 		return true;
// 	}
// 	return false;
// }

// T1033 - User Discovery And Export Via Get-ADUser Cmdlet
// select * from win_process_events where
// cmdline like '%Get-ADUser%' and
// cmdline like '% -Filter *%' and
//(cmdline like '% > %' or
// cmdline like '% | Select%' or
// cmdline like '%Out-File%' or
// cmdline like '%Set-Content%' or
// cmdline like '%Add-Content%');

bool user_directory_and_export_via_get_aduser_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		cmdline.find("Get-ADUser ") != std::string::npos &&
		cmdline.find(" -Filter \\*") != std::string::npos &&
		(cmdline.find(" > ") != std::string::npos ||
		 cmdline.find(" | Select") != std::string::npos ||
		 cmdline.find("Out-File") != std::string::npos ||
		 cmdline.find("Set-Content") != std::string::npos ||
		 cmdline.find("Add-Content") != std::string::npos))
	{
		std::stringstream ss;

		ss << "User Discovery And Export Via Get-ADUser Cmdlet";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1007 - SC.EXE Query Execution
// select * from win_process_events where path like '%\sc.exe%' and cmdline like '% query%';

bool scexe_query_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sc.exe") != std::string::npos && cmdline.find(" query") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected execution of 'sc.exe' to query information about registered services on the system";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1033 - Security Privileges Enumeration Via Whoami.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%whoami%' AND (cmdline LIKE '%/priv%' OR cmdline LIKE '%-priv%');

bool security_privileges_enumeration_via_whoami_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("whoami") != std::string::npos && (cmdline.find("/priv") != std::string::npos || cmdline.find("-priv") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected whoami.exe executed with the /priv command line flag, which if often used after a Privilege Escalation attempt.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1033 - Suspicious Whoami.EXE Execution
// SELECT * FROM win_process_events WHERE path LIKE '%whoami%' AND cmdline LIKE '>%' AND (cmdline LIKE '% -all%' OR cmdline LIKE '% /all%' OR cmdline LIKE '% /FO CSV%' OR cmdline LIKE '% -FO CSV%');

bool suspicious_whoami_EXE_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("whoami") != std::string::npos && cmdline.find(">") != std::string::npos && (cmdline.find(" -all") != std::string::npos || cmdline.find(" /all") != std::string::npos || cmdline.find(" /FO CSV") != std::string::npos || cmdline.find(" -FO CSV") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected whoami.exe executed with the /priv command line flag, which if often used after a Privilege Escalation attempt.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1069.001 - Local Groups Reconnaissance Via Wmic.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%wmic%' AND cmdline LIKE '%group%';

bool local_groups_reconnaissance_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("wmic") != std::string::npos && cmdline.find("group") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Adversaries might be attempting to find local system groups and permission settings.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1087.002 - PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE
// select * from win_process_events where
// cmdline like '%-sc admincountdmp%' and
// cmdline like '%-sc exchaddresses%' and
//(cmdline like '%lockoutduration%' or
// cmdline like '%lockoutthreshold%' or
// cmdline like '%lockoutobservationwindow%' or
// cmdline like '%maxpwdage%' or
// cmdline like '%minpwdage%' or
// cmdline like '%minpwdlength%' or
// cmdline like '%pwdhistorylength%' or
// cmdline like '%pwdproperties%');

bool pua_suspicious_activedirectory_enumeration_via_adfindexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("-sc admincountdmp") != std::string::npos &&
		cmdline.find("-sc exchaddresses") != std::string::npos &&
		(cmdline.find("lockoutduration") != std::string::npos ||
		 cmdline.find("lockoutthreshold") != std::string::npos ||
		 cmdline.find("lockoutobservationwindow") != std::string::npos ||
		 cmdline.find("maxpwdage") != std::string::npos ||
		 cmdline.find("minpwdage") != std::string::npos ||
		 cmdline.find("minpwdlength") != std::string::npos ||
		 cmdline.find("pwdhistorylength") != std::string::npos ||
		 cmdline.find("pwdproperties") != std::string::npos))
	{
		std::stringstream ss;

		ss << "PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1087.002 - PUA - AdFind Suspicious Execution
// select * from win_process_events where
// cmdline like '%domainlist%' or
// cmdline like '%trustdmp%' or
// cmdline like '%dcmodes%' or
// cmdline like '%adinfo%' or
// cmdline like '% dclist%' or
// cmdline like '%computer_pwdnotreqd%' or
// cmdline like '%objectcategory=%' or
// cmdline like '%-subnets -f%' or
// cmdline like '%name="Domain Admins"%' or
// cmdline like '%-sc u:%' or
// cmdline like '%domainncs%' or
// cmdline like '%dompol%' or
// cmdline like '% oudmp%' or
// cmdline like '%subnetdmp%' or
// cmdline like '%gpodmp%' or
// cmdline like '%fspdmp%' or
// cmdline like '%users_noexpire%' or
// cmdline like '%computers_active%' or
// cmdline like '%computers_pwdnotreqd%';

bool pua_adfind_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("domainlist") != std::string::npos ||
		cmdline.find("trustdmp") != std::string::npos ||
		cmdline.find("dcmodes") != std::string::npos ||
		cmdline.find("adinfo") != std::string::npos ||
		cmdline.find(" dclist") != std::string::npos ||
		cmdline.find("computer_pwdnotreqd") != std::string::npos ||
		cmdline.find("objectcategory=") != std::string::npos ||
		cmdline.find("-subnets -f") != std::string::npos ||
		cmdline.find("name=\"Domain Admins\"") != std::string::npos ||
		cmdline.find("-sc u:") != std::string::npos ||
		cmdline.find("domainncs") != std::string::npos ||
		cmdline.find("dompol") != std::string::npos ||
		cmdline.find(" oudmp") != std::string::npos ||
		cmdline.find("subnetdmp") != std::string::npos ||
		cmdline.find("gpodmp") != std::string::npos ||
		cmdline.find("fspdmp") != std::string::npos ||
		cmdline.find("users_noexpire") != std::string::npos ||
		cmdline.find("computers_active") != std::string::npos ||
		cmdline.find("computers_pwdnotreqd") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PUA - AdFind Suspicious Execution";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1046 - PUA - Advanced IP Scanner Execution
// select * from win_process_events where
// cmdline like '%/portable%' or
// cmdline like '%/lng%';

bool pua_advanced_ip_scanner_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\advanced_ip_scanner") != std::string::npos &&
		cmdline.find("/portable") != std::string::npos &&
		cmdline.find("/lng") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PUA - Advanced IP Scanner Execution";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1046 - PUA - Advanced Port Scanner Execution
// select * from win_process_events where
// cmdline like '%/portable%' and
// cmdline like '%/lng%';

bool pua_advanced_port_scanner_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("/portable") != std::string::npos &&
		cmdline.find("/lng") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PUA - Advanced Port Scanner Execution";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1087 - PUA - Seatbelt Execution
// select * from win_process_events where
//((cmdline like '% DpapiMasterKeys%' or
// cmdline like '% InterestingProcesses%' or
// cmdline like '% InterestingFiles%' or
// cmdline like '% CertificateThumbprints%' or
// cmdline like '% ChromiumBookmarks%' or
// cmdline like '% ChromiumHistory%' or
// cmdline like '% ChromiumPresence%' or
// cmdline like '% CloudCredentials%' or
// cmdline like '% CredEnum%' or
// cmdline like '% CredGuard%' or
// cmdline like '% FirefoxHistory%' or
// cmdline like '% ProcessCreationEvents%') and
//(cmdline like '% -group=misc%' or
// cmdline like '% -group=remote%' or
// cmdline like '% -group=chromium%' or
// cmdline like '% -group=slack%' or
// cmdline like '% -group=system%' or
// cmdline like '% -group=user%' or
// cmdline like '% -group=all%') and
// cmdline like '% -outputfile=%');

bool pua_seatbelt_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\Seatbelt.exe") != std::string::npos &&
		(cmdline.find(" DpapiMasterKeys") != std::string::npos ||
		 cmdline.find(" InterestingProcesses") != std::string::npos ||
		 cmdline.find(" InterestingFiles") != std::string::npos ||
		 cmdline.find(" CertificateThumbprints") != std::string::npos ||
		 cmdline.find(" ChromiumBookmarks") != std::string::npos ||
		 cmdline.find(" ChromiumHistory") != std::string::npos ||
		 cmdline.find(" ChromiumPresence") != std::string::npos ||
		 cmdline.find(" CloudCredentials") != std::string::npos ||
		 cmdline.find(" CredEnum") != std::string::npos ||
		 cmdline.find(" CredGuard") != std::string::npos ||
		 cmdline.find(" FirefoxHistory") != std::string::npos ||
		 cmdline.find(" ProcessCreationEvents") != std::string::npos) &&
		(cmdline.find(" -group=misc") != std::string::npos ||
		 cmdline.find(" -group=remote") != std::string::npos ||
		 cmdline.find(" -group=chromium") != std::string::npos ||
		 cmdline.find(" -group=slack") != std::string::npos ||
		 cmdline.find(" -group=system") != std::string::npos ||
		 cmdline.find(" -group=user") != std::string::npos ||
		 cmdline.find(" -group=all") != std::string::npos) &&
		cmdline.find(" -outputfile=") != std::string::npos)
	{
		std::stringstream ss;

		ss << "PUA - Seatbelt Execution";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1562.002 - Potential Suspicious Activity Using SeCEdit
// select * from win_process_events where path like '%\secedit.exe%' and ((cmdline like '%/export%' and cmdline like '%/cfg%') or (cmdline like '%/configure%' and cmdline like '%/db%'));

bool potential_suspicious_activity_using_secedit(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\secedit.exe") != std::string::npos && ((cmdline.find("/export") != std::string::npos && cmdline.find("/cfg") != std::string::npos) || (cmdline.find("/configure") != std::string::npos && cmdline.find("/db") != std::string::npos)))
	{
		std::stringstream ss;

		ss << "Detected potential suspicious behaviour using secedit.exe.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1083 - Powershell Directory Enumeration
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%foreach%' AND cmdline LIKE '%Get-ChildItem%' AND cmdline LIKE '%-Path%' AND cmdline LIKE '%-ErrorAction%' AND cmdline LIKE '%SilentlyContinue%' AND cmdline LIKE '%Out-File%' AND cmdline LIKE '%-append%');

bool powershell_directory_enumeration(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("foreach") != std::string::npos && cmdline.find("Get-ChildItem") != std::string::npos && cmdline.find("-Path") != std::string::npos && cmdline.find("-ErrorAction") != std::string::npos && cmdline.find("SilentlyContinue") != std::string::npos && cmdline.find("Out-File") != std::string::npos && cmdline.find("-append") != std::string::npos)
	{
		rule_event.metadata = "Powershell directories might be enumerated.";
		return true;
	}
	return false;
}


//T1217 - Files And Subdirectories Listing Using Dir
// SELECT * FROM win_process_events WHERE cmdline LIKE '%dir%' AND cmdline LIKE '% /s%' AND cmdline LIKE '% /b%';


bool files_subdirectories_dir(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("dir ") != std::string::npos && cmdline.find(" /s") != std::string::npos && cmdline.find(" /b") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected the usage of dir command to collect information about directories";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//T1083 - DirLister Execution
// select * from win_process_events where path like '%dirlister.exe%';

bool dirlister_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	if(path.find("dirlister.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected the usage of DirLister.exe a utility for quickly listing folder or drive contents";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1482 - Domain Trust Discovery Via Dsquery
//select * from win_process_events where path like '%dsquery.exe%' and cmdline like '%trustedDomain%';

bool domain_trust_discovery_dsquery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
	if(path.find("dsquery.exe") != std::string::npos && cmdline.find("trustedDomain") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected execution of dsquery.exe for domain trust discovery";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1082 - Kernel Dump using Dtrace
//SELECT * FROM win_process_events WHERE path LIKE '%dtrace.exe%' AND cmdline LIKE '%syscall:::return%' AND cmdline LIKE '%lkd(%';


bool kernel_dump_dtrace(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if(path.find("dtrace.exe") != std::string::npos && cmdline.find("syscall:::return") != std::string::npos && cmdline.find("lkd(") != std::string::npos){
		std::stringstream ss;
		ss << " Detected suspicious way to dump the kernel on Windows systems using dtrace.exe";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1057 - Potentially Suspicious Findstr.EXE Execution
//
bool suspicious_findstr_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if(path.find("findstr") != std::string::npos && (cmdline.find("ipconfig") != std::string::npos || cmdline.find("tasklist") != std::string::npos))
	{
		std::stringstream ss;
		ss << " Detected execution of findstr as a child process of potentially suspicious parent command lines";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1518.001 - Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE
//
bool sysmon_discovery_findstr(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if(path.find("findstr") != std::string::npos && cmdline.find("385201") != std::string::npos)
	{
		std::stringstream ss;
		ss << " Detected usage of findstr with the argument 385201";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1120 - Fsutil Drive Enumeration
//
bool fsutil_drive_enumeration(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if(path.find("fsutil") != std::string::npos && cmdline.find("drives") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected fsutil to enumerated connected drives";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1615 - Gpresult Display Group Policy Information
//
bool gpresult_display_group_policy_information(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\gpresult.exe") != std::string::npos && (cmdline.find("/z") != std::string::npos || cmdline.find("/v") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//Potential Pikabot discovery activity
bool potential_pikabot_discovery(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
if ((parent_path.find("SearchFilterHost.exe") != std::string::npos || parent_path.find("SearchProtocolHost.exe") != std::string::npos) &&
    (cmdline.find("ipconfig.exe /all") != std::string::npos || cmdline.find("netstat.exe -aon") != std::string::npos || cmdline.find("whoami.exe /all") != std::string::npos)) {
    std::stringstream ss;
		ss << "Detected cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information";
		rule_event.metadata = ss.str();
		return true;
}
return false;
}

// T1087 - SOAPHound - SOAPHound commands execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%--certdump%' OR cmdline LIKE '%--dnsdump%' OR cmdline LIKE '%--bhdump%' OR cmdline LIKE '%--buildcache%' OR cmdline LIKE '%--showstats%') AND (cmdline LIKE '%--cachefilename%' OR cmdline LIKE '%-c%' OR cmdline LIKE '%--outputdirectory%' OR cmdline LIKE '%-o%'));

bool soaphound_commands_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("--certdump") != std::string::npos || cmdline.find("--dnsdump") != std::string::npos || cmdline.find("--bhdump") != std::string::npos || cmdline.find("--buildcache") != std::string::npos || cmdline.find("--showstats") != std::string::npos) && (cmdline.find("--cachefilename") != std::string::npos || cmdline.find("-c") != std::string::npos || cmdline.find("--outputdirectory") != std::string::npos || cmdline.find("-o") != std::string::npos))
    {
        std::stringstream ss;
        ss << "SOAPHounds Command Execution";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

//T1003 - Discovery activity from SocGholish malware
//SELECT * FROM win_process_events WHERE (parent_path LIKE '%wscript.exe%' OR parent_path LIKE '%cscript.exe%') AND path LIKE '%cmd.exe%' AND cmdline LIKE '%whoami%';

bool discovery_activity_from_socgholish_malware(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if((parent_path.find("wscript.exe") != std::string::npos || parent_path.find("cscript.exe") != std::string::npos) && (path.find("cmd.exe") != std::string::npos && cmdline.find("whoami") != std::string::npos))
	{
		std::stringstream ss;
		ss << " Detected SocGholish reconnaissance activity scripts.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1069 - Users, groups and shares discovery via Powerview
//SELECT * FROM win_process_events WHERE (path LIKE '%powershell.exe%' AND (cmdline LIKE '%Get-NetLocalGroup%' OR cmdline LIKE '%Get-NetLocalGroupMember%' OR cmdline LIKE '%Get-NetShare%' OR cmdline LIKE '%Get-NetDomain%' OR cmdline LIKE "%Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}%" OR cmdline LIKE '%Get-DomainSID%' OR cmdline LIKE '%Get-DomainTrust%' OR cmdline LIKE '%Get-DomainGPO%' OR cmdline LIKE '%Get-DomainPolicy%'));

bool users_groups_and_shares_discovery_via_powerview(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if(path.find("powershell.exe") != std::string::npos && (cmdline.find("Get-NetLocalGroup") != std::string::npos || cmdline.find("Get-NetLocalGroupMember") != std::string::npos || cmdline.find("Get-NetShare") != std::string::npos || cmdline.find("Get-NetDomain") != std::string::npos || cmdline.find("Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}") != std::string::npos || cmdline.find("Get-DomainSID") != std::string::npos || cmdline.find("Get-DomainTrust") != std::string::npos || cmdline.find("Get-DomainGPO") != std::string::npos || cmdline.find("Get-DomainPolicy") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected the usage of Powerview script used for reconnaissance of users, groups and network shares";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


// T1482 - Domain trust discovery via nltest
// SELECT * FROM process_events WHERE path LIKE '%nltest.exe%' AND (cmdline LIKE '%/domain_trusts%' OR cmdline LIKE '%/all_trusts%');

bool domain_trust_discovery_via_nltest(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if(path.find("nltest.exe") != std::string::npos && (cmdline.find("/domain_trusts") != std::string::npos || cmdline.find("/all_trusts") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Domain trust discovery via nltest";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}