#include "win_lateral_movement.h"
#include <sstream>

// Lateral Movement

// T1021.006 - Enable Windows Remote Management
// select * from win_process_events where (cmdline like '%powershell.exe%' && cmdline like '%Enable-PSRemoting%');

bool enable_windows_remote_management(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Enable-PSRemoting") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Windows Remote Management is enabled";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.006 - Execute Invoke-command on Remote Host
// select * from win_process_events where cmdline like '%powershell.exe%' && cmdline like '%Enable-PSRemoting%' and cmdline like '%Invoke-Command %' and cmdline like '%-ComputerName%');

bool execute_invoke_command_on_remote_host(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Enable-PSRemoting") != std::string::npos && cmdline.find("Invoke-Command") != std::string::npos && cmdline.find("-ComputerName") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Invoke command on remote host is executed";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.002 - Suspicious New-PSDrive to Admin Share
// select * from win_process_events where cmdline like '%powershell.exe%' && cmdline like '%New-PSDrive%' and cmdline like '%-psprovider%' and cmdline like '%filesystem%' and cmdline like '%-root%');

bool suspicious_new_PSDrive_to_admin_share(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-PSDrive") != std::string::npos && cmdline.find("-psprovider") != std::string::npos && cmdline.find("filesystem") != std::string::npos && cmdline.find("-root") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Actions might be performed on behalf of the logged-on user";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1563.002 - Potential MSTSC Shadowing Activity
// select * from win_process_events where cmdline like '%noconsentprompt%' and cmdline like '%shadow:%';

bool potential_mstsc_shadowing_activity(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("noconsentprompt") != std::string::npos && cmdline.find("shadow:") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Potential MSTSC Shadowing Activity";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.001 - New Remote Desktop Connection Initiated Via Mstsc.EXE
// select * from win_process_events where cmdline like '%/v:%' and parent_path like '%C:\\Windows\\System32\\lxss\\wslhost.exe%' and path like '%\\mstsc.exe%' and cmdline like '%C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp%';

bool new_remote_desktop_connection_initiated_via_mstsc_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (cmdline.find("/v:") != std::string::npos && parent_path.find("C:\\Windows\\System32\\lxss\\wslhost.exe") != std::string::npos && path.find("\\mstsc.exe") != std::string::npos && cmdline.find("C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp") != std::string::npos)
	{
		std::stringstream ss;
		ss << "New Remote Desktop Connection Initiated Via Mstsc.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.002 - Windows Admin Share Mount Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% use%' and cmdline like '% \\\\\\\\*\\\\*$%');

bool windows_admin_share_mount_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" use") != std::string::npos && cmdline.find(" \\\\\\\\*\\\\*$") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Windows Admin Share Mount Via Net.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.002 - Windows Internet Hosted WebDav Share Mount Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% use%' and cmdline like '% http%');

bool windows_internet_hosted_webdav_share_mount_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" use") != std::string::npos && cmdline.find(" http") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Windows Internet Hosted WebDav Share Mount Via Net.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.002 - Windows Share Mount Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% use%' and cmdline like '% \\\\\\\%');

bool windows_share_mount_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" use") != std::string::npos && cmdline.find(" \\\\\\\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Windows Share Mount Via Net.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.002 - Password Provided In Command Line Of Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% use%' and cmdline like '% *\\\\%' and cmdline like '%/USER:* *%');

bool password_provided_in_command_line_of_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" use") != std::string::npos && cmdline.find(" *\\\\") != std::string::npos && cmdline.find("/USER:* *") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Password Provided In Command Line Of Net.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021 - Privilege Escalation via Named Pipe Impersonation
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\cmd.exe%' OR path LIKE '%\\powershell.exe%') AND cmdline LIKE '%echo%' AND cmdline LIKE '%>%' AND cmdline LIKE '%\\\\.\\pipe\\%');

bool privilege_escalation_via_named_pipe_impersonation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\cmd.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos) && cmdline.find("echo") != std::string::npos && cmdline.find(">") != std::string::npos && cmdline.find("\\\\.\\pipe\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Password Provided In Command Line Of Net.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021 - Potential Remote Desktop Tunneling
// SELECT * FROM win_process_events WHERE cmdline LIKE '% -L %' AND cmdline LIKE '% -P %' AND cmdline LIKE '% -R %' AND cmdline LIKE '% -pw %' AND cmdline LIKE '% -ssh %';

bool potential_remote_desktop_tunneling(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("-L") != std::string::npos &&
		cmdline.find("-P") != std::string::npos &&
		cmdline.find("-R") != std::string::npos &&
		cmdline.find("-pw") != std::string::npos &&
		cmdline.find("-ssh") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Password Provided In Command Line Of Net.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.001 - Suspicious RDP Redirect Using TSCON
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/dest:rdp-tcp#%';

bool suspicious_RDP_redirect_using_TSCON(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("/dest:rdp-tcp#") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected a suspicious RDP session redirect using tscon.exe.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.001 - Changing RDP Port to Non Standard Port via Powershell
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell.exe%' AND cmdline LIKE '%-ExecutionPolicy Bypass%' AND cmdline LIKE '%\\RDP-Tcp%' AND cmdline LIKE '%PortNumber%' AND cmdline LIKE '%New-NetFirewallRule%' AND cmdline LIKE '%-Action Allow%' AND cmdline LIKE '%-LocalPort%';

bool changing_RDP_port_to_non_standard_port_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos &&
    cmdline.find("-ExecutionPolicy Bypass ") != std::string::npos &&
    cmdline.find("\\RDP-Tcp ") != std::string::npos &&
    cmdline.find("PortNumber") != std::string::npos &&
    cmdline.find("New-NetFirewallRule") != std::string::npos &&
    cmdline.find("-Action Allow") != std::string::npos &&
    cmdline.find("-LocalPort ") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected RDP Port being changed to a Non Standard Port via Powershell.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090 - RDP Port Forwarding Rule Added Via Netsh.EXE
// SELECT * FROM win_process_events WHERE(path LIKE '%\\netsh.exe%' AND cmdline LIKE '% i%' AND cmdline LIKE '% p%' AND cmdline LIKE '%=3389%' AND cmdline LIKE '% c%');

bool rdp_port_forwarding_rule_added_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\netsh.exe") != std::string::npos && 
	cmdline.find(" i") != std::string::npos &&
    cmdline.find(" p") != std::string::npos &&
    cmdline.find("=3389") != std::string::npos &&
    cmdline.find(" c") != std::string::npos)
	{
		std::stringstream ss;
		ss << "RDP Port Forwarding Rule Added Via Netsh.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090 - New Port Forwarding Rule Added Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND  cmdline LIKE '%interface%' AND cmdline LIKE '%portproxy%' AND cmdline LIKE '%add%' AND cmdline LIKE '%v4tov4%' AND cmdline LIKE '%i %' AND cmdline LIKE '%p %' AND cmdline LIKE '%a %' AND cmdline LIKE '%v %' AND cmdline LIKE '%connectp%' AND cmdline LIKE '%listena%' AND cmdline LIKE '%c=%');

bool new_port_forwarding_rule_added_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\netsh.exe") != std::string::npos && 
	cmdline.find("interface") != std::string::npos &&
    cmdline.find("portproxy") != std::string::npos &&
    cmdline.find("add") != std::string::npos &&
    cmdline.find("v4tov4") != std::string::npos &&
	cmdline.find("i ") != std::string::npos &&
    cmdline.find("p ") != std::string::npos &&
	cmdline.find("a ") != std::string::npos &&
	cmdline.find("v ") != std::string::npos &&
	cmdline.find("connectp") != std::string::npos &&
	cmdline.find("listena") != std::string::npos &&
	cmdline.find("c=") != std::string::npos) 
	{
		std::stringstream ss;
		ss << "New Port Forwarding Rule Added Via Netsh.EXE";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.005 - Suspicious UltraVNC Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%-autoreconnect%' AND cmdline LIKE '%-connect%' AND cmdline LIKE '%-id:%';

bool suspicious_ultraVNC_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("-autoreconnect ") != std::string::npos &&
    cmdline.find("-connect ") != std::string::npos &&
    cmdline.find("-id:") != std::string::npos)

	{
		std::stringstream ss;
		ss << "Detected suspicious UltraVNC command line flag combination that indicate a auto reconnect upon execution.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool suspicious_sysaidserver_child(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	if ((parent_path.find("\\java.exe") != std::string::npos || parent_path.find("\\javaw.exe") != std::string::npos) && cmdline.find("SysAidServer") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious child processes of SysAidServer detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.003 - MMC Spawning Windows Shell
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\\mmc.exe%' AND (path LIKE '%\\cmd.exe%' OR cmdline LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR cmdline LIKE '%\\wscript.exe%' OR path LIKE '%\\cscript.exe%' OR cmdline LIKE '%\\sh.exe%' OR path LIKE '%\\bash.exe%' OR cmdline LIKE '%\\reg.exe%' OR path LIKE '%\\regsvr32.exe%' OR cmdline LIKE '%\\BITSADMIN%');

bool mmc_spawning_windows_shell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	
	if (parent_path.find("\\mmc.exe") != std::string::npos && (path.find("\\cmd.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\sh.exe") != std::string::npos || path.find("\\bash.exe") != std::string::npos || path.find("\\reg.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\BITSADMIN") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Windows command line executable started from MMC detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool mimikatz_variation_and_potential_lateral_movement_activity(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	
	if (cmdline.find("privilege::debug") != std::string::npos || cmdline.find("sekurlsa::pth") != std::string::npos || cmdline.find("CRYPTO::Extract") != std::string::npos)
	{
		std::stringstream ss;
		ss << "The presence of mimikatz and its variants as well as potential lateral movement detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1021.002 - Unsigned process creating binary in SMB share

bool unsigned_process_creating_binary_in_smb_share(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	
	if (path.find("admin$") != std::string::npos || path.find("c$") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Creation of executable in an admin SMB share by an unsigned process detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool kerberos_network_communication_from_suspicious_process(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	
	if (path.find("c:\\windows\\system32\\lsass.exe") != std::string::npos || path.find("c:\\program files\\vmware\\vmware view\\server\\bin\\ws_tomcatservice.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Kerberos traffic originating from a non-legit process";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

