#include "win_command_control_rules.h"
#include <sstream>

// T1132.001 - Data Encoding: Standard Encoding
// select * from win_process_events where cmdline like '%bxor%';

bool data_encoding_standard_encoding(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("bxor") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Malicious encoded data detected";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1071.004 - Application Layer Protocol: DNS
// DNS Large Query Volume
// select * from win_process_events where action like '%PROC_CREATE%' and cmdline like '%TXT%' and cmdline like '%QueryType%' and cmdline like '%C2Interval%';

bool dns_large_query_volume(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (process_event.entry.action.find("PROC_CREATE") && cmdline.find("TXT") != std::string::npos && cmdline.find("QueryType") != std::string::npos && cmdline.find("C2Interval") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Communication done for malicious purpose using DNS application layer protocol";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Software
// All combined
// select pid, path, parent_path, cmdline from win_process_events where path like '%\GoToAssist%' or path like '%ScreenConnect%' or path like '%ammyy.exe%' or path like '%RemotePC.exe%' or path like '%UltraViewer%' limit 10;

bool remote_access_software(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("GoToAssist.exe") != std::string::npos || cmdline.find("screenconnect") != std::string::npos || cmdline.find("ammyy.exe") != std::string::npos || cmdline.find("RemotePC.exe") != std::string::npos || cmdline.find("UltraViewer") != std::string::npos || cmdline.find("anydesk") != std::string::npos || cmdline.find("logmein") != std::string::npos || cmdline.find("teamviewer") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Remote access software downloaded to estalish connection for malicious purpose";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1572 - Protocol Tunneling
// select * from win_process_events where cmdline like '%-le%' and cmdline like '%Invoke-WebRequest%' and cmdline like '%BasicParsing%';

bool code_executed_via_excel(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("-le") != std::string::npos && cmdline.find("Invoke-WebRequest") != std::string::npos && cmdline.find("BasicParsing") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Protocol tunneling done for malicious purpose";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1105 - Ingress Tool Transfer
// select * from win_process_events where (cmdline like '%certutil%' and cmdline like'%datePath%') or (cmdline like '%cmd.exe%' and cmdline like '%nimgrab.exe%');

bool win_ingress_tool_transfer(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("certutil") != std::string::npos && cmdline.find("datePath") != std::string::npos) || (cmdline.find("cmd") != std::string::npos && cmdline.find("nimgrab.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Tools or files transferred from external system for malicious purpose";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1571 - Non-Standard Port
//  select * from win_process_events where cmdline like '%Test-NetConnection%' and cmdline '%port%';

bool non_standard_port(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Test-NetConnection") != std::string::npos && cmdline.find("port") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Communication via dissimilar port and protocol";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Ingress Tool Transfer: certutil download (urlcache)
bool win_ingress_tool_transfer_certutil(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("certutil.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Tools or files transferred from external system using certutil for malicious purpose";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090.001 - Proxy: Internal Proxy, portproxy reg key
bool internal_proxy_portproxy_regkey(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("CurrentControlSet\\Services\\PortProxy\\v4tov4") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Registry key added to set up proxy at the system";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Ingress Tool Transfer: Curl Download File
bool win_ingress_tool_transfer_curl_download(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("curl.exe") != std::string::npos && process_event.entry.cmdline.find("Curl") != std::string::npos)
	{
		std::stringstream ss;
		ss << "curl.exe used to download a remote DLL for malicious purpose";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1095 - Netcat The Powershell Version
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%powercat%' and cmdline like '%powercat.ps1%';

bool netcat_the_powershell_version(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("powercat") != std::string::npos && cmdline.find("powercat.ps1") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Netcat powershell version";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1071.001 - Change User Agents with WebRequest
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Invoke-WebRequest%' and cmdline like '%-UserAgent%';

bool change_user_agents_with_webRequest(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Invoke-WebRequest") != std::string::npos && cmdline.find("-UserAgent") != std::string::npos)
	{
		std::stringstream ss;

		ss << "User agents changed with web request";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1573 - Suspicious SSL Connection
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%New-Object%' and cmdline like '%System.Net.Security.SslStream%' and cmdline like '%Net.Security.RemoteCertificateValidationCallback%' and cmdline like '%.AuthenticateAsClient%');

bool suspicious_SSL_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Object") != std::string::npos && cmdline.find("System.Net.Security.SslStream") != std::string::npos && cmdline.find("Net.Security.RemoteCertificateValidationCallback") != std::string::npos && cmdline.find(".AuthenticateAsClient") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Suspicious SSL connection"; // To be checked
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Suspicious TeamViewer Domain Access
// select * from win_process_events where cmdline like '%taf.teamviewer.com%' or cmdline like '%udp.ping.teamviewer.com%' or cmdline like '%TeamViewer.exe%';

bool suspicious_teamViewer_domain_access(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("taf.teamviewer.com") != std::string::npos || cmdline.find("udp.ping.teamviewer.com") != std::string::npos && cmdline.find("TeamViewer.exe") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Domain access with TeamViewer acquired";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1090.003 - DNS Query Tor Onion Address - Sysmon
// select * from win_process_events where cmdline like '%powershell.exe%' and (cmdline like '%tor.exe%' or cmdline like '%.onion%');

bool dns_query_tor_onion_address_sysmon(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("tor.exe") != std::string::npos || cmdline.find(".onion") != std::string::npos))
	{
		std::stringstream ss;

		ss << "DNS queries to an .onion address";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1071.004 - Dnscat Execution
// select * from win_process_events where cmdline like '%powershell.exe%' and (cmdline like '%tor.exe%' or cmdline like '%.onion%');

bool dnscat_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Start-Dnscat2") != std::string::npos)
	{
		std::stringstream ss;

		ss << "C2 session started using the DNS protocol";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1132.001 - Suspicious FromBase64String Usage On Gzip Archive - Ps Script
// select * from win_process_events where cmdline like '%FromBase64String%' and cmdline like '%MemoryStream%' and cmdline like '%H4sI%';

bool suspicious_fromBase64String_usage_on_gzip_archive_ps_script(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("FromBase64String") != std::string::npos && cmdline.find("MemoryStream") != std::string::npos && cmdline.find("H4sI") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Malicious content loaded into memory";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1132.001 - Suspicious FromBase64String Usage On Gzip Archive - Ps Script
// select * from win_process_events where cmdline like '%[System.Net.HttpWebRequest]%' and cmdline like '%System.Net.Sockets.TcpListener%' and cmdline like '%AcceptTcpClient%';

bool suspicious_TCP_tunnel_via_powershell_script(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("[System.Net.HttpWebRequest]") != std::string::npos && cmdline.find("System.Net.Sockets.TcpListener") != std::string::npos && cmdline.find("AcceptTcpClient") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Suspicious TCP tunnnel detected via Powershell script.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1105 - Download a File with IMEWDBLD.exe
// select * from win_process_events where cmdline like '%powershell.exe%' and (cmdline like '%$imewdbled%' and cmdline like '%$inetcache%');

bool download_a_file_with_IMEWDBLD_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("$imewdbled") != std::string::npos || cmdline.find("$inetcache") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Used IMEWDBLD.exe (built-in to windows) to download a file";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Suspicious Mstsc.EXE Execution With Local RDP File
// select * from win_process_events where cmdline like '%\\mstsc.exe%' and ((cmdline like '%.rdp%' or cmdline like '%.rdp\"%') or (cmdline like '%:\\Users\\Public\\%' or  cmdline like '%:\\Windows\\System32\\spool\\drivers\\color%' or  cmdline like '%:\\Windows\\System32\\Tasks_Migrated%' or  cmdline like '%:\\Windows\\Tasks\\%' or  cmdline like '%:\\Windows\\Temp\\%' or  cmdline like '%:\\Windows\\Tracing\\%' or  cmdline like '%\\AppData\\Local\\Temp\\%'));

bool suspicious_mstsc_exe_execution_with_local_rdp_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (cmdline.find("\\mstsc.exe") != std::string::npos && (cmdline.find(".rdp") != std::string::npos || cmdline.find(".rdp\"") != std::string::npos) && (cmdline.find(":\\Users\\Public\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\spool\\drivers\\color") != std::string::npos || cmdline.find(":\\Windows\\System32\\Tasks_Migrated") != std::string::npos || cmdline.find(":\\Windows\\Tasks\\") != std::string::npos || cmdline.find(":\\Windows\\Temp\\") != std::string::npos || cmdline.find(":\\Windows\\Tracing\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious Mstsc.EXE Execution With Local RDP File";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Mstsc.EXE Execution With Local RDP File
// select * from win_process_events where cmdline like '%\\mstsc.exe%' and cmdline like '%C:\\Windows\\System32\\lxss\\wslhost.exe%' and (cmdline like '%.rdp%' or cmdline like '%.rdp\"%') and (cmdline like '%C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp%');

bool mstsc_exe_execution_with_local_rdp_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (cmdline.find("\\mstsc.exe") != std::string::npos && cmdline.find("C:\\Windows\\System32\\lxss\\wslhost.exe") != std::string::npos && (cmdline.find(".rdp") != std::string::npos || cmdline.find(".rdp\"") != std::string::npos) && (cmdline.find("C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Mstsc.EXE Execution With Local RDP File";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Mstsc.EXE Execution From Uncommon Parent
// select * from win_process_events where ((parent_path like '%\\brave.exe%' or  parent_path like '%\\CCleanerBrowser.exe%' or  parent_path like '%\\chrome.exe%' or  parent_path like '%\\chromium.exe%' or  parent_path like '%\\firefox.exe%' or  parent_path like '%\\iexplore.exe%' or  parent_path like '%\\microsoftedge.exe%' or  parent_path like '%\\msedge.exe%' or  parent_path like '%\\opera.exe%' or  parent_path like '%\\vivaldi.exe%' or  parent_path like '%\\whale.exe%') and (path like '%\\mstsc.exe%'));

bool mstsc_exe_execution_from_uncommon_parent(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((parent_path.find("\\brave.exe") != std::string::npos || parent_path.find("\\CCleanerBrowser.exe") != std::string::npos || parent_path.find("\\chrome.exe") != std::string::npos || parent_path.find("\\chromium.exe") != std::string::npos || parent_path.find("\\firefox.exe") != std::string::npos || parent_path.find("\\iexplore.exe") != std::string::npos || parent_path.find("\\microsoftedge.exe") != std::string::npos || parent_path.find("\\msedge.exe") != std::string::npos || parent_path.find("\\opera.exe") != std::string::npos || parent_path.find("\\vivaldi.exe") != std::string::npos || parent_path.find("\\whale.exe") != std::string::npos) && (path.find("\\mstsc.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Mstsc.EXE Execution From Uncommon Parent";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Suspicious TSCON Start as SYSTEM
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%') AND cmdline LIKE '%\\tscon.exe%';

bool suspicious_TSCON_start_as_SYSTEM(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("AUTHORI") != std::string::npos ||
		 cmdline.find("AUTORI") != std::string::npos) &&
		cmdline.find("\\tscon.exe") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected a tscon.exe start as LOCAL SYSTEM";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

bool hacktool_silenttrinity_stager_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("st2stager") != std::string::npos)
	{
		std::stringstream ss;
		ss << "SILENTTRINITY stager use via PE metadata detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1219 - Use of UltraViewer Remote Access Software
// SELECT * FROM win_process_events WHERE cmdline LIKE '%UltraViewer%' OR path LIKE '%UltraViewer_Desktop.exe%';

bool use_of_ultraviewer_remote_access_software(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (cmdline.find("UltraViewer") != std::string::npos || path.find("UltraViewer_Desktop.exe") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected an adversary trying to use legitimate desktop support and remote access software to establish an interactive command and control channel to target systems within the network.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - AnyDesk Piped Password Via CLI
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/c %' AND cmdline LIKE '%echo %' AND cmdline LIKE '%.exe --set-password%';

bool remote_access_tool_anydesk_piped_password_via_cli(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("/c ") != std::string::npos &&
		cmdline.find("echo ") != std::string::npos &&
		cmdline.find(".exe --set-password") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected piping the password to an anydesk instance via CMD and the '--set-password' flag.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - AnyDesk Silent Installation
// SELECT * FROM win_process_events WHERE cmdline LIKE '%--install%' AND cmdline LIKE '%--start-with-win%' AND cmdline LIKE '%--silent%';

bool remote_access_tool_anydesk_silent_installation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("--install") != std::string::npos && cmdline.find("--start-with-win") != std::string::npos && cmdline.find("--silent") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected AnyDesk Remote Desktop silent installation.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - Anydesk Execution From Suspicious Folder
// SELECT * FROM win_process_events WHERE path LIKE '%\AnyDesk.exe%' AND NOT (cmdline LIKE '%\AppData\%' OR cmdline LIKE '%Program Files (x86)\AnyDesk%' OR cmdline LIKE '%%');

bool remote_access_tool_anydesk_execution_from_suspicious_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\AnyDesk.exe") != std::string::npos && !(path.find("\\AppData\\") != std::string::npos || path.find("Program Files (x86)\\AnyDesk") != std::string::npos || path.find("Program Files\\AnyDesk") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected AnyDesk Remote Desktop software execution from suspicious folder.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - GoToAssist Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%GoTo Opener%';

bool remote_access_tool_gotoassist_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("GoTo Opener") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected GoToAssist software execution.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - LogMeIn Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%LMIGuardianSvc%';

bool remote_access_tool_logmein_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("LMIGuardianSvc") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected LogMeIn software execution.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - NetSupport Execution
// SELECT * FROM win_process_events WHERE path LIKE '%PCICFGUI.EXE%';

bool remote_access_tool_netsupport_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("PCICFGUI.EXE") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected NetSupport software execution.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - ScreenConnect Backstage Mode Anomaly
// SELECT * FROM win_process_events WHERE parent_path LIKE '%ScreenConnect.ClientService.exe%' AND (path LIKE '%\cmd.exe%' OR path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%');

bool remote_access_tool_screenconnect_backstage_mode_anomaly(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("ScreenConnect.ClientService.exe") != std::string::npos && (path.find("\\cmd.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected suspicious sub processes started by the ScreenConnect client service, which indicates the use of the Backstage mode";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Remote Access Tool - ScreenConnect Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%ScreenConnect%';

bool remote_access_tool_screenconnect_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("ScreenConnect") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected ScreenConnect software execution.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1219 - Use of UltraVNC Remote Access Software
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell.exe%' AND cmdline LIKE '%Start-Process%' AND cmdline LIKE '%\\\'uvnc bvba\\UltraVnc\\vncviewer.exe\'%';

bool use_of_ultraVNC_remote_access_software(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Start-Process") != std::string::npos && cmdline.find("\\'uvnc bvba\\UltraVnc\\vncviewer.exe'") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected execution of UltraVNC to establish an interactive command and control channel to target systems within networks.";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1132.001 - Gzip Archive Decode Via PowerShell
// select * from win_process_events where
// cmdline like '%GZipStream%' and
// cmdline like '%::Decompress%';

bool gzip_archive_decode_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("GZipStream") != std::string::npos &&
		cmdline.find("::Decompress") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Gzip Archive Decode Via PowerShell";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1105 - Potential COM Objects Download Cradles Usage
// select * from win_process_events where
// cmdline like '%[Type]::GetTypeFromCLSID(%';

bool potential_com_objects_download_cradles_usage(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("[Type]::GetTypeFromCLSID(") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Potential COM Objects Download Cradles Usage";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}


// T1105 - Potential DLL File Download Via PowerShell Invoke-WebRequest
// select * from win_process_events where
//((cmdline like '%Invoke-WebRequest%' or
// cmdline like '%IWR%') and
// cmdline like '%http%' and
// cmdline like '%OutFile%' and
// cmdline like '%.dll%');

bool potential_dll_file_download_via_powershell_invoke_webrequest(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if ((cmdline.find("Invoke-WebRequest ") != std::string::npos ||
		 cmdline.find("IWR ") != std::string::npos) &&
		cmdline.find("http") != std::string::npos &&
		cmdline.find("OutFile") != std::string::npos &&
		cmdline.find(".dll") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Potential DLL File Download Via PowerShell Invoke-WebRequest";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

bool suspicious_child_process_of_manage_engine_servicedesk(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("stop") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious child processes of the 'Manage Engine ServiceDesk Plus' Java web service detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1132.001 - Suspicious FromBase64String Usage On Gzip Archive
// select * from win_process_events where
//(cmdline like '%FromBase64String%' and
// cmdline like '%MemoryStream%' and
// cmdline like '%H4sI%');

bool suspicious_frombase64string_usage_on_gzip_archive(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("FromBase64String") != std::string::npos &&
		cmdline.find("MemoryStream") != std::string::npos &&
		cmdline.find("H4sI") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious FromBase64String Usage On Gzip Archive";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool import_ldap_data_interchange_format_file_via_ldifdeexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((cmdline.find("-i") != std::string::npos || cmdline.find("-f") != std::string::npos) && (path.find("ldifde.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detects the execution of 'Ldifde.exe' with the import flag '-i'.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_extrac32_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\extrac32.exe") != std::string::npos) && (cmdline.find("extrac32.exe") != std::string::npos || cmdline.find(".cab") != std::string::npos || cmdline.find("/C") != std::string::npos || cmdline.find("/Y") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Download/copying files with Extrac32 observed !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Abusing IEExec To Download Payloads
// select * from win_process_events where
//     cmdline like '%IEExec%' or
//     cmdline like '%https://%' or
//     cmdline like '%http://%';

bool abusing_ieexec_to_download_payload(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("IEExec") != std::string::npos || cmdline.find("https://") != std::string::npos || cmdline.find("http://") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Execution of the IEExec utility to download payloads detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - PrintBrm ZIP Creation of Extraction
// select * from win_process_events where
//     cmdline like '%-f%' and
//     cmdline like '%.zip%';

bool printbrm_zip_creation_of_extraction(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-f") != std::string::npos && cmdline.find(".zip") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Execution of the LOLBIN PrintBrm.exe detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Suspicious Certreq Command to Download

bool suspicious_certreq_command_to_download(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("-Post") != std::string::npos && cmdline.find("-config") != std::string::npos && cmdline.find("http") != std::string::npos && cmdline.find("C:\\windows\\win.ini") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious certreq execution taken from the LOLBAS detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Replace.exe Usage
// select * from win_process_events where
//     cmdline like '%/a%' or
//     cmdline like '%-a%';

bool replaceexe_usage(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("/a") != std::string::npos || cmdline.find("-a") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Use of Replace.exe detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Potential Download/Upload Activity Using Type Command
// SELECT * FROM win_process_events WHERE
//     cmdline LIKE '%type %' AND
//     cmdline LIKE '% > \\\\%' AND
//     cmdline LIKE '%type \\\\%' AND
//     cmdline LIKE '% > %';
bool potential_upload_download_ctivity_using_type_command(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("type ") != std::string::npos && cmdline.find(" > \\\\") != std::string::npos && cmdline.find("type \\\\") != std::string::npos && cmdline.find(" > ") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Usage of the 'type' command to download/upload data from WebDAV server detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_diantz_download_and_compress_into_a_cab_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("diantz.exe") != std::string::npos && cmdline.find(" \\\\") != std::string::npos && cmdline.find(".cab") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Downloading and compressing a remote file from your device and storeing it in a cab file on local machine itself.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_invoke_webRequest_execution_with_directip(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("curl") != std::string::npos ||
		 cmdline.find("Invoke-WebRequest") != std::string::npos ||
		 cmdline.find("iwr") != std::string::npos ||
		 cmdline.find("wget") != std::string::npos) &&
		cmdline.find("://1") != std::string::npos &&
		cmdline.find("://2") != std::string::npos &&
		cmdline.find("://3") != std::string::npos &&
		cmdline.find("://4") != std::string::npos &&
		cmdline.find("://5") != std::string::npos &&
		cmdline.find("://6") != std::string::npos &&
		cmdline.find("://7") != std::string::npos &&
		cmdline.find("://8") != std::string::npos &&
		cmdline.find("://9") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious Invoke-WebRequest Execution With DirectIP";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Suspicious Invoke-WebRequest Execution
// SELECT * FROM win_process_events WHERE
//(cmdline LIKE '%curl%' OR
// cmdline LIKE '%Invoke-WebRequest%' OR
// cmdline LIKE '%iwr%' OR
// cmdline LIKE '%wget%') AND
//(cmdline LIKE '% -ur%' OR
// cmdline LIKE '% -o%') AND
//(cmdline LIKE '%\\AppData\\%' OR
// cmdline LIKE '%\\Desktop\\%' OR
// cmdline LIKE '%\\Temp\\%' OR
// cmdline LIKE '%\\Users\\Public\\%' OR
// cmdline LIKE '%\\Users\\Public\\%' OR
// cmdline LIKE '%\\Temp\\%' OR
// cmdline LIKE '%\\Temp\\%' OR
// cmdline LIKE '%\\Windows\\%');

bool suspicious_invoke_webRequest_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
		path.find("\\pwsh.exe") != std::string::npos &&
		(cmdline.find("curl") != std::string::npos ||
		 cmdline.find("Invoke-WebRequest") != std::string::npos ||
		 cmdline.find("iwr") != std::string::npos ||
		 cmdline.find("wget") != std::string::npos) &&
		(cmdline.find(" -ur") != std::string::npos ||
		 cmdline.find(" -o") != std::string::npos) &&
		(cmdline.find("\\AppData\\") != std::string::npos ||
		 cmdline.find("\\Desktop\\") != std::string::npos ||
		 cmdline.find("\\Temp\\") != std::string::npos ||
		 cmdline.find("\\Users\\Public\\") != std::string::npos ||
		 cmdline.find("%AppData%") != std::string::npos ||
		 cmdline.find("%Public%") != std::string::npos ||
		 cmdline.find("%Temp%") != std::string::npos ||
		 cmdline.find("%tmp%") != std::string::npos ||
		 cmdline.find("C:\\Windows\\") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious Invoke-WebRequest Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1104 - PowerShell DownloadFile
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%powershell%' AND
// cmdline LIKE '%.DownloadFile%' AND
// cmdline LIKE '%System.Net.WebClient%';

bool powershell_downloadfile(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("powershell") != std::string::npos &&
		cmdline.find(".DownloadFile") != std::string::npos &&
		cmdline.find("System.Net.WebClient") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PowerShell DownloadFile";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1572 - PUA - 3Proxy Execution
// select * from win_process_events where
// cmdline like '%.exe -i127.0.0.1 -p%';

bool pua_3proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\3proxy.exe") != std::string::npos && cmdline.find(".exe -i127.0.0.1 -p") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PUA - 3Proxy Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090.001 - PUA - Chisel Tunneling Tool Execution
// select * from win_process_events where
//(cmdline like '%exe client%' or
// cmdline like '%exe server%') and
//(cmdline like '%-socks5%' or
// cmdline like '%-reverse%' or
// cmdline like '% r:%' or
// cmdline like '%:127.0.0.1:%' or
// cmdline like '%-tls-skip-verify%' or
// cmdline like '%:socks%');

bool pua_chisel_tunneling_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\chisel.exe") != std::string::npos &&
		(cmdline.find("exe client ") != std::string::npos ||
		 cmdline.find("exe server ") != std::string::npos) &&
		(cmdline.find("-socks5") != std::string::npos ||
		 cmdline.find("-reverse") != std::string::npos ||
		 cmdline.find(" r:") != std::string::npos ||
		 cmdline.find(":127.0.0.1:") != std::string::npos ||
		 cmdline.find("-tls-skip-verify ") != std::string::npos ||
		 cmdline.find(":socks") != std::string::npos))
	{
		std::stringstream ss;
		ss << "PUA - Chisel Tunneling Tool Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090 - PUA - Fast Reverse Proxy (FRP) Execution
// select * from win_process_events where
// cmdline like '%\\frpc.ini%';

bool pua_fast_reverse_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\frpc.exe") != std::string::npos &&
		path.find("\\frps.exe") != std::string::npos &&
		cmdline.find("\\frpc.ini") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PUA - Fast Reverse Proxy (FRP) Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090 - PUA - IOX Tunneling Tool Execution
// select * from win_process_events where
// cmdline like '%.exe fwd -l%' or
// cmdline like '%.exe fwd -r%' or
// cmdline like '%.exe proxy -l%' or
// cmdline like '%.exe proxy -r%';

bool pua_iox_tunneling_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\iox.exe") != std::string::npos &&
			cmdline.find(".exe fwd -l ") != std::string::npos ||
		cmdline.find(".exe fwd -r ") != std::string::npos ||
		cmdline.find(".exe proxy -l ") != std::string::npos ||
		cmdline.find(".exe proxy -r ") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PUA - IOX Tunneling Tool Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1095 - PUA - Netcat Suspicious Execution
// select * from win_process_events where
// cmdline like '% -lvp %' or
// cmdline like '% -lvnp%' or
// cmdline like '% -l -v -p %' or
// cmdline like '% -lv -p %' or
// cmdline like '% -l --proxy-type http %' or
// cmdline like '% -vnl --exec %' or
// cmdline like '% -vnl -e %' or
// cmdline like '% --lua-exec %' or
// cmdline like '% --sh-exec %';

bool pua_netcat_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\nc.exe") != std::string::npos &&
			path.find("\\ncat.exe") != std::string::npos &&
			path.find("\\netcat.exe") != std::string::npos &&
			(cmdline.find(" -lvp ") != std::string::npos ||
		cmdline.find(" -lvnp") != std::string::npos ||
		cmdline.find(" -l -v -p ") != std::string::npos ||
		cmdline.find(" -lv -p ") != std::string::npos ||
		cmdline.find(" -l --proxy-type http ") != std::string::npos ||
		cmdline.find(" -vnl --exec ") != std::string::npos ||
		cmdline.find(" -vnl -e ") != std::string::npos ||
		cmdline.find(" --lua-exec ") != std::string::npos ||
		cmdline.find(" --sh-exec ") != std::string::npos))
	{
		std::stringstream ss;
		ss << "PUA - Netcat Suspicious Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1572 - PUA - Ngrok Execution
// select * from win_process_events where
//((cmdline like '% tcp 139%' or
// cmdline like '% tcp 445%' or
// cmdline like '% tcp 3389%' or
// cmdline like '% tcp 5985%' or
// cmdline like '% tcp 5986%') and
//(cmdline like '% start%' and
// cmdline like '%--all%' and
// cmdline like '%--config%' and
// cmdline like '%.yml%') and
//(cmdline like '% tcp%' or
// cmdline like '% http%' or
// cmdline like '% authtoken%') and
//(cmdline like '%.exe authtoken%' or
// cmdline like '%.exe start --all%'));

bool pua_ngrok_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("ngrok.exe") != std::string::npos &&
		(cmdline.find(" tcp 139") != std::string::npos ||
		 cmdline.find(" tcp 445") != std::string::npos ||
		 cmdline.find(" tcp 3389") != std::string::npos ||
		 cmdline.find(" tcp 5985") != std::string::npos ||
		 cmdline.find(" tcp 5986") != std::string::npos) &&
		(cmdline.find(" start") != std::string::npos &&
		 cmdline.find("--all") != std::string::npos &&
		 cmdline.find("--config") != std::string::npos &&
		 cmdline.find(".yml") != std::string::npos) &&
		(cmdline.find(" tcp") != std::string::npos ||
		 cmdline.find(" http") != std::string::npos ||
		 cmdline.find(" authtoken") != std::string::npos) &&
		(cmdline.find(".exe authtoken ") != std::string::npos ||
		 cmdline.find(".exe start --all") != std::string::npos))
	{
		std::stringstream ss;
		ss << "PUA - Ngrok Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090 - PUA - NPS Tunneling Tool Execution
// select * from win_process_events where
// cmdline like '% -server=%' and
// cmdline like '% -vkey=%' and
// cmdline like '% -password=%' and
// cmdline like '% -config=npc%';

bool pua_nps_tunneling_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\npc.exe") != std::string::npos &&
		cmdline.find(" -server=") != std::string::npos &&
		cmdline.find(" -vkey=") != std::string::npos &&
		cmdline.find(" -password=") != std::string::npos &&
		cmdline.find(" -config=npc") != std::string::npos)
	{
		std::stringstream ss;
		ss << "PUA - NPS Tunneling Tool Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1572 - Port Forwarding Attempt Via SSH
// select * from win_process_events where path like '%\ssh.exe%' and cmdline like '% -R %';

bool port_forwarding_attempt_via_ssh(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\ssh.exe") != std::string::npos && cmdline.find(" -R ") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected suspicious SSH tunnel port forwarding to a local port";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1572 - Potential RDP Tunneling Via SSH
// select * from win_process_events where path like '%\ssh.exe%' and cmdline like '%:3389%';

bool potential_rdp_tunneling_via_ssh(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\ssh.exe") != std::string::npos && cmdline.find(":3389") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected execution of ssh.exe to perform data exfiltration and tunneling through RDP";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1219 - Potential Amazon SSM Agent Hijacking
// select * from win_process_events where path like '%\amazon-ssm-agent.exe%' and (cmdline like '%-register %' and cmdline like '%-code %' and cmdline like '%-id %' and cmdline like '%-region %');

bool potential_amazon_ssm_agent_hijacking(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\amazon-ssm-agent.exe") != std::string::npos && cmdline.find("-register ") != std::string::npos && cmdline.find("-code ") != std::string::npos && cmdline.find("-id ") != std::string::npos && cmdline.find("-region ") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected potential Amazon SSM agent hijack attempt";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Browser Execution In Headless Mode
// select * from win_process_events where (path like '%\\brave.exe%' or path like '%\\chrome.exe%' or path like '%\\msedge.exe%' or path like '%\\opera.exe%' or path like '%\\vivaldi.exe%') and cmdline like '%--headless%';

bool browser_execution_headless(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\brave.exe") != std::string::npos || path.find("\\chrome.exe") != std::string::npos || path.find("\\msedge.exe") != std::string::npos || path.find("\\opera.exe") != std::string::npos || path.find("\\vivaldi.exe") != std::string::npos) && cmdline.find("--headless") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Chromium based browser launched in headless mode";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - File Download with Headless Browser
// select * from win_process_events where (path like '%\\brave.exe%' or path like '%\\chrome.exe%' or path like '%\\msedge.exe%' or path like '%\\opera.exe%' or path like '%\\vivaldi.exe%') and (cmdline like '%--headless%' and cmdline like '%dump-dom%' and cmdline like '%http%');

bool file_download_headless_browser(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\brave.exe") != std::string::npos || path.find("\\chrome.exe") != std::string::npos || path.find("\\msedge.exe") != std::string::npos || path.find("\\opera.exe") != std::string::npos || path.find("\\vivaldi.exe") != std::string::npos) && (cmdline.find("--headless") != std::string::npos && cmdline.find("dump-dom") != std::string::npos && cmdline.find("http") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Chromium based browser launched in headless mode is being used to download files";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Chromium Browser Headless Execution To Mockbin Like Site
// select * from win_process_events where (path like '%\\brave.exe%' or path like '%\\chrome.exe%' or path like '%\\msedge.exe%' or path like '%\\opera.exe%' or path like '%\\vivaldi.exe%') and (cmdline like '%--headless%' and (cmdline like '%://run.mocky%' or cmdline like '%://mockbin%'));

bool chromium_headless_execution_mockbin(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\brave.exe") != std::string::npos || path.find("\\chrome.exe") != std::string::npos || path.find("\\msedge.exe") != std::string::npos || path.find("\\opera.exe") != std::string::npos || path.find("\\vivaldi.exe") != std::string::npos) && (cmdline.find("--headless") != std::string::npos && (cmdline.find("://run.mocky") != std::string::npos || cmdline.find("://mockbin") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Chromium based browser launched in headless mode is being pointed at mockbin";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - File Download From Browser Process Via Inline Link
// select * from win_process_events where (path like '%\\brave.exe%' or path like '%\\chrome.exe%' or path like '%\\msedge.exe%' or path like '%\\opera.exe%' or path like '%\\vivaldi.exe%') and cmdline like '% http%' and (cmdline like '%.dat%' or cmdline like '%.dll%' or cmdline like '%.exe%' or cmdline like '%.hta%' or cmdline like '%.ps1%' or cmdline like '%.txt%' or cmdline like '%.vbe%' or cmdline like '%.vbs%' or cmdline like '%.zip%');

bool file_download_browser_inline_link(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("\\brave.exe") != std::string::npos || path.find("\\chrome.exe") != std::string::npos || path.find("\\msedge.exe") != std::string::npos || path.find("\\opera.exe") != std::string::npos || path.find("\\vivaldi.exe") != std::string::npos) && cmdline.find(" http") != std::string::npos && (cmdline.find(".dat") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".hta") != std::string::npos || cmdline.find(".ps1") != std::string::npos || cmdline.find(".txt") != std::string::npos || cmdline.find(".vbe") != std::string::npos || cmdline.find(".vbs") != std::string::npos || cmdline.find(".zip") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected download of arbitrary files using browser";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1090.003 - Tor Client/Browser Execution
//  select * from win_process_events where path like '%\\tor.exe%' or path like '%\\Tor Browser\\Browser\\firefox.exe%';

bool tor_browser_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	if (path.find("\\tor.exe") != std::string::npos || path.find("\\Tor Browser\\Browser\\firefox.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected use of Tor or Tor Browser to connnect to onion routing networks";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - File Download via CertOC.EXE
// select * from win_process_events where path like '%\\certoc.exe%' and cmdline like '%-GetCACAPS%' and cmdline like '%http%';

bool file_download_certoc(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("certoc.exe") != std::string::npos && cmdline.find("-GetCACAPS") != std::string::npos && cmdline.find("http") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected a download using certoc.exe for malicious purpose";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - File Download From IP Based URL Via CertOC.EXE - Review

// T1102 - Cloudflared Tunnel Connections Cleanup
//  select * from win_process_events where (cmdline like '%tunnel%' and cmdline like '%cleanup%') and (cmdline like '%--config%' or cmdline like '%--connector-id%');

bool cloudflared_tunnel_connection_cleanup(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("tunnel") != std::string::npos && cmdline.find("cleanup") != std::string::npos) && (cmdline.find("--config") != std::string::npos || cmdline.find("--connector-id") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected execution of cloudflared tool for cleanup of tunnel connections";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1102 - Cloudflared Tunnel Execution
//  select * from win_process_events where (cmdline like '% tunnel %' and cmdline like '% run %') and (cmdline like '% --config %' or cmdline like '% --credentials-contents %' or cmdline like '% --credentials-file %' or cmdline like '% --token %');

bool cloudflared_tunnel_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find(" tunnel ") != std::string::npos && cmdline.find(" run ") != std::string::npos) && (cmdline.find(" --config ") != std::string::npos || cmdline.find(" --credentials-contents ") != std::string::npos || cmdline.find(" --credentials-file ") != std::string::npos || cmdline.find(" --token ") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected a cloudflared tool to connect back to a tunnel";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Curl Download And Execute Combination
// select * from win_process_events where cmdline like '% /c %' and cmdline like '%curl %' and cmdline like '%http%' and cmdline like '%-o%' and cmdline like '%&%';

bool curl_download_execute_combination(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find(" /c ") != std::string::npos && cmdline.find("curl ") != std::string::npos && cmdline.find("http") != std::string::npos && cmdline.find("-o") != std::string::npos && cmdline.find("&") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected adversaries using curl to download malicious payload remotely";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Remote File Download Via Desktopimgdownldr Utility
// SELECT * FROM win_process_events WHERE (path LIKE '%\\desktopimgdownldr.exe%' AND parent_path LIKE '%\\desktopimgdownldr.exe%' AND cmdline LIKE '%/lockscreenurl:http%');

bool remote_file_download_desktopimgdownldr(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	std::string parent_path = process_event.entry.parent_path;
	if (path.find("\\desktopimgdownldr.exe") != std::string::npos && parent_path.find("\\desktopimgdownldr.exe") != std::string::npos && cmdline.find("/lockscreenurl:http") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected the desktopimgdownldr utility being used to download a remote file";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1105 - Finger.exe Suspicious Invocation
//
bool finger_invocation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	if (path.find("finger.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected suspicious aged finger.exe tool execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool registry_changes(const ProcessEvent &process_event, Event &rule_event)
{
    std::string action = process_event.entry.action;
    std::string process_name = process_event.entry.process_name;
    std::string owner_uid = process_event.entry.owner_uid;

    if((action == "REG_SETVALUE" || action == "REG_DELETE") && process_name.find("C:\\Windows\\regedit.exe") != std::string::npos && !(owner_uid.find("NT AUTHORITY\\SYSTEM") != std::string::npos))
    {
        if(action =="REG_DELETE"){

        std::stringstream ss;
        ss << "Detected deletion of a registry key";
        rule_event.metadata = ss.str();
        return true;
        }
        if(action =="REG_SETVALUE"){

        std::stringstream ss;
        ss << "Detected modification of a registry key";
        rule_event.metadata = ss.str();
        return true;
        }
    }
    return false;
}

bool agobot_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && value_data.find("nvchip4.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Agobot Backdoor Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool bagleworm_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if(action == "REG_SETVALUE" && target_name.find("USER\\S-1-5-21-1513855291-493545534-2728907929-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\d3dupdate.exe") != std::string::npos && value_data.find("bbeagle.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Bagleworm backdoor activity detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool baglebworm_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if(action == "REG_SETVALUE" && target_name.find("USER\\S-1-5-21-1513855291-493545534-2728907929-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && value_data.find("au.exe") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Bagle.B worm backdoor activity detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool bugbearbworm_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if(action == "REG_SETVALUE" && target_name.find("USER\\S-1-5-21-1513855291-493545534-2728907929-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\EnableAutodial") != std::string::npos && value_data.find("0000001") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Bugbear.B worm backdoor activity detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool deepthroat_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && value_data.find("SystemTray") != std::string::npos)
	{
		std::stringstream ss;
		ss << "DeepThroat Backdoor activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool dnschanger_malware(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces") != std::string::npos && (target_name.find("DhcpNameServer") != std::string::npos || target_name.find("NameServer") != std::string::npos) && value_data.find("85.255") != std::string::npos)
	{
		std::stringstream ss;
		ss << "DNSChanger Malware activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool downloadware_software(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && (value_data.find("MediaLoads Installer") != std::string::npos || value_data.find("DownloadWare") != std::string::npos || value_data == "dw"))
	{
		std::stringstream ss;
		ss << "Downloadware Software activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool girlfriend_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && (value_data.find("Windll.exe") != std::string::npos ))
	{
		std::stringstream ss;
		ss << "Girlfriend backdoor activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool lovgate_virus(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && ((target_name.find("WinGate initialize") != std::string::npos && value_data.find("WinGate.exe -remoteshell") != std::string::npos) || (target_name.find("syshelp") != std::string::npos && value_data.find("syshelp.exe") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "LovGate virus activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool ncat_tls_listener(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
		if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") != std::string::npos && (target_name.find("DisableAutomaticUpdates") != std::string::npos && value_data.find("0") != std::string::npos)){
		std::stringstream ss;
		ss << "ncat tls listener virus activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool sasser_virus(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && target_name.find("avserve.exe") && (value_data.find("avserve.exe") != std::string::npos ))
	{
		std::stringstream ss;
		ss << "Sasser backdoor activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool timesink_spyware(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
    std::string target_name = process_event.entry.target_name;
	std::string value_data = process_event.entry.value_data;
	if((action == "REG_SETVALUE") && ((target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos && (value_data.find("tsad.dll") != std::string::npos || value_data.find("tsadbot.exe") != std::string::npos)) || (target_name.find("MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs") != std::string::npos && value_data.find("flexactv.dll") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Timesink Spyware activity Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool registry_changes_application(const ProcessEvent &process_event, Event &rule_event)
{
	std::string owner_uid = process_event.entry.owner_uid;
    std::string process_name = process_event.entry.process_name;
	std::string value_data = process_event.entry.value_data;

	if( !(process_name.find("system") != std::string::npos || process_name.find("System") != std::string::npos || process_name.find("regedit") != std::string::npos || process_name.find("OneDrive") != std::string::npos || process_name.find("msiexec") != std::string::npos || process_name.find("Temp") != std::string::npos || process_name.find("regsvr") != std::string::npos) && !(owner_uid.find("NT AUTHORITY") != std::string::npos) && !(value_data.empty())){
		std::stringstream ss;
		ss << "Changes in registry via application detected";
		rule_event.metadata = ss.str();
		return true;
	}


	return false;
}