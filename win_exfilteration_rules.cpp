#include "win_exfilteration_rules.h"
#include <unordered_set>
#include <sstream>

// Exfiltration

// T1020 - Automated Exfiltration
// select * from win_process_events where cmdline like '%Invoke-WebRequest% -Method Put % -InFile %';
bool automated_exfiltration(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("Invoke-WebRequest") != std::string::npos && process_event.entry.cmdline.find("-Method Put") != std::string::npos && process_event.entry.cmdline.find("-InFile") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Automated Exfiltration Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1048.002 - Exfiltration Over Alternative Protocol - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
// select * from win_process_events where path like '%curl.exe%' and (cmdline like '%Curl.exe%' or cmdline like '%curl%') and cmdline like '%file.io%';

bool exfiltration_over_encrypted_protocol(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.path.find("curl.exe") != std::string::npos && (process_event.entry.cmdline.find("curl") != std::string::npos || process_event.entry.cmdline.find("Curl.exe") != std::string::npos) && process_event.entry.cmdline.find("file.io") != std::string::npos)
	{
		rule_event.metadata = "Exfiltration over encrypted protocol";
		return true;
	}
	return false;
}

// T1048.003 - PowerShell ICMP Exfiltration
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%New-Object%' and cmdline like '%System.Net.NetworkInformation.Ping%' and cmdline like '%.Send(%';
bool powershell_ICMP_exfiltration(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Object") != std::string::npos && cmdline.find("System.Net.NetworkInformation.Ping") != std::string::npos && cmdline.find(".Send(") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Powershell is utilizing ping(ICMP) to exfiltrate notepad.exe to a remote address";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1048 - Powershell DNSExfiltration
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Invoke-DNSExfiltrator%' and cmdline like '%-i%' and cmdline like '%-d%' and cmdline like '%-p%' and cmdline like '%-doh%'and cmdline like '%-t%';
bool powershell_DNSExfiltration(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Invoke-DNSExfiltrator") != std::string::npos && cmdline.find("-i") != std::string::npos && cmdline.find("-d") != std::string::npos && cmdline.find("-p") != std::string::npos && cmdline.find("-doh") != std::string::npos && cmdline.find("-t") != std::string::npos)
	{
		std::stringstream ss;
		ss << "DNS exfiltratration using powershell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1048.00 - Powershell Exfiltration Over SMTP
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Send-MailMessage%';
bool powershell_exfiltration_over_SMTP(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Send-MailMessage") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Powershell might've sent an email with attached file to a remote address";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%New-Item%' and cmdline like '%rclone%';
bool exfiltration_over_web_service(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Item") != std::string::npos && cmdline.find("rclone") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Exfiltration to cloud storage";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// Exfiltration


// T1567.001 - Communication To Mega.nz
// select * from win_process_events where cmdline like '%api.mega.co.nz%';
bool communication_to_mega_nz(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("api.mega.co.nz") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Forbidden file sharing might be done to exfiltrate data"; //To be reviewed
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1567.001 - Communication To Ngrok.io
// select * from win_process_events where cmdline like '%.ngrok.io%';
bool communication_to_ngrok_io(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(".ngrok.io") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected executable accessing ngrok.io, indicating data exfiltration by Malicious actors.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1048 - Suspicious Redirection to Local Admin Share
// select * from win_process_events where cmdline like '%\\127.0.0.1\admin$\%' or cmdline like '%\\localhost\admin$\%';
bool suspicious_redirection_to_local_admin_share(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("\\\\127.0.0.1\\admin$\\") != std::string::npos || cmdline.find("\\\\localhost\\admin$\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected a suspicious output redirection to the local admins share";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1012 - Exports Critical Registry Keys To a File
// select * from win_process_events where path like '%\regedit.exe%' and (cmdline like '% /E %' or cmdline like '% -E %') and (cmdline like '%hklm%' or cmdline like '%hkey_local_machine%') and (cmdline like '%\system%' or cmdline like '%\sam%' or cmdline like '%\security%');
bool exports_critical_registry_keys_to_a_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\regedit.exe") != std::string::npos && (cmdline.find(" /E ") != std::string::npos || cmdline.find(" -E ") != std::string::npos) && (cmdline.find("hklm") != std::string::npos || cmdline.find("hkey_local_machine") != std::string::npos) && (cmdline.find("\\system") != std::string::npos || cmdline.find("\\sam") != std::string::npos || cmdline.find("\\security") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected the export of a critical Registry key to a file.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1012 - Exports Registry Key To a File
// select * from win_process_events where path like '%\regedit.exe%' and (cmdline like '% /E %' or cmdline like '% -E %') and  not ((cmdline like '%hklm%' or cmdline like '%hkey_local_machine%') and (cmdline like '%\system%' or cmdline like '%\sam%' or cmdline like '%\security%'));
bool exports_registry_key_to_a_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\regedit.exe") != std::string::npos && (cmdline.find(" /E ") != std::string::npos || cmdline.find(" -E ") != std::string::npos) && !((cmdline.find("hklm") != std::string::npos || cmdline.find("hkey_local_machine") != std::string::npos) && (cmdline.find("\\system") != std::string::npos || cmdline.find("\\sam") != std::string::npos || cmdline.find("\\security") != std::string::npos)))
	{
		std::stringstream ss;
		ss << "Detected the export of a target Registry key to a file.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1048 - Tap Installer Execution
// SELECT * FROM win_process_events WHERE path LIKE '%tapinstall.exe%' AND cmdline LIKE '%\\tap%' AND cmdline LIKE '%VPN%';

bool tap_installer_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	
	{
		std::stringstream ss;
		ss << "Detected installation of TAP Software, possible preparation for data exfiltration using tunneling techniques.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1048 - Email Exifiltration Via Powershell
//select * from win_process_events where
//cmdline like '%Add-PSSnapin%' and
//cmdline like '%Get-Recipient%' and
//cmdline like '%-ExpandProperty%' and
//cmdline like '%EmailAddresses%' and
//cmdline like '%SmtpAddress%' and
//cmdline like '%-hidetableheaders%';

bool email_exfiltration_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\powershell.exe") != std::string::npos &&
	path.find("\\pwsh.exe") != std::string::npos &&
	cmdline.find("Add-PSSnapin") != std::string::npos && 
	cmdline.find("Get-Recipient") != std::string::npos && 
	cmdline.find("-ExpandProperty") != std::string::npos &&
	cmdline.find("EmailAddresses") != std::string::npos &&
	cmdline.find("SmtpAddress") != std::string::npos &&
	cmdline.find("-hidetableheaders") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Email Exifiltration Via Powershell";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1048 - Suspicious PowerShell Mailbox Export to Share
//SELECT * FROM win_process_events WHERE 
//cmdline LIKE '% -Mailbox%' AND
//cmdline LIKE '% -FilePath \\\\\\\\\\\%' AND
//cmdline LIKE '%New-MailboxExportRequest%';


bool suspicious_powershell_mailbox_export_to_share(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(" -Mailbox") != std::string::npos && 
	cmdline.find(" -FilePath \\\\\\\\") != std::string::npos && 
	cmdline.find("New-MailboxExportRequest") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Suspicious PowerShell Mailbox Export to Share";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool active_directory_structure_export_via_ldifdeexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\ldifde.exe") != std::string::npos) && (cmdline.find("-f") != std::string::npos || cmdline.find("-i") != std::string::npos))
	{
		std::stringstream ss;
		ss << "The execution of 'ldifde.exe' in order to export organizational Active Directory structure detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool suspicious_configsecuritypolicy_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\ConfigSecurityPolicy.exe") != std::string::npos) && (cmdline.find("https://") != std::string::npos || cmdline.find("http://") != std::string::npos || cmdline.find("ftp://") != std::string::npos || cmdline.find("ConfigSecurityPolicy.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious ConfigSecurityPolicy execution detected ! (Upload file, credentials or data exfiltration with Binary part of Windows Defender)";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool lolbas_data_exfiltration_by_datasvcutilexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if ((path.find("\\DataSvcUtil.exe") != std::string::npos) && (cmdline.find("/in:") != std::string::npos || cmdline.find("/out:") != std::string::npos || cmdline.find("/uri:") != std::string::npos))
	{
		std::stringstream ss;
		ss << "User performing data exfiltration using DataSvcUtil.exe";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1048.003 - WebDav Client Execution Via Rundll32.EXE
//SELECT * FROM win_process_events WHERE parent_path LIKE '%\svchost.exe%' AND path LIKE '%\rundll32.exe%' AND cmdline LIKE '%C:\windows\system32\davclnt.dll,DavSetCookie%';

bool webdav_client_execution_via_rundll32exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("\\svchost.exe") != std::string::npos && path.find("\\rundll32.exe") != std::string::npos && cmdline.find("C:\\windows\\system32\\davclnt.dll,DavSetCookie") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected exfiltration or use of WebDav to launch code";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1567.002 - PUA - Rclone Execution
//select * from win_process_events where path like '%\\rclone.exe%' and 
//cmdline like '%--config %' and 
//cmdline like '%--no-check-certificate %' and 
//cmdline like '% copy %' and
//(cmdline like '%pass%' or
//cmdline like '%user%' or
//cmdline like '%copy%' or
//cmdline like '%sync%' or
//cmdline like '%config%' or
//cmdline like '%lsd%' or
//cmdline like '%remote%' or
//cmdline like '%ls%' or
//cmdline like '%mega%' or
//cmdline like '%pcloud%' or
//cmdline like '%ftp%' or
//cmdline like '%ignore-existing%' or
//cmdline like '%auto-confirm%' or
//cmdline like '%transfers%' or
//cmdline like '%multi-thread-streams%' or
//cmdline like '%no-check-certificate%');

bool pua_rclone_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\rclone.exe") != std::string::npos && cmdline.find("--config ") != std::string::npos && 
	cmdline.find("--no-check-certificate ") != std::string::npos && 
	cmdline.find(" copy ") != std::string::npos &&
	(cmdline.find("pass") != std::string::npos ||
	cmdline.find("user") != std::string::npos ||
	cmdline.find("copy") != std::string::npos ||
	cmdline.find("sync") != std::string::npos ||
	cmdline.find("config") != std::string::npos ||
	cmdline.find("lsd") != std::string::npos ||
	cmdline.find("remote") != std::string::npos ||
	cmdline.find("ls") != std::string::npos ||
	cmdline.find("mega") != std::string::npos ||
	cmdline.find("pcloud") != std::string::npos ||
	cmdline.find("ftp") != std::string::npos ||
	cmdline.find("ignore-existing") != std::string::npos ||
	cmdline.find("auto-confirm") != std::string::npos ||
	cmdline.find("transfers") != std::string::npos ||
	cmdline.find("multi-thread-streams") != std::string::npos ||
	cmdline.find("no-check-certificate") != std::string::npos))
	{
		std::stringstream ss;
		ss << "PUA - Rclone Execution";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1048.001 - DNS Exfiltration and Tunneling Tools Execution
//
bool dns_exfiltration_tunneling_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	if(path.find("iodine.exe") != std::string::npos || path.find("dnscat2") != std::string::npos)
	{
		std::stringstream ss;
		ss << "DNS Exfiltration tools executed";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1041 - Exfiltration and Tunneling Tools Execution
//
bool exfiltration_tunneling_tools_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	if (path.find("\\plink.exe") || path.find("\\socat.exe") || path.find("\\stunnel.exe") || path.find("\\httptunnel.exe")){
		std::stringstream ss;
		ss << "Execution of well known tools for data exfiltration and tunneling";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}



//Finfisher Keylogger
//    dialoge.exe (MD5: ee5b03b5990dc310b77aac1d32da68de)
    // gpj.1egami.exe (MD5: e82647e42868e0ff0b6357fcf0f6e95f)
    // gpj.stcepsuS detserrA.exe (MD5: b6d700a58965692e92dce5dbc4323391)
    // gpj.bajaR.exe (MD5: d1216d3fd238cd87d9a7e433b6892b98)
    // gpj.1bajaR.exe (MD5: ad6f72b851ebcf7bf7c8b1c551140c5f)
    // wefaq.exe (MD5: cf7b2e1485771967ece90d32f3076814)

bool finfisher_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("ee5b03b5990dc310b77aac1d32da68de") != std::string::npos || md5.find("e82647e42868e0ff0b6357fcf0f6e95f") != std::string::npos || md5.find("b6d700a58965692e92dce5dbc4323391") != std::string::npos || md5.find("d1216d3fd238cd87d9a7e433b6892b98") != std::string::npos || md5.find("ad6f72b851ebcf7bf7c8b1c551140c5f") != std::string::npos || md5.find("cf7b2e1485771967ece90d32f3076814") != std::string::npos )
	{
		std::stringstream ss;
		ss << "Finfisher Keylogger Files detected";
		rule_event.metadata = ss.str();
		return true;
	}
	if(md5.find("0f8249a2593f38c6bf54b6f366c0cac6") != std::string::npos )
	{
		std::stringstream ss;
		ss << "Finfisher Keylogger driver Files detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// //1a808ef944bab7d1a5c09fa70bc6b57c 	
// 	f32d3fd487068e662b16196bd5d25eb7 	
// 	fb164d900f2dac413402f9473b43f14e 	
// 60d14afa33b14c317b30c273481d30d3
// Ghost keylogger 

bool ghost_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("1a808ef944bab7d1a5c09fa70bc6b57c") != std::string::npos || md5.find("f32d3fd487068e662b16196bd5d25eb7") != std::string::npos || md5.find("fb164d900f2dac413402f9473b43f14e") != std::string::npos || md5.find("60d14afa33b14c317b30c273481d30d3") != std::string::npos )
	{
		std::stringstream ss;
		ss << "Ghost Keylogger Files detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//1A0F4CC0513F1B56FEF01C815410C6EA 	60A14FE18925243851E7B89859065C24 	A30BCD0198276E8E28E0E98FA4214E8B 	BDEF67C31299A3D0C10E3608C7EE2BDB 	E35421E937DC29379780972F64542C05
bool snake_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("1a0f4cc0513f1b56fef01c815410c6ea") != std::string::npos || md5.find("60a14fe18925243851e7b89859065c24") != std::string::npos || md5.find("a30bcd0198276e8e28e0e98fa4214e8b") != std::string::npos || md5.find("bdef67c31299a3d0c10e3608c7ee2bdb") != std::string::npos || md5.find("e35421e937dc29379780972f64542c05") != std::string::npos)
	{	
		std::stringstream ss;
		ss << "Snake Keylogger Files detected";
		rule_event.metadata = ss.str();
		return true;

	}
	return false;
}

//DD keylogger
bool dd_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("12b0e0525c4dc2510a26d4f1f2863c75") != std::string::npos || md5.find("78f2acc3309e1e743f98109a16c2b481") != std::string::npos || md5.find("96c28bddba400ddc9a4b12d6cc806aa3") != std::string::npos || md5.find("0e058126f26b54b3a4a950313ec5dbce") != std::string::npos || md5.find("b13ab523e89d9bb055aee4d4566ab34f") != std::string::npos)
	{	
		std::stringstream ss;
		ss << "DD Keylogger Files detected";
		rule_event.metadata = ss.str();
		return true;

	}
	return false;
}

//Jsp Backdoor 
bool jsprat_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("364691d4de2bbead973f31e06ecaf210") != std::string::npos || md5.find("69f187a3072be5e6edf1486ad473016b") != std::string::npos || md5.find("79867b86281293c7f5e4aeccc51cfab9") != std::string::npos )
	{	
		std::stringstream ss;
		ss << "Jsprat backdoor Files detected";
		rule_event.metadata = ss.str();
		return true;

	}
	return false;
}

//Ispy backdoor

bool ispy_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("b99491b53faabb559adf42d6156d9dad") != std::string::npos || md5.find("2b8e2d23c88b11bbcf59928d5d440bdb") != std::string::npos || md5.find("73dcbece89a474bccfb76f022e5e81a4") != std::string::npos || md5.find("c1838d9542e6860cd44d706883b49a73") != std::string::npos || md5.find("2aac4e7b7a1ab407039e12b53a4af942") != std::string::npos || md5.find("398680cbdd017f7b99e9add1477939a8") != std::string::npos || md5.find("2368102c5e12b0c881bc09256546d255") != std::string::npos || md5.find("92a342a6ce4b0accfb20c61fd657104b") != std::string::npos || md5.find("1ffadc9cde4d4a1d794362c9179a0ec9") != std::string::npos || md5.find("c17cddb6f63d9797583167a30c5711c1") != std::string::npos || md5.find("de7db381733f3c5a479865120f58a8c1") != std::string::npos || md5.find("58334fb57165350ccb06c1949459a65c") != std::string::npos || md5.find("5e6114b726b1b8a52331890054157969") != std::string::npos || md5.find("12f4de75e2e299e6d444a58fff78d83d") != std::string::npos || md5.find("92eaac8b2266fb2514e66a8e2cf98f13") != std::string::npos || md5.find("a9867d69c3d7d716339dd10ac4b29216") != std::string::npos || md5.find("edaf8ce53d4919c52e422c7ce7242738") != std::string::npos || md5.find("2b478db2af56153a2cee33f71213cc2f") != std::string::npos || md5.find("214280b4e09fe4c4cc46aebef533e07e") != std::string::npos || md5.find("ba8c47e679eba575c4e8605da97f4e77") != std::string::npos || md5.find("d151378aeae384e85ab10f5bb19ef254") != std::string::npos || md5.find("881e968ddf34c38943a56651a3870174") != std::string::npos || md5.find("0e565eb881a25180993539f34e88ec3d") != std::string::npos )
	{
		std::stringstream ss;
		ss << "Ispy Keylogger Files detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//Kraken Keylogger 

bool kraken_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("79571f0ad832a31a1121f7c698496de7e4700271ccf0a7ed7fe817688528a953") != std::string::npos || md5.find("beec3ec08fba224c161464ebcc64727912c6678dd452596440809ce99c8390fd") != std::string::npos || md5.find("dddaf7dfb95c12acaae7de2673becf94fb9cfa7c2d83413db1ab52a5d9108b79") != std::string::npos || md5.find("f7c66ce4c357c3a7c44dda121f8bb6a62bb3e0bc6f481619b7b5ad83855d628b") != std::string::npos || md5.find("43e79df88e86f344180041d4a4c9381cc69a8ddb46315afd5c4c3ad9e6268e17") != std::string::npos || md5.find("ee76fec4bc7ec334cc6323ad156ea961e27b75eaa7efb4e88212b81e65673000") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Kraken Keylogger Files Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//
bool phoenix_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
		std::string md5 = process_event.entry.md5;
	    std::unordered_set<std::string> hashes = {
        "db38f716369fc629661b139cc4f8ebe837d0f372",
        "d0cde738ecd58a1d57f157e42934eeb80ee33818",
        "b09983f52ab898fbd665eb63f0619a527c2197de",
        "a3483b95d1853a77fff66afd497565d317bf0b4f",
        "07f31d4ce1fb332aaa45adf4cd62959bce3b2a63",
        "591049db2ec06a767ccc107a580470e85a094c58",
        "3f92fffa2aa671eaa8a54ee863095d6559e9511d",
        "75ba438d3a5f46adbdfc31a0be32852015954473",
        "9288e24817a83baf77df6c92a98284acbd9d7a64",
        "72bafd86de64d290becbe3586e3b1d43341b7cf1",
        "7b25c43557cbb7897353cc83ca687a57925174d7",
        "df13e838c0a83934b52da326c06ec83b6418ca3c",
        "ee302d94352ae30fea95ee623cae6f4e76f3e1fa",
        "f5c9353a4bbdbc4954d6a7f9ac7b3e718357d7a7",
        "0ed6ebf045d3ccd809b115606637e7abb9b8f732",
        "24eef89544e5e4ddd09b2be2a23358e9a01efe0a",
        "5d1a930b73159faa85dd0c387ffa00fef7cc0b69",
        "7ade96063b0d971486b33a92a2988a2bb234ce1d",
        "b0a269cce5466527ffbd5fe405309e98ef8a2c8e",
        "dbf3cbeba3095a098c6f0ac37626265a6c4bbc9e",
        "f8fc1f4f8c7288fe9e5e23ea7c7b756d324ed583",
        "70fe24cc1e2c8ad73d19b7d6bd78e7060047d997",
        "24f26a86ba5dee453fc2ffe37aeb208fc2a7cb18",
        "1c92c80c476169bc048151f500364bd2fea0f2dd",
        "8a00aa37e91ec6e2c28ba57420e258c30490bf95",
        "fcc1639ee09b825a2ccbd7733e00772e33dcf2db",
        "39e12df9a59a3d222780d2d44aa9563e10cf564e",
        "6dd0c478b88670a437a887b3a82555690bac991c",
        "2d70c7731d2329165abf449ea1aaacc384f87089",
        "b5ae65280e82885ee0bdb296db73cf35ec529614",
        "0adaeacdbf2eaf49fcf959deb634c415e74c60b5",
        "1554e451e913f8946a487088a202b4ff9bb04b20",
        "2d4bf9d99f3021a3fb4f7088086db00b6b827b57",
        "22c45c37eaa531eb939c2d6a4c58e7e6a2eb02a6",
        "596a594b4d81dd81f0ed6474b8f913b3fe84840e",
        "574bd7bf5f3654d17623b4f66a7b3129f85982de",
        "4bbd0dbcb1d9d57c4ca9d2fe7b488ef469271e52",
        "f0e19b03e9f7ec89251c7d157c2b99bd5a853b41",
		
    };

	for(const auto& str:hashes)
	{
		if(md5 == str)
		{
			std::stringstream ss;
			ss << "Phoenix Keylogger detected";
			rule_event.metadata =  ss.str();
			return true;
		}
		
	}
	return false;
}

//Witchetty Keylogger

bool witchetty_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	if(md5.find("d8326470d5631e58409401fbadfc8157ee247c32b368fb4be70c2b8f8f88427e") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Witchetty keylogger files detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool lookback_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	std::unordered_set<std::string> hashes = {
		"619b64c6728f9ec27bba7912528a4101a9c835a547db6596fa095b3fe628e128",
		"e597aae95dcaccc5677f78d38cd455fa06b74d271fef44bd514e7413772b5dcb",
		"ce3293002a9681736a049301ca5ed6d696d0d46257576929efbb638545ecb78e",
		"73bf59c7f6a28c092a21bf1256db04919084aca5924bbd74277f8bda6191b584",
		"acc52983d5f6b86bec6a81bc3fbe5c195b469def733f7677d681f0e405a1049b",
		"f91e44ff423908b6acf8878dced05dc7188ddab39d1040e0d736f96f0a43518d",
		"e7fcc98005cff9f406a5806222612c20dae3e47c469ff6028310847a599d1a38"
	};

	for(const auto& str:hashes)
	{
		if(md5 == str)
		{
			std::stringstream ss;
			ss << "Lookback Backdoor Files detected";
			rule_event.metadata = ss.str();
			return true;
		}
		
	}
	return false;
}

bool polonium_keylogger(const ProcessEvent &process_event, Event &rule_event)
{
	std::string sha256 = process_event.entry.sha256;
	std::unordered_set<std::string> hashes = {
		"07fc89a40a7b907a50297f5f59e49bdb1691dbcb3e5db27baca072d44975618a",
"54ba6a51bb31617646abd9ee6bda99c4f21a3b9d0cb2489033bddacaab8a1d9d",
"2558633bb4dc36da4878cfee8feff300d0beb86454f5186d44dd3802d155d8be",
"767b0cfd930e27c04fd56f7ceb25e2c660536d0154ffb4de279ebf58de8ef483",
"12a04d9858347c00864138cece6255dc0eabec56c3aae394fb4e2873a85d7b3c",
"84fc4cb4a1a36a4264038554934bf9a6f410e9a9e42c9ab5e8666aff62945fb4",
"b3c6991f6dcf2fdc3bbf55e07d6d940ac2f2e83ce7c9d57a981b8ec17fc87b93",
"3e5e46312b34348df4c6ae416476f4493a44c439397884212c45da59758ed6e2",
"e66df95fad26b8c5141e19161bf5815f4620ff63735c5e14f8b9c0d6c37c5093",
"d01597198609bc65b606aa7b8885a6df7e8769d79bc79b64260d2eaf89edccb0",
"888117eead327786ead3bfbf57f876b8facd9b045dba60ff8e9bcc1b7f3f1a97",
"1f61c4ac44791f3367f92d2ccb474a0505552e8b7fa3bd3cfce97eb6e3a71074",
"d1c473dbb29009071fa7a838ffed6a7425d3eccb775550438610a16ca927e6e3",
"4d4e56a2c199ce5808a38d9ed1f258d306db1b0a04a6bf27f6d7dadc66e64aa7",
"0ef25538fc9da516835a636b3fb4ca6e5c61fcec9f6819044e4ca19e766bb136",
"73bf106069b0fbc05021a1382a8e16ccb1fc42db127aac6b8959290126000c2b",
"7b5787da3affdaf51e495a0cf8b7fa46f18345837dbfb1c4cd7d05b0b692dac9",
"be766d3d560227ed69c30e0a2684b959082c0436772f986181d1fee7a90425bb", 
"ca58e713048fc0570c8af001a5fc489653d91affeb2258681826dd0cde4c50ff", 
"8239e54f663c82984945e9020f510888813795f5a91abe2a3f0f9f08ba1b366b", 
"3788fdbd8f3ce8824c30fafa365184292c784d3f98a317b64c1430316f221ec4", 
"c3b71c21a9e6f261bf42b5dfa016c36f15ed417a55639562d7e2a3640efcc29f",
"326e9a2ae1ee2f4ae7dbb5ddffba8bfe56fc8640c30f020660a09add5030834f",
"859f6b56966143cb4c723d8d1e81514f8c76abab92faecee73d05ab58313acec",
"cd81a0b379c9f0bc2eb34e77ff6e65a1c2f5bfd09a57b09d7d26e0476303051" ,
"dcf4295c4a5b70f82e17b963dd4517ced5d47ff4df56b006733d6fb5c6b4c022",
"3b90ccef1e8762c64a96086e313b4fc25f81d2b48d12f040921a414e129eacf9",
"c36394697e7c250a876f19d0c599de92c8626d882ce1e4aa9795f07fd15d9967",
"dc902546580d4e42f9836535caaae144ce9ce18a441cb1de4d2e2da863c8424f",
"18b31388dc3e44c86edeaff78e1bc8287bfe3b7efb5e5cfd894d2fffdc3cbbef" ,
"314c60cd840def0f5dadefe9df88a87b21c9ccde538c6e29bd5b49a1fd3d2e7a",
"75caa726fbc26b52b8a8e650491c97a514f22b2ae4695652777d0187c1dd8823", 
"78d044d88b37cb45f4f82107726979543eb4e99c3204efa8ad248c5819a67694", "48e18aa2bfd7348730e876e17c5bfcc34d35dd12e9b7be56c9018a1c67c3ce93", "a72c7eec9f6ad77ec75af1c77744c11ab0e297ce6681ee92b5be171344c6d961", "99c94aaad886d97ba5218575ac76a7910015827e1a5bcbefe355071441df460a", 
"6d079d6cbbe56f4187cb66928fd02cc4dff5637925ce1f3ae9fd0e25e6a6194d",
    "1177f0b6365b297e815ae7945ff7a536d61467407fe83fd1a5abc7fc0289b1c7",
    "66800e4526ba617aace7e1ead1ea7e536d95a16cfea64564c8211f78f5a9d2a0",
    "6c26a47b7ca43a4e211e2b1a3f7b96ac0d183dc556af758fb774d38f7824a04c",
    "833ef8c3cad71050fafa83600439dfe4471c52a260f49d2e0451dae286ec10f8",
    "c2eefe59c3683f36e5aba5007b5756cae61b1b1ed0fd40c7c2ff1a5590ab69d8",
    "3074bc18bdd366718ae9783c766486d86b3f810dbb4c95d558c6cd7bfc40c6be",
    "6228792b30e5e89d2fc48d292561909f0d8bd70284a497723d0881ed68414f06",
    "6ce344f39eca48b24a56530bebc82d4046042bde2d255d923b9a60117f759bae",
    "12fcaeb6e2fc29a1273433b580ba637ae810718842567ab7f5a15fa5c71efabf",
    "c251707127444c09bf70961f6a565ffcd335849b298db215ff718e9b0508ac77",
    "1662cc0cbee9877ab0403a2e2caf41ccf5bc6b573721ff7a3806bc32d70b5a47",
    "2a21afa378e221200faa41136b5ef1e0be550e9f7f5524a6340e57f96beb2daa",
    "3c3643e3b4d5958bedfb5e1202b3d973245fe7705006106fa4d0685baa22e7ba",
    "a42fcff2ed20ce197ea3d132b62d45ca9d6cfc35b6c3fda57b473bf3a1dbef13",
    "a0ec02a6d8347cd17473f4b4db6b2d321300e3da8ea77a123287ab3962a4c075",
    "a918fc2045b67a7402bb7df61ae9bdfc82d0aac5092a306c78dfa08398b322f6",
    "1a3e53cc7d21addd8307c733905d136c6d957ba642cda93eb435aab8febe8774",
    "d0d2631214fe655698fc325ae1903a123ff34bfb49f441e9bb97c8d8bfe29e92",
    "f9142cbb6f7af5e1bf532f8306ea82a3c68c2dbe9c1e9e3a6dc31b5c613fc4a2",
    "2a5a11bc2a4e58c32796d0a1939149a895b63c3afe4456d591f7447c1cea089e",
    "d4cfd52cf8f33a25a5b778688c97c79aa8702fdbd45dfd1d2684a306c787bfb1",
    "431fcdefb1bc99ca48df55d40e127afb180dce02ed97d08bbb79fc48bedb6b5a",
    "edf67da07cb5fc6f18d438e1d9387d0716c187975cd513fd1a7da5c76513b740",
    "f72203903b408692a273d7b02f04c9c58bf461d6cfd92879afed7661a0e17b5b",
    "15df4bc5e25582270cf7fb081678a123da21551ce275bc6acb2aabab13ba99f5",
    "13c17e8a8851c42e59148ec0c5005395bb84de3b3709320209f1f3368be65996",
    "0f97bb84205e831d5205e96b43ad45aa48b869a9f35b8906c25492089548ab0a",
    "7568e123d893274c31fdbacdfea619b35b102e278c1bb3d285e3e2816985c4a5",
    "e2bfeff6808a6a7831fb72789823bee9c4d6855b65da03b9c3d5cc0e6db378b8",
    "fa2a1c616b09494654e3e21eb4c842c6ebc4e5ed49240930e365d4bdc197243c",
    "d8a8f9b4b66f4ae964e124e7d22101080764669a5c8b1a2752351fcdf26847be",
    "71997f13eab022812d4e6b340b1611cdad9e0d720d0525278c785c0abcb0458d",
    "427de8fd49572fa7278aae160800cf9920ca0f0addcb5013e7f4447b27b4d3ed",
    "f30bd2e190be3be97d7d247ad7f860f37dd164bd94294a97e96e6c835bfd4f87",
    "049bb63ed4afeff9575fe94f9a1c77a5c708a866db67d516eedd0d66b794888d",
    "fcad08f7f7c7da86d592b14e71adde9a034760d529a617accfa8752b3732e6da",
    "48d848348f6a3177796e42812720bbf0ddb3aa983523d9a01dd8baa2aaeea754",
    "02c216e331b0dbf7c5d9605fc47b97b9c7df1419ad94cda910e5d2e2dd898d81",
    "c30ebed7c492c075b19c04cb98a10cc2a817b97cd872400dbd3642686517df89",
    "a10b27e6a13dd3378a71e8df1333c2ae80fdb6a8363dd4767923d79e517bf188",
    "02d69f04590ff6cae6ef6e3951ab371481779d30b7ac7c940ae030f8042e98fe",
    "14809f399bcda716a3296406ae7943b439482cbf44e2a628b9dcb66d044c8a57",
    "fbccf21f88d0e1af068e39132070ba73959ad09fbcb6bd83adbd9f7f86d9a68b",
    "edd628968dc6148d9cae76208846c4149dd17f99a592d7bfdd8f47a3d81cd57f",
    "325e4f8069f69d685b0d0957e39da8d2aa53cd66b870f3695e5273352812a7f7",
    "bc548f6659e767961ed5c5886057ea2cc6620d5b344cfe51f3df072ee8f467e5",
    "bf6d87c2e11be52eb7adebac42b780e769a411048daa4b00e6f9342872ee6ff0",
    "f3de441c7d60a45b70e4fcefec6aacf8b165af969474f6184e3aca9106fd6a84",
    "7f172ec299f0ed5c025887ef7bde3a663593b37f51b86aa253c8ea99d95ee4c5",
    "2fc7c9db8e443a1b6222f2f14f3a20f879196634783bbfd64b2bfcd135d7c326",
    "337de602c72f3270ca7f70ffb037a3b044e221421b53ceeb16cc189571ca7202",
    "f01375784c1ee38ad4ac6686ed537c825abdeb4575e45971301e5015ffc31a06",
    "0f97287ffb29848d955d44acdfcb9bd1cd62b896e4e9164560026e9d04953a95",
    "ff35945c4218114a1cf6011bd1525fb4d2fdb34f2c74e4b8240b97c99a2ed41f",
    "408be86000f6c7229aa13c348c2cc02a23f91f06b563b2b295c1403d8537fdb7",
    "730c83393000c74702a520c33ae1276ed5e2a5ca4e990fb530e0a7ac6e4e7d16",
    "c057fe516223889c9210acb728437d77120b8796196740a51dc277bf05af5792",
    "67faf062030f6717e11f36a40221694e664830e11235e2c6b761a4d4116bd829",
    "dcbd2a62debbce1a4afb10326fcb066a95add2e57785102dba8f69b41731352a",
    "c62121c4d14bd45acf731b560b7928f0f363540395156954b4fb4d56fdcde449",
    "4045f13aac3c1bf8bc8aacfe5091cc53ac5872b38e43ca17c350bde2f0daa8fa",
    "14f43414ef95a473350ecf952aa929eaa845efa42d83e287673ff773128e95ed",
    "4d13cc0448d14c5748d315cbe7b808d6c24612cacd0b0b333ff5ef17522ccc09",
    "ad8daba56b66c4222f46f1b862ec99d2aa7e9b977c4777c1e06ac44971993124",
    "94aa5ef3147f4b2ddc5498b2d2234a0e2628662f3306cc855bb813baab8f2f9c",
    "a952f614e64f81862cc9405e489832354d20f4eb46401ea42e82c5bdcb9736f1",
    "24cdbf37d701b864940ee34f018a6161a06a08ce9ac9abff7b1201a0d2d67bc8",
    "d7c111c096a0152392437366f8ebcc994cc6f48015ed3e19c352e9d87ad6ff8c"
	};
	for(const auto& str:hashes)
	{
		if(sha256 == str)
		{
			std::stringstream ss;
			ss << "Polonium backdoor detected Files detected";
			rule_event.metadata = ss.str();
			return true;
		}
	}
	return false;
}