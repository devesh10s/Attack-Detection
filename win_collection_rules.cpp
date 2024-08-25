#include "win_collection_rules.h"
#include <sstream>
#include <iostream>
#include <pqxx/pqxx>
#include <string>
#include <unordered_set>

using namespace std;


// T1113 - Screen Capture
// select * from win_process_events where path like '%psr.exe' and cmdline like '%psr.exe%' and cmdline like '%sc%';

bool screen_capture(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.path.find("psr.exe") != std::string::npos && process_event.entry.cmdline.find("psr.exe") != std::string::npos && process_event.entry.cmdline.find("start") != std::string::npos && process_event.entry.cmdline.find("sc") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Screen capture used for gathering information";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1074.001 - Data Staged: Local Data Staging

// select * from win_process_events where cmdline like '%Invoke-WebRequest%' and cmdline like '%discovery.bat%';

// bool data_staged(const WinFileEvent &win_file_event, Event &rule_event)
// {

// 	if(win_file_event.entry.target_path.find(".bat") != std::string::npos && win_file_event.entry.target_path.find("AppData") != std::string::npos && (win_file_event.entry.process_name.find("powershell") != std::string::npos || win_file_event.entry.process_name.find("cmd") != std::string::npos)) // || chrome_extension.entry.permissions.find("://*/"))
// 	{
// 		std::stringstream ss;

//         	ss << "[" << win_file_event.entry.target_path << ")] Possibly malicious";

//         	rule_event.metadata = ss.str();

//         	return true;
// 	}

// 	return false;
// }

bool data_staged(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.cmdline.find("powershell.exe") != std::string::npos && process_event.entry.cmdline.find("Invoke-WebRequest") != std::string::npos && process_event.entry.cmdline.find("discovery.bat") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Data staged for malicious purpose";

		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1119 - Automated Collection
// select path, parent_path, cmdline from win_process_events where action="PROC_CREATE" and cmdline like '%findstr%' and cmdline like '%temp%' and cmdline like '%copy%' limit 10;

bool automated_collection(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.cmdline.find("findstr") != std::string::npos && process_event.entry.cmdline.find("temp") != std::string::npos && process_event.entry.cmdline.find("copy") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Internal data collected using automated techniques for malicious purpose";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// POWERSHELL!!
//  bool automated_collection_2(const ProcessEvent &process_event, Event &rule_event)
//  {

// 	if(process_event.entry.cmdline.find("Get-Children") != std::string::npos && process_event.entry.cmdline.find("Recurse") != std::string::npos && process_event.entry.cmdline.find("Copy-Item") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;
// 	}

// 	return false;
// }

// T1115 - Clipboard Data
// select * from win_process_events where action='PROC_CREATE' and cmdline like '%clip%' and cmdline like '%.txt%' and cmdline like '%echo%';

bool clipboard_data(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.cmdline.find("clip") != std::string::npos && process_event.entry.cmdline.find(".txt") != std::string::npos && process_event.entry.cmdline.find("echo") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Clipboard data accessed using clip.exe";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1560 - Archive Collected Data
//  select * from win_process_events where cmdline like '%Compress-Archive%' and cmdline like '%Recurse%';

bool archive_collected_data(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.cmdline.find("Compress-Archive") != std::string::npos && process_event.entry.cmdline.find("Recurse") != std::string::npos && process_event.entry.cmdline.find(".zip") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Collected data is archived";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1125 - Video Capture
// select * from win_process_events where path like '%reg%' and cmdline like '%reg%' and cmdline like '%add%' and cmdline like '%webcam%';

bool video_capture(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.path.find("reg.exe") != std::string::npos && process_event.entry.cmdline.find("reg") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos && process_event.entry.cmdline.find("webcam") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Video capture used for gathering information";

		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1039 - Data from Network Shared Drive
// select * from win_process_events where cmdline like '%Easter_Bunny%' and cmdline like '%Easter_egg%';
bool network_shared_drive_data(const ProcessEvent &process_event, Event &rule_event)
{

	if (process_event.entry.cmdline.find("cmd") != std::string::npos && process_event.entry.cmdline.find("Easter_Bunny") != std::string::npos && process_event.entry.cmdline.find("Easter_egg") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Sensitive data collected via shared networks for malicious purpose";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1123 - Audio capture
//  select * from win_process_events where cmdline like '%WindowsAudioDevice-Powershell-Cmdlet%' or (cmdline like '%reg%' and cmdline like '%add%' and cmdline like '%microphone%');

bool audio_capture(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("WindowsAudioDevice-Powershell-Cmdlet") != std::string::npos) || (cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("microphone") != std::string::npos))
	{

		std::stringstream ss;
		ss << "Audio capture used for gathering information";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1056.002 - Input Capture: GUI Input Capture
//  select * from win_process_events where cmdline like '%UI.PromptForCredential%';

bool gui_input_capture(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("UI.PromptForCredential") != std::string::npos)
	{
		std::stringstream ss;
		ss << "OS GUI mimicked to obtain credentials";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1056.001 - Powershell Keylogging
// select * from win_process_events where path like '%powershell.exe' and cmdline like '%Get-Keystrokes%' and cmdline like '%Get-ProcAddress user32.dll GetAsyncKeyState%' and cmdline like '%Get-ProcAddress user32.dll GetForegroundWindow%';

bool powershell_keylogging(const ProcessEvent &process_event, Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-Keystrokes") != std::string::npos && cmdline.find("Get-ProcAddress user32.dll GetAsyncKeyState") != std::string::npos && cmdline.find("Get-ProcAddress user32.dll GetForegroundWindow") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Keystrokes are being captured";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1114.001 - Powershell Local Email Collection
// select * from win_process_events where (path like '%powershell.exe' and (cmdline like '%Get-Inbox.ps1%' or cmdline like '%-comobject outlook.application%'));

bool powershell_local_email_collection(const ProcessEvent &process_event, Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Get-Inbox.ps1") != std::string::npos || cmdline.find("-comobject outlook.application") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Local emails might be exposed";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1119 - Recon Information for Export with PowerShell
// select * from win_process_events where (path like '%powershell.exe' and cmdline like '%Get-Service%' and cmdline like '%Get-ChildItem%' and cmdline like '%Get-Process%');

bool recon_information_for_export_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-Service") != std::string::npos && cmdline.find("Get-ChildItem") != std::string::npos && cmdline.find("Get-Process") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Automated techniques might be used for collecting internal data";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1115 - PowerShell Get Clipboard
// select * from win_process_events where path like '%Get-Clipboard%';

bool powershell_get_clipboard(const ProcessEvent &process_event, Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("Get-Clipboard") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Clipboard data is being captured";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1119 - Automated Collection Command Prompt
// select * from win_process_events where cmdline like '%cmd.exe%' and cmdline like '%dir%' and cmdline like '%/b%' and cmdline like '%/s%' and cmdline like '%findstr%';

bool automated_collection_command_prompt(const ProcessEvent &process_event, Event &rule_event)
{

	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("cmd.exe") != std::string::npos && cmdline.find("dir") != std::string::npos && cmdline.find("/b") != std::string::npos && cmdline.find("/s") != std::string::npos && cmdline.find("findstr") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Automated techniques might be used to collect internal data!";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1560.001 - Suspicious Manipulation Of Default Accounts Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and cmdline like '% user %' and cmdline like '%/active no%' and (cmdline like '%Administrator%' or cmdline like '%guest%' or cmdline like '%DefaultAccount%'));

bool suspicious_manipulation_of_default_accounts_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && cmdline.find(" user ") != std::string::npos && cmdline.find("/active no") != std::string::npos && (cmdline.find("Administrator") != std::string::npos || cmdline.find("guest") != std::string::npos || cmdline.find("DefaultAccount") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious Manipulation Of Default Accounts Via Net.EXE";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1560.001 - Files Added To An Archive Using Rar.EXE
// select * from win_process_events where path like '%\rar.exe%' and cmdline like '% a %';
bool files_added_to_archive_using_rar(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if (path.find("\\rar.exe") != std::string::npos && cmdline.find(" a ") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Rar might have be used to add files to an archive for potential compression";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1560.001 - Rar Usage with Password and Compression Level
// select * from win_process_events where cmdline like '% -hp%' and (cmdline like '% -m%' or cmdline like '% a %');
bool rar_usage_with_password_and_compression_level(const ProcessEvent &process_event, Event &rule_event)

{

	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(" -hp") != std::string::npos && (cmdline.find(" -m") != std::string::npos || cmdline.find(" a ") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Rar might have be used to create an archive with password protection or with a specific compression level";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1039 - Copy from Admin Share
// select * from win_process_events where (cmdline like '%\\robocopy.exe%' or cmdline like '%\\xcopy.exe%') and cmdline like '%cmd.exe%' and cmdline like '%copy-item%' and cmdline like '%move-item%' and cmdline like '%$%';

bool copy_from_admin_share(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("\\robocopy.exe") != std::string::npos || cmdline.find("\\xcopy.exe") != std::string::npos) && cmdline.find("cmd.exe") != std::string::npos && cmdline.find("copy-item") != std::string::npos && cmdline.find("move-item") != std::string::npos && cmdline.find("$") != std::string::npos)
	{

		std::stringstream ss;

		ss << "Detected a suspicious copy command to or from an Admin share or remote";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1119 - Recon Information for Export with Command Prompt
// SELECT * FROM win_process_events WHERE cmdline LIKE '%sc%' AND cmdline LIKE '%query%' AND cmdline LIKE '%TEMP%' AND cmdline LIKE '%doskey%' AND cmdline LIKE '%wmic%' AND cmdline LIKE '%tree%';


bool recon_information_for_export_with_command_prompt(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("sc") != std::string::npos && cmdline.find("query") != std::string::npos && cmdline.find("%TEMP%") != std::string::npos && cmdline.find("doskey") != std::string::npos && cmdline.find("wmic") != std::string::npos && cmdline.find("tree") != std::string::npos)
	{

		std::stringstream ss;

		ss << "An adversary may be using automated techniques for collecting internal data";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1123 - Audio Capture via PowerShell
//select * from win_process_events where
//cmdline like '%WindowsAudioDevice-Powershell-Cmdlet%' or
//cmdline like '%Toggle-AudioDevice%' or
//cmdline like '%Get-AudioDevice%' or
//cmdline like '%Set-AudioDevice%' or
//cmdline like '%Write-AudioDevice%';

bool audio_capture_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("WindowsAudioDevice-Powershell-Cmdlet") != std::string::npos || 
	cmdline.find("Toggle-AudioDevice") != std::string::npos ||
	cmdline.find("Get-AudioDevice") != std::string::npos || 
	cmdline.find("Set-AudioDevice") != std::string::npos || 
	cmdline.find("Write-AudioDevice") != std::string::npos)
	{

		std::stringstream ss;

		ss << "Audio Capture via PowerShell";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1115 - PowerShell Get-Clipboard Cmdlet Via CLI
//select * from win_process_events where cmdline like '%Get-Clipboard%';

bool powershell_get_clipboard_cmdlet_via_cli(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Get-Clipboard") != std::string::npos)
	{

		std::stringstream ss;

		ss << "PowerShell Get-Clipboard Cmdlet Via CLI";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1114 - Exchange PowerShell Snap-Ins Usage
//SELECT * FROM win_process_events WHERE 
//cmdline LIKE '%Add-PSSnapin%' AND
//cmdline LIKE '%$exserver=Get-ExchangeServer ([Environment]::MachineName) -ErrorVariable exerr 2> $null%' AND
//(cmdline LIKE '%Microsoft.Exchange.Powershell.Snapin%' OR
//cmdline LIKE '%Microsoft.Exchange.Management.PowerShell.SnapIn%');

bool exchange_powershell_snapins_usage(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (path.find("\\powershell.exe") != std::string::npos &&
	path.find("\\pwsh.exe") != std::string::npos &&
	parent_path.find("C:\\Windows\\System32\\msiexec.exe") != std::string::npos &&
	cmdline.find("$exserver=Get-ExchangeServer ([Environment]::MachineName) -ErrorVariable exerr 2> $null") != std::string::npos &&
	(cmdline.find("Microsoft.Exchange.Powershell.Snapin") != std::string::npos ||
	cmdline.find("Microsoft.Exchange.Management.PowerShell.SnapIn") != std::string::npos))
	{

		std::stringstream ss;

		ss << "Exchange PowerShell Snap-Ins Usage";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1560.001 - Winrar Compressing Dump Files
// SELECT * FROM win_process_events WHERE (path LIKE '%rar.exe%' OR path LIKE '%winrar.exe%') AND (cmdline LIKE '%.dmp%' OR cmdline LIKE '%.dump%' OR cmdline LIKE '%.hdmp%');

bool winrar_compressing_dump_files(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((path.find("rar.exe") != std::string::npos || path.find("winrar.exe") != std::string::npos) && (cmdline.find(".dmp") != std::string::npos || cmdline.find(".dump") != std::string::npos || cmdline.find(".hdmp") != std::string::npos))
	{

		std::stringstream ss;

		ss << "Detected execution of WinRAR in order to compress a file with a '.dmp'/'.dump'extension, which could be a step in a process of dump file exfiltration.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1560.001 - Compress Data and Lock With Password for Exfiltration With WINZIP
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%winzip%' OR cmdline LIKE '%winzip.exe%' OR cmdline LIKE '%winzip64.exe%') AND cmdline LIKE '%-s"%' AND cmdline LIKE '%-min%' AND cmdline LIKE '%-a%';

bool compress_data_and_lock_with_password_for_exfiltration_with_WINZIP(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if ((cmdline.find("winzip") != std::string::npos || cmdline.find("winzip.exe") != std::string::npos || cmdline.find("winzip64.exe") != std::string::npos) && cmdline.find("-s") != std::string::npos && cmdline.find("-min") != std::string::npos && cmdline.find("-a") != std::string::npos)
	{

		std::stringstream ss;

		ss << "An adversary might be compressing or encrypting data that is collected prior to exfiltration using 3rd party utilities.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1074.001 - Zip A Folder With PowerShell For Staging In Temp
//select * from win_process_events where 
//cmdline like '%Compress-Archive%' and
//cmdline like '% -Path%' and
//cmdline like '% -Destination%' and
//cmdline like '%$env:TEMP\\%';

bool zip_a_folder_with_powershell_for_staging_in_temp(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Compress-Archive") != std::string::npos &&
	cmdline.find(" -Path") != std::string::npos &&
	cmdline.find(" -Destination") != std::string::npos &&
	cmdline.find("$env:TEMP\\") != std::string::npos)
	{

		std::stringstream ss;

		ss << "Zip A Folder With PowerShell For Staging In Temp";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1113 - Psr.exe Capture Screenshots
//select * from win_process_events where 
//cmdline like '%/start%';

bool psr_exe_capture_screenshot(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	
	if (path.find("\\Psr.exe") != std::string::npos && cmdline.find("/start") != std::string::npos)
	{

		std::stringstream ss;

		ss << "Psr.exe Capture Screenshots";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1123 - Audio Capture via SoundRecorder
//select * from win_process_events where path like '%\SoundRecorder.exe%' AND cmdline like '%/FILE%';

bool audio_capture_via_soundrecorder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\SoundRecorder.exe") != std::string::npos && cmdline.find("/FILE") != std::string::npos)
	{

		std::stringstream ss;

		ss << "Detected attacker collecting audio via SoundRecorder application.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1005 - Veeam Backup Database Suspicious Query
//select * from win_process_events where path like '%\sqlcmd.exe%' AND (cmdline like '%VeeamBackup%' AND cmdline like '%From %') AND (cmdline like '%BackupRepositories%' OR cmdline like '%Backups%' OR cmdline like '%Credentials%' OR cmdline like '%HostCreds%' OR cmdline like '%SmbFileShares%' OR cmdline like '%Ssh_creds%' OR cmdline like '%VSphereInfo%');

bool veeam_backup_database_suspicious_query(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sqlcmd.exe") != std::string::npos && (cmdline.find("VeeamBackup") != std::string::npos && cmdline.find("From ") != std::string::npos) && (cmdline.find("BackupRepositories") != std::string::npos || cmdline.find("Backups") != std::string::npos || cmdline.find("Credentials") != std::string::npos || cmdline.find("HostCreds") != std::string::npos || cmdline.find("SmbFileShares") != std::string::npos || cmdline.find("Ssh_creds") != std::string::npos || cmdline.find("VSphereInfo") != std::string::npos))
	{

		std::stringstream ss;

		ss << "Detected potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1005 - VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
//select * from win_process_events where path like '%\sqlcmd.exe%' AND (cmdline like '%SELECT%' AND cmdline like '%TOP%' AND cmdline like '%[VeeamBackup].[dbo].[Credentials]%');

bool veeambackup_database_credentials_dump_via_sqlcmdexe(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\sqlcmd.exe") != std::string::npos && (cmdline.find("SELECT") != std::string::npos && cmdline.find("TOP") != std::string::npos && cmdline.find("[VeeamBackup].[dbo].[Credentials]") != std::string::npos))
	{

		std::stringstream ss;

		ss << "Detected dump of credentials in VeeamBackup dbo.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1560.001 - 7Zip Compressing Dump Files
// select * from win_process_events where cmdline like '%7-zip%' and (cmdline like '%7z.exe%' or cmdline like '%7za.exe%') and (cmdline like '%.dmp%' or cmdline like '%.dump%' or cmdline like '%.hdmp%');

bool compress_and_exfiltrate_dump_files(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("7-zip") != std::string::npos || path.find("7z.exe") != std::string::npos || path.find("7za.exe") != std::string::npos) && (cmdline.find(".dmp") != std::string::npos || cmdline.find(".dump") != std::string::npos || cmdline.find(".hdmp") != std::string::npos))
	{
		std::stringstream ss;

		ss << "An adversary might be compressing the dump files using 7Zip prior to exfitration";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1560.001 -  Compress Data and Lock With Password for Exfiltration With 7-ZIP
//select * from win_process_events where (cmdline like '%7z.exe%' or cmdline like '%7za.exe%') and cmdline like '% -p%' and (cmdline like '% a %' or cmdline like '% u %');


bool compress_data_and_lock_with_password_for_exfiltration_with_7zip(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string cmdline = process_event.entry.cmdline;
	if ((path.find("7z.exe") != std::string::npos || path.find("7za.exe") != std::string::npos) && (cmdline.find(" -p") != std::string::npos) && (cmdline.find(" a ") != std::string::npos || cmdline.find(" u ") != std::string::npos))
	{
		std::stringstream ss;
		ss << "An adversary might be compressing or encrypting data that is collected prior to exfiltration using 3rd party utilities.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1560.001 - Password Protected Compressed File Extraction Via 7Zip
// select * from win_process_events where cmdline like '%7-zip%' and (cmdline like '%7z.exe%' or cmdline like '%7za.exe%') and (cmdline like '%-o%' or cmdline like '%x%' or cmdline like '%-p%');

bool password_protected_compressed_file_7zip(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("7-zip") != std::string::npos && (cmdline.find("7z.exe") != std::string::npos || cmdline.find("7za.exe") != std::string::npos) && (cmdline.find("-o") != std::string::npos || cmdline.find("x") != std::string::npos || cmdline.find("-p") != std::string::npos))
	{
		std::stringstream ss;
		ss << "An adversary might be extracting password protected file using 7zip";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1005 - Esentutl Steals Browser Information
//
bool esentutl_steals_browser_information(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if(path.find("esentutl.exe") != std::string::npos && cmdline.find("/r") != std::string::npos && cmdline.find("-r") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected esentutl.exe to steal sensitive information from Edge";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool usage_winrar_utility_archive_creation(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	if((path.find("winrar.exe") != std::string::npos || path.find("rar.exe") != std::string::npos) && cmdline.find(" a ") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected the creation of a RAR archive using winrar utility with command-line arguments";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//T1003.001 - Dump of lsass from task manager

bool dump_lsass_task_manager(const ProcessEvent &process_event, Event &rule_event)
{
    std::string target_path = process_event.entry.target_path;
    std::string process_name = process_event.entry.process_name;

    if(target_path.find("lsass") != std::string::npos && (target_path.find(".dmp") != std::string::npos || target_path.find(".dump") != std::string::npos) && process_name.find("taskmgr.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << " Detected Certify a tool for Active Directory certificate abuse based on PE metadata";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

//T1003.001 - Abnormal lsass child process

bool abnormal_lsass_child_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    if (parent_path.find("lsass.exe") != std::string::npos &&
    (path.find("cmd.exe") != std::string::npos ||
     path.find("powershell.exe") != std::string::npos ||
     path.find("regsvr32.exe") != std::string::npos ||
     path.find("mstsc.exe") != std::string::npos ||
     path.find("dllhost.exe") != std::string::npos)) {
    std::stringstream ss;
        ss << " Detected the suspicious parent-child relationship for parent lsass.exe.";
        rule_event.metadata = ss.str();
        return true;
}
return false;

}

bool adws_connection_soaphound_binary(const ProcessEvent &process_event, Event &rule_event)
{
	int remote_port = process_event.entry.remote_port;
	std::string process_name = process_event.entry.process_name;
	if (remote_port == 9389 &&
    !(process_name.find("dsac.exe") != std::string::npos ||
      process_name.find("pwsh.exe") != std::string::npos ||
      process_name.find("C:\\Windows\\System32\\WindowsPowerShell\\") != std::string::npos ||
      process_name.find("C:\\Windows\\SysWOW64\\WindowsPowerShell\\") != std::string::npos ||
      process_name.find("C:\\Program Files\\Microsoft Monitoring Agent\\") != std::string::npos)) {
    std::stringstream ss;
		ss << "Detected suspicious connection to AD Web Service (ADWS) port 9389 originating from suspcious processes.";
		rule_event.metadata = ss.str();
		return true;
}
return false;
}

bool delete_test_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string target_path = process_event.entry.target_path;
    std::string action = process_event.entry.action;
    std::string process_name = process_event.entry.process_name;

    if((action.find("FILE_DELETE") != std::string::npos  && process_name.find("explorer.exe") != std::string::npos ) || (action.find("FILE_RENAME") != std::string::npos  && process_name.find("explorer.exe") != std::string::npos && target_path.find("$RECYCLE.BIN") != std::string::npos)) 
    {
        std::stringstream ss;
        ss << " Detected text file delete";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}


//Cut file rule
	std::string extractFileName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

// Function to compare filenames from the original and latter paths
bool compareFileNames(const std::string& input) {
    // Find the positions of the paths in the input string
    size_t origPos = input.find("[Orig: ");
    if (origPos == std::string::npos) {
        return false; // [Orig: not found
    }

    // Extract the latter path (before [Orig: )
    std::string latterPath = input.substr(0, origPos - 1); // -1 to remove trailing space
    // Extract the original path (after [Orig: )
    std::string originalPath = input.substr(origPos + 7, input.length() - origPos - 8); // 7 to skip "[Orig: ", -8 to remove "]"

    // Extract filenames from both paths
    std::string latterFileName = extractFileName(latterPath);
    std::string originalFileName = extractFileName(originalPath);

    // Compare the filenames
    return latterFileName == originalFileName;
}

bool cut_file(const ProcessEvent &process_event, Event &rule_event)
{
	std::string action = process_event.entry.action;
	std::string process_name = process_event.entry.process_name;
if(compareFileNames(process_event.entry.target_path) && action.find("RENAME") != std::string::npos && (process_name.find("explorer") != std::string::npos || process_name.find("dllhost.exe") != std::string::npos)){
	std::stringstream ss;
	ss << "File is cut and pasted at " << process_event.entry.target_path.substr(0, process_event.entry.target_path.find("["));
	rule_event.metadata = ss.str();
	return true;
}
return false;
}


//Copy a file



bool has_matching_md5(long long unixtime, const std::string& md5) {
  try {

     std::string db_name = "fleet";
        std::string user_name = "vajra";
        std::string password = "admin";
        std::string host = "127.0.0.1"; // Or the host address if remote

        // Connection string
        std::string connection_string = "dbname=" + db_name + " user=" + user_name +
                                         " password=" + password + " host=" + host;
    // Create a connection object
    pqxx::connection c(connection_string);

    if (!c.is_open()) {
      return false; // Connection failed
    }

    pqxx::work txn(c);
    std::stringstream query;
    query << "select distinct(md5) from win_file_events where unixtime < " << unixtime << ";";

    // Execute the query
    pqxx::result res = txn.exec(query.str());

    // Check for query execution errors
    if (res.size() == 0) {
      return false; // Error executing query
    }

    std::unordered_set<std::string> md5_values;

    // Store results in the unordered set
    for (pqxx::result::const_iterator c = res.begin(); c != res.end(); ++c) {
      md5_values.insert(c[0].as<std::string>());
    }

    // Search for a match in the unordered set
    return md5_values.count(md5) > 0;

  } catch (const std::exception& e) {
    // Handle exceptions (e.g., log the error)
    return false;
  }
}
bool copy_file(const ProcessEvent &process_event, Event &rule_event)
{

	long long unixtime = process_event.entry.unixtime;
	std::string md5 = process_event.entry.md5;
	std::string process_name = process_event.entry.process_name;
	if(has_matching_md5(unixtime,md5) && process_event.entry.action.find("WRITE") != std::string::npos && (process_name.find("explorer.exe") != std::string::npos || process_name.find("dllhost.exe") != std::string::npos) && !(process_event.entry.target_path.find("Recycle") != std::string::npos || process_event.entry.target_path.find("Recycle") != std::string::npos || process_event.entry.target_path.find("Zone.Identifier") != std::string::npos) )
	{
		std::stringstream ss;
		ss << "File is copy and pasted at " << process_event.entry.target_path;
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

	
}