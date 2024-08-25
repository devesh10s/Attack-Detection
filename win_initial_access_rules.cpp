#include <sstream>
#include <unordered_set>
#include "win_initial_access_rules.h"

// T1195: Supply Chain Compromise
// select * from win_process_events where (cmdline like '%ExplorerSync%' and cmdline like '%temp%') or (path like '%schtasks.exe%' and cmdline like '%ExplorerSync%');

bool scheduled_tasks(const ProcessEvent &process_event, Event &rule_event)
{
	if ((process_event.entry.cmdline.find("ExplorerSync") != std::string::npos && process_event.entry.cmdline.find("temp") != std::string::npos) || (process_event.entry.path.find("schtasks.exe") != std::string::npos && process_event.entry.cmdline.find("ExplorerSync") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Malicious Process Scheduled";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

//T1200: Hardware additions
// select * from file where (path like 'D:%' or path like 'E:%' or path like 'F:%' or path like 'G:%' or path like 'H:%') and filename like '%AUTORUN%';
//need to set query for file table in appropriate drive
bool win_hardware_additions(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	if(process_event.entry.filename.find("autorun") != std::string::npos && (path.find("D:") != std::string::npos || path.find("F:") != std::string::npos || path.find("E:") != std::string::npos || path.find("G:") != std::string::npos || path.find("H:") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Autorun file detected in USB";
        	rule_event.metadata = ss.str();
        	return true;
	}
	return false;
}

// T1566: Phishing: Spearphishing Attachment
// select * from win_process_events where cmdline like '%url%' and cmdline like '%OutFile%' and cmdline like '%Invoke-WebRequest%';

bool spearphishing_attack(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("url") != std::string::npos && cmdline.find("OutFile") != std::string::npos && cmdline.find("Invoke-WebRequest") != std::string::npos) // || chrome_extension.entry.permissions.find("://*/"))
	{
		std::stringstream ss;

		ss << "Spearphising emails with malicious attachment detected";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1133 - External Remote Services, Running Chrome VPN Extensions via the Registry 2 vpn extension

bool external_remote_services(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	if (cmdline.find("Wow6432Node\\Google\\Chrome\\Extensions") != std::string::npos && cmdline.find("fcfhplploccackoneaefokcmbjfbkenj") != std::string::npos && cmdline.find("fdcgdnkidjaadafnichfpabhfomcebme") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Chrome VPN Extensions used for gaining access";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1078 - Suspicious Computer Machine Password by PowerShell
// select * from win_process_events where cmdline like '%Reset-ComputerMachinePassword%';

bool suspicious_computer_machine_password_by_powershell(const ProcessEvent &process_event, Event &rule_event)
{
	if (process_event.entry.cmdline.find("Reset-ComputerMachinePassword") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Computer password has been reset by PowerShell";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1566 - Phishing Pattern ISO in Archive
// select * from win_process_events where (cmdline like '\Winrar.exe%' or cmdline like '%\7zFM.exed%' or cmdline like '%\peazip.exe%') and (cmdline like '%\isoburn.exe%' or cmdline like '%\PowerISO.exe%' or cmdline like '%\ImgBurn.exe%');

bool phishing_pattern_ISO_in_archive(const ProcessEvent &process_event, Event &rule_event)
{
	if ((process_event.entry.cmdline.find("\\Winrar.exe") != std::string::npos || process_event.entry.cmdline.find("\\7zFM.exe") != std::string::npos || process_event.entry.cmdline.find("\\peazip.exe") != std::string::npos) && (process_event.entry.cmdline.find("\\isoburn.exe") != std::string::npos || process_event.entry.cmdline.find("\\PowerISO.exe") != std::string::npos || process_event.entry.cmdline.find("\\ImgBurn.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Computer password has been reset by PowerShell";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1505.003 - Suspicious Child Process Of SQL Server
// select * from process_events where parent_path like '%\\sqlservr.exe%' and parent_path like '%C:\\Program Files\\Microsoft SQL Server\\%' and parent_path like '%DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe%' and path like '%C:\\Windows\\System32\\cmd.exe%' and cmdline like '%C:\\Windows\\system32\\cmd.exe%' and (path like '%\\bash.exe%' or path like '%\\bitsadmin.exe%' or path like '%\\cmd.exe%' or path like '%\\netstat.exe%' or path like '%\\ping.exe%' or path like '%\\nltest.exe%' or path like '%\\powershell.exe%' or path like '%\\pwsh.exe%' or path like '%\\regsvr32.exe%' or path like '%\\rundll32.exe%' or path like '%\\sh.exe%' or path like '%\\systeminfo.exe%' or path like '%\\tasklist.exe%' or path like '%\\wsl.exe%');


bool suspicious_child_process_of_sql_server(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if (process_event.entry.parent_path.find("\\sqlservr.exe") != std::string::npos && process_event.entry.parent_path.find("C:\\Program Files\\Microsoft SQL Server\\") != std::string::npos && process_event.entry.parent_path.find("DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe") != std::string::npos && process_event.entry.path.find("C:\\Windows\\System32\\cmd.exe") != std::string::npos && process_event.entry.cmdline.find("C:\\Windows\\system32\\cmd.exe") != std::string::npos && (process_event.entry.path.find("\\bash.exe") != std::string::npos || process_event.entry.path.find("\\bitsadmin.exe") != std::string::npos || process_event.entry.path.find("\\cmd.exe") != std::string::npos || process_event.entry.path.find("\\netstat.exe") != std::string::npos || process_event.entry.path.find("\\ping.exe") != std::string::npos || process_event.entry.path.find("\\nltest.exe") != std::string::npos || process_event.entry.path.find("\\powershell.exe") != std::string::npos || process_event.entry.path.find("\\pwsh.exe") != std::string::npos || process_event.entry.path.find("\\regsvr32.exe") != std::string::npos || process_event.entry.path.find("\\rundll32.exe") != std::string::npos || process_event.entry.path.find("\\sh.exe") != std::string::npos || process_event.entry.path.find("\\systeminfo.exe") != std::string::npos || process_event.entry.path.find("\\tasklist.exe") != std::string::npos || process_event.entry.path.find("\\wsl.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious Child Process Of SQL Server";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1505 - Suspicious Child Process Of Veeam Database
// select * from process_events where  cmdline like '%VEEAMSQL%' and parent_path like '%\\sqlservr.exe%' and (path like '%\\cmd.exe%' or path like '%\\pwsh.exe%' or path like '%\\powershell.exe%' or path like '%\\wsl.exe%' or path like '%\\wt.exe%') and (cmdline like '%-ex%' or cmdline like '%bypass%' or cmdline like '%cscript%' or cmdline like '%http://%' or cmdline like '%mshta%' or cmdline like '%DOwnloadString%' or cmdline like '%https://%' or cmdline like '%regsvr32%' or cmdline like '%rundll32%' or cmdline like '%wscript%' or cmdline like '%copy%') and (path like '%\\net.exe%' or path like '%\\net1.exe%' or path like '%\\netstat.exe%' or path like '%\\nltest.exe%' or path like '%\\ping.exe%' or path like '%\\tasklist.exe%' or path like '%\\whoami.exe%');

bool suspicious_child_process_of_veeam_database(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;

	if ((process_event.entry.cmdline.find("VEEAMSQL") != std::string::npos) && (process_event.entry.parent_path.find("\\sqlservr.exe") != std::string::npos) && (process_event.entry.path.find("\\cmd.exe") != std::string::npos || process_event.entry.path.find("\\powershell.exe") != std::string::npos || process_event.entry.path.find("\\pwsh.exe") != std::string::npos || process_event.entry.path.find("\\wsl.exe") != std::string::npos || process_event.entry.path.find("\\wt.exe") != std::string::npos) && (process_event.entry.cmdline.find("-ex") != std::string::npos || process_event.entry.cmdline.find("bypass") != std::string::npos || process_event.entry.cmdline.find("cscript") != std::string::npos || process_event.entry.cmdline.find("http://") != std::string::npos || process_event.entry.cmdline.find("mshta") != std::string::npos || process_event.entry.cmdline.find("DOwnloadString") != std::string::npos || process_event.entry.cmdline.find("https://") != std::string::npos || process_event.entry.cmdline.find("regsvr32") != std::string::npos || process_event.entry.cmdline.find("rundll32") != std::string::npos || process_event.entry.cmdline.find("wscript") != std::string::npos || process_event.entry.cmdline.find("copy") != std::string::npos) && (process_event.entry.path.find("\\net.exe") != std::string::npos || process_event.entry.path.find("\\net1.exe") != std::string::npos || process_event.entry.path.find("\\netstat.exe") != std::string::npos || process_event.entry.path.find("\\nltest.exe") != std::string::npos || process_event.entry.path.find("\\ping.exe") != std::string::npos || process_event.entry.path.find("\\tasklist.exe") != std::string::npos || process_event.entry.path.find("\\whoami.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Suspicious Child Process Of Veeam Database";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1566.001 - Suspicious Double Extension File Execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%.doc.exe%' OR cmdline LIKE '%.docx.exe%' OR cmdline LIKE '%.xls.exe%' OR cmdline LIKE '%.xlsx.exe%' OR cmdline LIKE '%.ppt.exe%' OR cmdline LIKE '%.pptx.exe%' OR cmdline LIKE '%.rtf.exe%' OR cmdline LIKE '%.pdf.exe%' OR cmdline LIKE '%.txt.exe%' OR cmdline LIKE '%      .exe%' OR cmdline LIKE '%______.exe%' OR cmdline LIKE '%.doc.js%' OR cmdline LIKE '%.docx.js%' OR cmdline LIKE '%.xls.js%' OR cmdline LIKE '%.xlsx.js%' OR cmdline LIKE '%.ppt.js%' OR cmdline LIKE '%.pptx.js%' OR cmdline LIKE '%.rtf.js%' OR cmdline LIKE '%.pdf.js%' OR cmdline LIKE '%.txt.js%' OR cmdline LIKE '%.doc.lnk%' OR cmdline LIKE '%.docx.lnk%' OR cmdline LIKE '%.xls.lnk%' OR cmdline LIKE '%.xlsx.lnk%' OR cmdline LIKE '%.ppt.lnk%' OR cmdline LIKE '%.pptx.lnk%' OR cmdline LIKE '%.rtf.lnk%' OR cmdline LIKE '%.pdf.lnk%' OR cmdline LIKE '%.txt.lnk%') OR (path LIKE '%.doc.exe%' OR path LIKE '%.docx.exe%' OR path LIKE '%.xls.exe%' OR path LIKE '%.xlsx.exe%' OR path LIKE '%.ppt.exe%' OR path LIKE '%.pptx.exe%' OR path LIKE '%.rtf.exe%' OR path LIKE '%.pdf.exe%' OR path LIKE '%.txt.exe%' OR path LIKE '%      .exe%' OR path LIKE '%______.exe%' OR path LIKE '%.doc.js%' OR path LIKE '%.docx.js%' OR path LIKE '%.xls.js%' OR path LIKE '%.xlsx.js%' OR path LIKE '%.ppt.js%' OR path LIKE '%.pptx.js%' OR path LIKE '%.rtf.js%' OR path LIKE '%.pdf.js%' OR path LIKE '%.txt.js%' OR path LIKE '%.doc.lnk%' OR path LIKE '%.docx.lnk%' OR path LIKE '%.xls.lnk%' OR path LIKE '%.xlsx.lnk%' OR path LIKE '%.ppt.lnk%' OR path LIKE '%.pptx.lnk%' OR path LIKE '%.rtf.lnk%' OR path LIKE '%.pdf.lnk%' OR path LIKE '%.txt.lnk%'));

bool suspicious_double_extension_file_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find(".doc.exe") != std::string::npos || cmdline.find(".docx.exe") != std::string::npos || cmdline.find(".xls.exe") != std::string::npos || cmdline.find(".xlsx.exe") != std::string::npos || cmdline.find(".ppt.exe") != std::string::npos || cmdline.find(".pptx.exe") != std::string::npos || cmdline.find(".rtf.exe") != std::string::npos || cmdline.find(".pdf.exe") != std::string::npos || cmdline.find(".txt.exe") != std::string::npos || cmdline.find("      .exe") != std::string::npos || cmdline.find("______.exe") != std::string::npos || cmdline.find(".doc.js") != std::string::npos || cmdline.find(".docx.js") != std::string::npos || cmdline.find(".xls.js") != std::string::npos || cmdline.find(".xlsx.js") != std::string::npos || cmdline.find(".ppt.js") != std::string::npos || cmdline.find(".pptx.js") != std::string::npos || cmdline.find(".rtf.js") != std::string::npos || cmdline.find(".pdf.js") != std::string::npos || cmdline.find(".txt.js") != std::string::npos || cmdline.find(".doc.lnk") != std::string::npos || cmdline.find(".docx.lnk") != std::string::npos || cmdline.find(".xls.lnk") != std::string::npos || cmdline.find(".xlsx.lnk") != std::string::npos || cmdline.find(".ppt.lnk") != std::string::npos || cmdline.find(".pptx.lnk") != std::string::npos || cmdline.find(".rtf.lnk") != std::string::npos || cmdline.find(".pdf.lnk") != std::string::npos || cmdline.find(".txt.lnk") != std::string::npos) || path.find(".doc.exe") != std::string::npos || path.find(".docx.exe") != std::string::npos || path.find(".xls.exe") != std::string::npos || path.find(".xlsx.exe") != std::string::npos || path.find(".ppt.exe") != std::string::npos || path.find(".pptx.exe") != std::string::npos || path.find(".rtf.exe") != std::string::npos || path.find(".pdf.exe") != std::string::npos || path.find(".txt.exe") != std::string::npos || path.find("      .exe") != std::string::npos || path.find("______.exe") != std::string::npos || path.find(".doc.js") != std::string::npos || path.find(".docx.js") != std::string::npos || path.find(".xls.js") != std::string::npos || path.find(".xlsx.js") != std::string::npos || path.find(".ppt.js") != std::string::npos || path.find(".pptx.js") != std::string::npos || path.find(".rtf.js") != std::string::npos || path.find(".pdf.js") != std::string::npos || path.find(".txt.js") != std::string::npos || path.find(".doc.lnk") != std::string::npos || path.find(".docx.lnk") != std::string::npos || path.find(".xls.lnk") != std::string::npos || path.find(".xlsx.lnk") != std::string::npos || path.find(".ppt.lnk") != std::string::npos || path.find(".pptx.lnk") != std::string::npos || path.find(".rtf.lnk") != std::string::npos || path.find(".pdf.lnk") != std::string::npos || path.find(".txt.lnk") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected suspicious double extension files that can be used to hide executables and other impactful file types.";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// T1133 - Remote Access Tool - ScreenConnect Suspicious Execution
// select * from win_process_events where cmdline like '%e=Access&%' AND cmdline like '%y=Guest&%' AND cmdline like '%&p=%' AND cmdline like '%&c=%' AND cmdline like '%&k=%';

bool remote_access_tool_screenconnect_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("e=Access&") != std::string::npos && cmdline.find("y=Guest&") != std::string::npos && cmdline.find("&p=") != std::string::npos && cmdline.find("&c=") != std::string::npos && cmdline.find("&k=") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Detected ScreenConnect program start that established a remote access to that system";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

// // T1566.001 - Suspicious Microsoft OneNote Child Process
// // SELECT * FROM win_process_events WHERE (cmdline LIKE '%.hta%' OR cmdline LIKE '%.vb%' OR cmdline LIKE '%.wsh%' OR cmdline LIKE '%.js%' OR cmdline LIKE '%.ps%' OR cmdline LIKE '%.scr%' OR cmdline LIKE '%.pif%' OR cmdline LIKE '%.bat%' OR cmdline LIKE '%.cmd%');

// bool suspicious_microsoft_onenote_clid_process(const ProcessEvent &process_event, Event &rule_event)
// {
// 	std::string cmdline = process_event.entry.cmdline;

// 	if (cmdline.find(".hta") != std::string::npos || cmdline.find(".vb") != std::string::npos || cmdline.find(".wsh") != std::string::npos || cmdline.find(".js") != std::string::npos || cmdline.find(".ps") != std::string::npos || cmdline.find(".scr") != std::string::npos || cmdline.find(".pif") != std::string::npos || cmdline.find(".bat") != std::string::npos || cmdline.find(".cmd") != std::string::npos)
// 	{
// 		std::stringstream ss;

// 		ss << "Suspicious Microsoft OneNote Child Process";
// 		rule_event.metadata = ss.str();

// 		return true;
// 	}
// 	return false;
// }

// T1566.001 - Execution in Outlook Temp Folder
// SELECT * FROM win_process_events WHERE path LIKE '%\\Temporary Internet Files\\Content.Outlook\\%';

bool execution_in_outlook_temp_folder(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;

	if (path.find("\\Temporary Internet Files\\Content.Outlook\\") != std::string::npos)
	{
		std::stringstream ss;

		ss << "Execution in Outlook Temp Folder";
		rule_event.metadata = ss.str();

		return true;
	}
	return false;
}

bool shells_spawned_by_java(const ProcessEvent &process_event, Event &rule_event)
{
	std::string path = process_event.entry.path;
	std::string parent_path = process_event.entry.parent_path;
	std::string cmdline = process_event.entry.cmdline;

	if (parent_path.find("\\java.exe") != std::string::npos && (path.find("\\cmd.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos) && !(parent_path.find("build") != std::string::npos && cmdline.find("build") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Shell spawned from Java host process detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_shells_spawned_by_java(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.path; //Didnt change cmdline to path
	std::string parent_path = process_event.entry.parent_path;

	if (parent_path.find("\\java.exe") != std::string::npos && (cmdline.find("\\sh.exe") != std::string::npos || cmdline.find("\\bash.exe") != std::string::npos || cmdline.find("\\powershell.exe") != std::string::npos || cmdline.find("\\pwsh.exe") != std::string::npos || cmdline.find("\\schtasks.exe") != std::string::npos || cmdline.find("\\certutil.exe") != std::string::npos || cmdline.find("\\whoami.exe") != std::string::npos || cmdline.find("\\bitsadmin.exe") != std::string::npos || cmdline.find("\\wscript.exe") != std::string::npos || cmdline.find("\\cscript.exe") != std::string::npos || cmdline.find("\\scrcons.exe") != std::string::npos || cmdline.find("\\regsvr32.exe") != std::string::npos || cmdline.find("\\hh.exe") != std::string::npos || cmdline.find("\\wmic.exe") != std::string::npos || cmdline.find("\\mshta.exe") != std::string::npos || cmdline.find("\\rundll32.exe") != std::string::npos || cmdline.find("\\forfiles.exe") != std::string::npos || cmdline.find("\\scriptrunner.exe") != std::string::npos || cmdline.find("\\mftrace.exe") != std::string::npos || cmdline.find("\\AppVLP.exe") != std::string::npos || cmdline.find("\\curl.exe") != std::string::npos || cmdline.find("\\systeminfo.exe") != std::string::npos || cmdline.find("\\net.exe") != std::string::npos || cmdline.find("\\net1.exe") != std::string::npos || cmdline.find("\\reg.exe") != std::string::npos || cmdline.find("\\query.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious shell spawned from Java host process detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool suspicious_shells_spawn_by_java_utility_keytool(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string cmdline = process_event.entry.path; //Didnt change cmdline to path

	if (parent_path.find("\\keytool.exe") != std::string::npos && (cmdline.find("\\cmd.exe") != std::string::npos || cmdline.find("\\sh.exe") != std::string::npos || cmdline.find("\\bash.exe") != std::string::npos || cmdline.find("\\powershell.exe") != std::string::npos || cmdline.find("\\pwsh.exe") != std::string::npos || cmdline.find("\\schtasks.exe") != std::string::npos || cmdline.find("\\certutil.exe") != std::string::npos || cmdline.find("\\whoami.exe") != std::string::npos || cmdline.find("\\bitsadmin.exe") != std::string::npos || cmdline.find("\\wscript.exe") != std::string::npos || cmdline.find("\\cscript.exe") != std::string::npos || cmdline.find("\\scrcons.exe") != std::string::npos || cmdline.find("\\regsvr32.exe") != std::string::npos || cmdline.find("\\hh.exe") != std::string::npos || cmdline.find("\\wmic.exe") != std::string::npos || cmdline.find("\\mshta.exe") != std::string::npos || cmdline.find("\\rundll32.exe") != std::string::npos || cmdline.find("\\forfiles.exe") != std::string::npos || cmdline.find("\\scriptrunner.exe") != std::string::npos || cmdline.find("\\mftrace.exe") != std::string::npos || cmdline.find("\\AppVLP.exe") != std::string::npos || cmdline.find("\\systeminfo.exe") != std::string::npos || cmdline.find("\\reg.exe") != std::string::npos || cmdline.find("\\query.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Suspicious shell spawn from Java utility keytool process detected !";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1190 - Suspicious Processes Spawned by WinRM
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\wsmprovhost.exe%' AND (path LIKE '%\\cmd.exe%' OR path LIKE '%\\sh.exe%' OR path LIKE '%\\bash.exe%' OR path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR path LIKE '%\\wsl.exe%' OR path LIKE '%\\schtasks.exe%' OR path LIKE '%\\certutil.exe%' OR path LIKE '%\\whoami.exe%' OR path LIKE '%\\bitsadmin.exe%'));

bool suspicious_processes_spawned_by_winRM(const ProcessEvent &process_event, Event &rule_event)
{
	std::string parent_path = process_event.entry.parent_path;
	std::string path = process_event.entry.path;

	if (parent_path.find("\\wsmprovhost.exe") != std::string::npos && (path.find("\\cmd.exe") != std::string::npos || path.find("\\sh.exe") != std::string::npos || path.find("\\bash.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\wsl.exe") != std::string::npos || path.find("\\schtasks.exe") != std::string::npos || path.find("\\certutil.exe") != std::string::npos || path.find("\\whoami.exe") != std::string::npos || path.find("\\bitsadmin.exe") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Detected suspicious processes including shells spawnd from WinRM host process.";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//Failed login attempt
//

bool failed_login_attempt(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.provider_name.find("Security") != std::string::npos && process_event.entry.eventid == 4625  && process_event.entry.data.find("0xc000006d") != std::string::npos && process_event.entry.data.find("0xc000006a") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Failed Login attempt detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

//Uncommon ports opened

bool uncommon_ports_opened(const ProcessEvent &process_event, Event &rule_event)
{
    int port = process_event.entry.remote_port;
	std::string local = process_event.entry.local_address;

    // List of common TCP and UDP ports
    std::unordered_set<int> common_ports = {
        // List of common ports
		0,1,2,3,4,6,7,9,13,17,19,20,21,22,23,25,26,30,32,33,37,38,42,43,49,53,53,67,68,69,70,79,80,81,82,83,84,85,88,89,90,99,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5400,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6665,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9418,9443,9500,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389
    };

    // Check if the port is not in the common_ports set
    if (common_ports.find(port) == common_ports.end() && !(local.find("127.0.0.1") != std::string::npos) )
    {
        std::stringstream ss;
        ss << "Uncommon port opened: " << port;
        rule_event.metadata = ss.str();
        return true;
    }

    return false;
}


bool ssh_attempt_successful(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.local_port == 22 && process_event.entry.state.find("ESTABLISHED") != std::string::npos && process_event.entry.action.find("added") != std::string::npos)
	{
		std::stringstream ss;
		ss << "ssh attempt on your device is successful";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


//reverse shell basics
// bool agobot_backdoor(const ProcessEvent &process_event, Event &rule_event)
// {
// 	if(process_event.entry.name.find("agobot.fo") != std::string::npos)
// 	{
// 		std::stringstream ss;
// 		ss << "agobot backdoor open";
// 		rule_event.metadata = ss.str();
// 		return true;
// 	}
// 	return false;
// }

bool fake_smtp_server_detection(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("three_digits") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Fake smtp server detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool finger_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("finger") != std::string::npos && process_event.entry.port == 79)
	{
		std::stringstream ss;
		ss << "Finger backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool fluxay_sensor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("fluxay") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Fluxay sensor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool FsSniffer_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("RemoteNC") != std::string::npos)
	{
		std::stringstream ss;
		ss << "FsSniffer backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool gatecrasher_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("GateCrasher") != std::string::npos && process_event.entry.port == 6969)
	{
		std::stringstream ss;
		ss << "Gatecrasher backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool generic_backdoor_detection(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("220backdoor") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Generic Backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool irc_bot_detection(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("fake-identd") != std::string::npos && process_event.entry.port == 113)
	{
		std::stringstream ss;
		ss << "IRC Bot Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool irc_bot_ident_server(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("auth") != std::string::npos && process_event.entry.port == 113)
	{
		std::stringstream ss;
		ss << "IRC Bot ident server detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool Kibuv_worm_detection(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("three_digits") != std::string::npos && (process_event.entry.port == 7955 || process_event.entry.port == 14920 || process_event.entry.port == 42260 ))
	{
		std::stringstream ss;
		ss << "Kibuv Worm Detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool linux_ftp_server_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("ftp") != std::string::npos && process_event.entry.port == 21)
	{
		std::stringstream ss;
		ss << "Linux FTP server detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool netbus_software(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("netbus") != std::string::npos && process_event.entry.port == 12345)
	{
		std::stringstream ss;
		ss << "Netbus software detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool subseven_detection(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("subseven") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Subseven backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool tftp_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("tftp") != std::string::npos && process_event.entry.port == 69)
	{
		std::stringstream ss;
		ss << "tftp backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool unrealirc_backdoor_detection(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("irc") != std::string::npos && process_event.entry.port == 6667)
	{
		std::stringstream ss;
		ss << "Unrealirc backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}


bool winshell_trojan(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("winshell") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Winshell trojan detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

bool wollf_backdoor(const ProcessEvent &process_event, Event &rule_event)
{
	if(process_event.entry.name.find("wollf") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Wollf backdoor detected";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}
//RDP: AnyDesk Connection
bool anydesk_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string process_name = process_event.entry.process_name;

	// if(process_name.find("AnyDesk.exe") != std::string::npos && process_event.entry.remote_port == 443)
	// {
	// 	std::stringstream ss;
	// 	ss << "Anydesk used to establish connection with remote pc";
	// 	rule_event.metadata = ss.str();
	// 	return true;
	// }

	if(process_name.find("AnyDesk.exe") != std::string::npos && process_event.entry.remote_port == 80)
	{
		std::stringstream ss;
		ss << "Connection established to your Anydesk from a remote pc";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}
//RDP: TeamViewer Connection
bool teamviewer_connection(const ProcessEvent &process_event, Event &rule_event)
{
	std::string process_name = process_event.entry.process_name;


	// if(process_name.find("TeamViewer.exe") != std::string::npos && process_event.entry.remote_port == 443)
	// {
	// 	std::stringstream ss;
	// 	ss << "TeamViewer used to establish connection with remote pc";
	// 	rule_event.metadata = ss.str();
	// 	return true;
	// }

	if(process_name.find("TeamViewer.exe") != std::string::npos && process_event.entry.remote_port == 443)
	{
		std::stringstream ss;
		ss << "Connection established to your TeamViewer from a remote pc";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;

}

//phishing attachment
bool phishing_attachment(const ProcessEvent &process_event, Event &rule_event)
{
	std::string md5 = process_event.entry.md5;
	std::string action = process_event.entry.action;
	if(md5.find("ca95874adad930c6611402fca758f5e4") != std::string::npos && !(action.find("FILE_DELETE") != std::string::npos))
	{
		std::stringstream ss;
		ss << "Phishing attachment found";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}