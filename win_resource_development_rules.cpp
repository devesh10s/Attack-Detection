#include "win_resource_development_rules.h"
#include <sstream>

// RESOURCE DEVELOPMENT RULES

// T1588.002 - Potential Execution of Sysinternals Tools
// SELECT * FROM win_process_events WHERE cmdline LIKE '%-accepteula%' OR cmdline LIKE '%/accepteula%';

bool potential_execution_of_sysinternals_tools(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("-accepteula") != std::string::npos || cmdline.find("/accepteula") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1587.001 - PsExec/PAExec Escalation to LOCAL SYSTEM
// SELECT * FROM win_process_events WHERE ( cmdline LIKE '% -s cmd%' OR cmdline LIKE '% /s cmd%' OR cmdline LIKE '% -s -i cmd%' OR cmdline LIKE '% /s /i cmd%' OR cmdline LIKE '% /s -i cmd%' OR cmdline LIKE '% -s /i cmd%' OR cmdline LIKE '% -i -s cmd%' OR cmdline LIKE '% /i /s cmd%' OR cmdline LIKE '% -i /s cmd%' OR cmdline LIKE '% /i -s cmd%' OR cmdline LIKE '% -s pwsh%' OR cmdline LIKE '% /s pwsh%' OR cmdline LIKE '% -s -i pwsh%' OR cmdline LIKE '% /s /i pwsh%' OR cmdline LIKE '% /s -i pwsh%' OR cmdline LIKE '% -s /i pwsh%' OR cmdline LIKE '% -i -s pwsh%' OR cmdline LIKE '% /i /s pwsh%' OR cmdline LIKE '% -i /s pwsh%' OR cmdline LIKE '% /i -s pwsh%' OR cmdline LIKE '% -s powershell%' OR cmdline LIKE '% /s powershell%' OR cmdline LIKE '% -s -i powershell%' OR cmdline LIKE '% /s /i powershell%' OR cmdline LIKE '% /s -i powershell%' OR cmdline LIKE '% -s /i powershell%' OR cmdline LIKE '% -i -s powershell%' OR cmdline LIKE '% /i /s powershell%' OR cmdline LIKE '% -i /s powershell%' OR cmdline LIKE '% /i -s powershell%' );


bool psExec_PAExec_escalation_to_LOCAL_SYSTEM(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find(" -s cmd") != std::string::npos || 
    cmdline.find(" /s cmd") != std::string::npos || 
    cmdline.find(" -s -i cmd") != std::string::npos || 
    cmdline.find(" /s /i cmd") != std::string::npos || 
    cmdline.find(" /s -i cmd") != std::string::npos || 
    cmdline.find(" -s /i cmd") != std::string::npos || 
    cmdline.find(" -i -s cmd") != std::string::npos || 
    cmdline.find(" /i /s cmd") != std::string::npos || 
    cmdline.find(" -i /s cmd") != std::string::npos || 
    cmdline.find(" /i -s cmd") != std::string::npos || 
    cmdline.find(" -s pwsh") != std::string::npos || 
    cmdline.find(" /s pwsh") != std::string::npos || 
    cmdline.find(" -s -i pwsh") != std::string::npos || 
    cmdline.find(" /s /i pwsh") != std::string::npos || 
    cmdline.find(" /s -i pwsh") != std::string::npos || 
    cmdline.find(" -s /i pwsh") != std::string::npos || 
    cmdline.find(" -i -s pwsh") != std::string::npos || 
    cmdline.find(" /i /s pwsh") != std::string::npos || 
    cmdline.find(" -i /s pwsh") != std::string::npos || 
    cmdline.find(" /i -s pwsh") != std::string::npos || 
    cmdline.find(" -s powershell") != std::string::npos || 
    cmdline.find(" /s powershell") != std::string::npos || 
    cmdline.find(" -s -i powershell") != std::string::npos || 
    cmdline.find(" /s /i powershell") != std::string::npos || 
    cmdline.find(" /s -i powershell") != std::string::npos || 
    cmdline.find(" -s /i powershell") != std::string::npos || 
    cmdline.find(" -i -s powershell") != std::string::npos || 
    cmdline.find(" /i /s powershell") != std::string::npos || 
    cmdline.find(" -i /s powershell") != std::string::npos || 
    cmdline.find(" /i -s powershell") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1588.002 - Potential Execution of Sysinternals Tools
// SELECT * FROM win_process_events WHERE cmdline LIKE '%accepteula%' AND cmdline LIKE '% -u %' AND cmdline LIKE '% -p %' AND cmdline LIKE '% \\\\\\\\%';

bool potential_PsExec_remote_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;

	if (cmdline.find("accepteula") != std::string::npos &&
    cmdline.find(" -u ") != std::string::npos &&
    cmdline.find(" -p ") != std::string::npos &&
    cmdline.find(" \\\\\\\\") != std::string::npos)
	{
		std::stringstream ss;
		ss << "Detected potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility";
		rule_event.metadata = ss.str();
		return true;
	}
	return false;
}

// T1588.002 - Renamed SysInternals DebugView Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Sysinternals%' OR cmdline LIKE '%DebugView%') AND NOT (path LIKE '%\\Dbgview.exe%');

bool renamed_sysinternals_debugview_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if ((cmdline.find("Sysinternals") != std::string::npos || cmdline.find("DebugView") != std::string::npos) && !(path.find("\\Dbgview.exe") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected suspicious renamed SysInternals DebugView execution";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}

// T1587 - HackTool - PurpleSharp Execution
// SELECT * FROM win_process_events WHERE (path LIKE '%\\purplesharp%' AND (cmdline LIKE '%xyz123456.exe%' OR path LIKE '%PurpleSharp%'));

bool hacktool_purplesharp_execution(const ProcessEvent &process_event, Event &rule_event)
{
	std::string cmdline = process_event.entry.cmdline;
	std::string path = process_event.entry.path;

	if (path.find("\\purplesharp") != std::string::npos && (cmdline.find("xyz123456.exe") != std::string::npos || path.find("PurpleSharp") != std::string::npos))
	{
		std::stringstream ss;

		ss << "Detected the execution of the PurpleSharp adversary simulation tool";
		rule_event.metadata = ss.str();

		return true;
	}

	return false;
}