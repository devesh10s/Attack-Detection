#include "privilege_escalation_rules.h"
#include <sstream>

// -------------------------------------------------- Privilege Escalation ------------------------------------------------------

// T1548 - Linux Doas Tool Execution
// SELECT * FROM bpf_process_events WHERE (path LIKE '%doas%');

bool linux_doas_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("doas") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1548 - User Added To Root/Sudoers Group Using Usermod
// SELECT * FROM bpf_process_events WHERE path LIKE '%/usermod%' AND (cmdline LIKE '%-aG root%' OR cmdline LIKE '%-aG sudoers%');

bool user_added_to_root_sudoers_group_using_usermod(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("/usermod") != std::string::npos && (cmdline.find("-aG root") != std::string::npos || cmdline.find("-aG sudoers") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected usage of the 'usermod' binary to add users to the root or suoders groups.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1053.003 - Scheduled Cron Task/Job
// SELECT * FROM process_events WHERE (path LIKE '%crontab%' AND cmdline LIKE '%/tmp/%');

bool scheduled_cron_task_job(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("crontab") != std::string::npos && (cmdline.find("/tmp/") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Scheduled Cron Task/Job";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1548.003 - Sudo Privilege Escalation
// SELECT * FROM process_events WHERE cmdline LIKE '% -u#%';

bool sudo_privilege_escalation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find(" -u#") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Sudo Privilege Escalation";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1068 - OMIGOD SCX RunAsProvider ExecuteScript or Shell
// 

bool omigod_scx_runasprovider_executescript(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("var/opt/microsoft/scx/tmp") != std::string::npos)
    {
        if(cmdline.find("/etc/opt/microsoft/scx/conf/tmpdir/scx") != std::string::npos){
            std::stringstream ss;
            ss << "The use of the SCX RunAsProvider ExecuteScript detected !";
            rule_event.metadata = ss.str();
            return true;
        }
        if(cmdline.find("/bin/sh") != std::string::npos){
            std::stringstream ss;
            ss << "The use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell detected !";
            rule_event.metadata = ss.str();
            return true;
        } 
        
    }
    return false;
}