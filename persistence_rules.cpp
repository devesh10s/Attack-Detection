#include "persistence_rules.h"
#include <sstream>

// -------------------------------------------------- Persistence ------------------------------------------------------

// T1136 - ESXi Account Creation Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%system%' AND cmdline LIKE '%account%' AND cmdline LIKE '%add%');
// False Positives - Legitimate administration activities

bool ESXi_account_creation_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("system") != std::string::npos && process_event.entry.cmdline.find("account") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected user account creation on ESXi system via esxcli.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1548.001 - Setuid and Setgid
// SELECT * FROM process_events WHERE path LIKE '%chown root%' AND (cmdline LIKE '%chmod u+s%' OR cmdline LIKE '%chmod g+s%');

bool setuid_and_setgid(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("chown root") != std::string::npos && (process_event.entry.cmdline.find(" chmod u+s ") != std::string::npos || process_event.entry.cmdline.find("chmod g+s ") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Setuid and Setgid";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}