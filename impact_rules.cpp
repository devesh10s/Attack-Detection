#include "impact_rules.h"
#include <sstream>

// ----------------------------------------------------- Impact ---------------------------------------------------------

// T1485 - DD File Overwrite
// SELECT * FROM bpf_process_events WHERE (path LIKE '%/bin/dd%' OR path LIKE '%/usr/bin/dd%') AND cmdline LIKE '%of=%' AND (cmdline LIKE '%if=/dev/zero%' OR cmdline LIKE '%if=/dev/null%');
//https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd

bool dd_file_overwrite(const ProcessEvent &process_event, Event &rule_event)
{
    if ((process_event.entry.path.find("/bin/dd") != std::string::npos || process_event.entry.path.find("/usr/bin/dd") != std::string::npos) && process_event.entry.cmdline.find("of=") != std::string::npos && (process_event.entry.cmdline.find("if=/dev/zero") != std::string::npos || process_event.entry.cmdline.find("if=/dev/null") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected potential overwriting and deletion of a file using DD.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1531 - Group Has Been Deleted Via Groupdel
// SELECT * FROM bpf_process_events WHERE (path LIKE '%/groupdel%');

bool group_has_been_deleted_via_groupdel(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("/groupdel") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detects execution of the 'groupdel' binary which is used to delete a group, often used by threat actors to cover tracks.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1565.001 - Potential Suspicious Change To Sensitive/Critical Files
// SELECT * FROM bpf_process_events WHERE (((((path LIKE '%/cat%' OR path LIKE '%/echo%' OR path LIKE '%/grep%' OR path LIKE '%/head%' OR path LIKE '%/more%' OR path LIKE '%/tail%') AND cmdline LIKE '%>%') OR (path LIKE '%/emacs%' OR path LIKE '%/nano%' OR path LIKE '%/sed%' OR path LIKE '%/vi%' OR path LIKE '%/vim%')) AND (cmdline LIKE '%/bin/login%' OR cmdline LIKE '%/bin/passwd%' OR cmdline LIKE '%/boot/%' OR cmdline LIKE '%/etc/*.conf%' OR cmdline LIKE '%/etc/cron.%' OR cmdline LIKE '%/etc/crontab%' OR cmdline LIKE '%/etc/hosts%' OR cmdline LIKE '%/etc/init.d%' OR cmdline LIKE '%/etc/sudoers%' OR cmdline LIKE '%/opt/bin/%' OR cmdline LIKE '%/sbin%' OR cmdline LIKE '%/usr/bin/%' OR cmdline LIKE '%/usr/local/bin/%'));

bool potential_suspicious_change_to_sensitive_critical_files(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((((path.find("/cat") != std::string::npos || path.find("/echo") != std::string::npos || path.find("/grep") != std::string::npos || path.find("/head") != std::string::npos || path.find("/more") != std::string::npos || path.find("/tail") != std::string::npos) && cmdline.find(">") != std::string::npos) || (path.find("/emacs") != std::string::npos || path.find("/nano") != std::string::npos || path.find("/sed") != std::string::npos || path.find("/vi") != std::string::npos || path.find("/vim") != std::string::npos)) && (cmdline.find("/bin/login") != std::string::npos || cmdline.find("/bin/passwd") != std::string::npos || cmdline.find("/boot/") != std::string::npos || cmdline.find("/etc/*.conf") != std::string::npos || cmdline.find("/etc/cron.") != std::string::npos || cmdline.find("/etc/crontab") != std::string::npos || cmdline.find("/etc/hosts") != std::string::npos || cmdline.find("/etc/init.d") != std::string::npos || cmdline.find("/etc/sudoers") != std::string::npos || cmdline.find("/opt/bin/") != std::string::npos || cmdline.find("/sbin") != std::string::npos || cmdline.find("/usr/bin/") != std::string::npos || cmdline.find("/usr/local/bin/") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of the 'groupdel' binary which is used to delete a group, often used by threat actors to cover tracks.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1531 - User Has Been Deleted Via Userdel
// SELECT * FROM bpf_process_events WHERE path LIKE '%/userdel%';

bool user_has_been_deleted_via_userdel(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("/userdel") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'userdel' binary which is used to delete a user account.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1565.001 - History File Deletion
// SELECT * FROM process_events WHERE (path LIKE '%/rm%' OR path LIKE '%/unlink%' OR path LIKE '%/shred%') AND (cmdline LIKE '%/.bash_history%' OR cmdline LIKE '%/.zsh_history%');

bool history_file_deletion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("/rm") != std::string::npos || path.find("/unlink") != std::string::npos || path.find("/shred") != std::string::npos) && (cmdline.find("/.bash_history") != std::string::npos && cmdline.find("/.zsh_history") != std::string::npos))
    {
        std::stringstream ss;

        ss << "History File Deletion";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}