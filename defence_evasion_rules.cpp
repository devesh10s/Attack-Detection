#include "defence_evasion_rules.h"
#include <sstream>

// ----------------------------------------------------- Defense Evasion ---------------------------------------------------------

// T1055.009 - Potential Linux Process Code Injection Via DD Utility
// SELECT * FROM bpf_process_events WHERE (path LIKE '%dd%' AND cmdline LIKE '%of=%' AND cmdline LIKE '%proc/%' AND cmdline LIKE '%mem%';

bool potential_linux_process_code_injection_via_DD_utility(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("dd") != std::string::npos && process_event.entry.cmdline.find("of=") != std::string::npos && process_event.entry.cmdline.find("proc") != std::string::npos && process_event.entry.cmdline.find("mem") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the injection of code by overwriting the memory map of a Linux process using the 'dd' Linux command.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1562.004 - Ufw Force Stop Using Ufw-Init
// SELECT * FROM bpf_process_events WHERE (cmdline LIKE '%c%' AND cmdline LIKE '%force-stop%') OR (cmdline LIKE '%ufw%' AND cmdline LIKE '%disable%');
// False Positives - Network Administrators

bool ufw_force_stop_using_ufw_init(const ProcessEvent &process_event, Event &rule_event)
{
    if ((process_event.entry.cmdline.find("c") != std::string::npos && process_event.entry.cmdline.find("force-stop") != std::string::npos) || (process_event.entry.cmdline.find("ufw") != std::string::npos && process_event.entry.cmdline.find("disable") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected attempts to force stop the ufw using ufw-init.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1562.001 - ESXi Syslog Configuration Change Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%system%' AND cmdline LIKE '%syslog%' AND cmdline LIKE '%config%' AND cmdline LIKE '%set%');
// Legitimate administrative activities

bool ESXi_syslog_configuration_change_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("system") != std::string::npos && process_event.entry.cmdline.find("syslog") != std::string::npos && process_event.entry.cmdline.find("config") != std::string::npos && process_event.entry.cmdline.find("set") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected changes to the ESXi syslog configuration via 'esxcli'";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1070.004 - File Deletion
// SELECT * FROM bpf_process_events WHERE (path LIKE '%shred%' AND path LIKE '%unlink%');
// Legitimate administrative activities

bool file_deletion(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("shred") != std::string::npos || process_event.entry.path.find("unlink") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detects file deletion using 'shred' or 'unlink' commands, often by adversaries to delete files left behind by the actions of their intrusion activity.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1553.004 - Install Root Certificate
// SELECT * FROM win_process_events WHERE (path LIKE '%update-ca-certificates%' AND path LIKE '%update-ca-trust%');
// Legitimate administrative activities

bool linux_install_root_certificate(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("update-ca-certificates") != std::string::npos || process_event.entry.path.find("update-ca-trust") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1140 - Linux Shell Pipe to Shell
// SELECT * FROM bpf_process_events WHERE (cmdline LIKE '%sh -c %' OR cmdline LIKE '%bash -c %') AND ((cmdline LIKE '%| bash %' OR cmdline LIKE '%| sh %' OR cmdline LIKE '%|bash %' AND cmdline LIKE '%|sh %') OR (cmdline LIKE '%| bash%' OR cmdline LIKE '%| sh%' OR cmdline LIKE '%|bash%' AND cmdline LIKE '% |sh%'));

bool linux_shell_pipe_to_shell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("sh -c ") != std::string::npos || cmdline.find("bash -c ") != std::string::npos) && ((cmdline.find("| bash ") != std::string::npos || cmdline.find("| sh ") != std::string::npos || cmdline.find("|bash ") != std::string::npos || cmdline.find("|sh ") != std::string::npos) || (cmdline.find("| bash") != std::string::npos || cmdline.find("| sh") != std::string::npos || cmdline.find("|bash") != std::string::npos || cmdline.find(" |sh") != std::string::npos)))
    {
        std::stringstream ss;

        ss << "Detected suspicious process command line that starts with a shell and gets piped into another shell.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}


// T1070.006 - Touch Suspicious Service File
// SELECT * FROM bpf_process_events WHERE path LIKE '%/touch%' AND cmdline LIKE '% -t %' AND cmdline LIKE '%.service%';

bool touch_suspicious_service_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/touch") != std::string::npos && cmdline.find(" -t ") != std::string::npos && cmdline.find(".service") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected usage of the 'touch' process in service file.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.006 - Triple Cross eBPF Rootkit Execve Hijack
// SELECT * FROM bpf_process_events WHERE path LIKE '%/sudo%' AND cmdline LIKE '%execve_hijack%';

bool triple_cross_ebpf_rootkit_execve_hijack(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/sudo") != std::string::npos && cmdline.find("execve_hijack") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of a the file 'execve_hijack' to elevate privileges.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1014 - Triple Cross eBPF Rootkit Install Commands
// SELECT * FROM bpf_process_events WHERE path LIKE '%/sudo%' AND (cmdline LIKE '% tc %' AND cmdline LIKE '% enp0s3 %') AND (cmdline LIKE '% qdisc %' OR cmdline LIKE '% filter %');

bool triple_cross_ebpf_rootkit_install_commands(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/sudo") != std::string::npos && (cmdline.find(" tc ") != std::string::npos && cmdline.find(" enp0s3 ") != std::string::npos) && (cmdline.find(" qdisc ") != std::string::npos || cmdline.find(" filter ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected default install commands of the Triple Cross eBPF rootkit.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070 - Linux Package Uninstall
// SELECT * FROM process_events WHERE ((path LIKE '%/yum%' AND (cmdline LIKE '%erase%' OR cmdline LIKE '%remove%')) OR (path LIKE '%/apt%' OR path LIKE '%/apt-get%') AND (cmdline LIKE '%remove%' OR cmdline LIKE '%purge%') OR (path LIKE '%/dpkg%' AND (cmdline LIKE '% -r %' OR cmdline LIKE '%--remove %')) OR (path LIKE '%/rpm%' AND cmdline LIKE '% -e %'));

bool linux_package_uninstall(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/yum") != std::string::npos && (cmdline.find("erase") != std::string::npos || cmdline.find("remove") != std::string::npos)) && ((path.find("/apt") != std::string::npos || path.find("/apt-get") != std::string::npos) && (cmdline.find("remove") != std::string::npos || cmdline.find("purge") != std::string::npos)) && (path.find("/dpkg") != std::string::npos && (cmdline.find(" -r ") != std::string::npos || cmdline.find("--remove ") != std::string::npos)) && (path.find("/rpm") != std::string::npos && cmdline.find(" -e ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Linux Package Uninstall";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Disabling Security Tools
// SELECT * FROM process_events WHERE (path LIKE '%/service%' OR path LIKE '%/chkconfig%' OR path LIKE '%/systemctl%') AND (cmdline LIKE '%iptables%stop%' OR cmdline LIKE '%ip6tables%' OR cmdline LIKE '%firewalld%disable%' OR cmdline LIKE '%cbdaemon%off%' OR cmdline LIKE '%0%' OR cmdline LIKE '%falcon-sensor%');

bool disabling_security_tools(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/service") != std::string::npos && path.find("/chkconfig") != std::string::npos && path.find("/systemctl") != std::string::npos && cmdline.find("iptables") != std::string::npos && cmdline.find("stop") != std::string::npos && cmdline.find("ip6tables") != std::string::npos && cmdline.find("firewalld") != std::string::npos && cmdline.find("disable") != std::string::npos && cmdline.find("cbdaemon") != std::string::npos && cmdline.find("off") != std::string::npos && cmdline.find("0") != std::string::npos && cmdline.find("falcon-sensor") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Disabling Security Tools";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Disable Or Stop Services
// SELECT * FROM process_events WHERE (path LIKE '%/service%' OR path LIKE '%/chkconfig%' OR path LIKE '%/systemctl%') AND (cmdline LIKE '%stop%' OR cmdline LIKE '%disable%');

bool disable_or_stop_services(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/service") != std::string::npos || path.find("/chkconfig") != std::string::npos || path.find("/systemctl") != std::string::npos) && (cmdline.find("stop") != std::string::npos || cmdline.find("disable") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Disable Or Stop Services";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1222.002 - Chmod Suspicious Directory
// SELECT * FROM process_events WHERE path LIKE '%/chmod%' AND (cmdline LIKE '%/tmp/%' OR cmdline LIKE '%/.Library/%' OR cmdline LIKE '%/etc/%' OR cmdline LIKE '%/opt/%');

bool chmod_suspicious_directory(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/chmod") != std::string::npos && (cmdline.find("/tmp/") != std::string::npos || cmdline.find("/.Library/") != std::string::npos || cmdline.find("/etc/") != std::string::npos || cmdline.find("/opt/") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Chmod Suspicious Directory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Potentially Suspicious Execution From Tmp Folder
// SELECT * FROM process_events WHERE path LIKE '%/tmp/%';

bool potentially_suspicious_execution_from_tmp_folder(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/tmp/") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potentially Suspicious Execution From Tmp Folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.004 - Suspicious Package Installed - Linux
// SELECT * FROM win_process_events WHERE (path LIKE '%/apt%' OR path LIKE '%/apt-get%' OR path LIKE '%/yum%' OR path LIKE '%/rpm%' OR path LIKE '%/dpkg%') AND (cmdline LIKE '%install%' OR cmdline LIKE '%localinstall%' OR cmdline LIKE '%-i%' OR cmdline LIKE '%--install%' OR cmdline LIKE '%nmap%' OR cmdline LIKE '%nc%' OR cmdline LIKE '%netcat%' OR cmdline LIKE '%%' OR cmdline LIKE '%wireshark%' OR cmdline LIKE '%tshark%' OR cmdline LIKE '%openconnect%' OR cmdline LIKE '%proxychains%');

bool suspicious_package_installed_linux(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/apt") != std::string::npos || path.find("/apt-get") != std::string::npos || path.find("/yum") != std::string::npos || path.find("/rpm") != std::string::npos || path.find("/dpkg") != std::string::npos) && (cmdline.find("install") != std::string::npos || cmdline.find("localinstall") != std::string::npos || cmdline.find("-i") != std::string::npos || cmdline.find("--install") != std::string::npos || cmdline.find("nmap") != std::string::npos || cmdline.find("nc") != std::string::npos || cmdline.find("netcat") != std::string::npos || cmdline.find("wireshark") != std::string::npos || cmdline.find("tshark") != std::string::npos || cmdline.find("openconnect") != std::string::npos || cmdline.find("proxychains") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detects installation of packages using system installation utilities";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Flush Iptables Ufw Chain
// SELECT * FROM win_process_events WHERE 
//     (
//         path LIKE '%/iptables%' OR 
//         path LIKE '%/xtables-legacy-multi%' OR 
//         path LIKE '%/iptables-legacy-multi%' OR 
//         path LIKE '%/ip6tables%' OR 
//         path LIKE '%/ip6tables-legacy-multi%'
//     ) AND 
//     (
//         cmdline LIKE '%-F%' OR 
//         cmdline LIKE '%-Z%' OR 
//         cmdline LIKE '%-X%' OR 
//         cmdline LIKE '%ufw-logging-deny%' OR 
//         cmdline LIKE '%ufw-logging-allow%' OR 
//         cmdline LIKE '%ufw6-logging-deny%' OR 
//         cmdline LIKE '%ufw6-logging-allow%'
//     );

bool flush_iptables_ufw_chain(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/iptables") != std::string::npos || path.find("/xtables-legacy-multi") != std::string::npos || path.find("/iptables-legacy-multi") != std::string::npos || path.find("/ip6tables") != std::string::npos || path.find("/ip6tables-legacy-multi") != std::string::npos) && (cmdline.find("-F") != std::string::npos || cmdline.find("-Z") != std::string::npos || cmdline.find("-X") != std::string::npos || cmdline.find("ufw-logging-deny") != std::string::npos || cmdline.find("ufw-logging-allow") != std::string::npos || cmdline.find("ufw6-logging-deny") != std::string::npos || cmdline.find("ufw6-logging-allow") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Use of iptables to flush all firewall rules, tables and chains and allow all network traffic detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562 - Terminate Linux Process Via Kill
// SELECT * FROM win_process_events WHERE path LIKE '%/kill%' OR path LIKE '%/pkill%' OR path LIKE '%/killall%';

bool terminate_linux_process_via_kill(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/kill") != std::string::npos || path.find("/pkill") != std::string::npos || path.find("/killall") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of command line tools such as 'kill', 'pkill' or 'killall' to terminate or signal a running process detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1090 - Connection Proxy
// SELECT * FROM win_process_events WHERE cmdline LIKE '%http_proxy=%' OR cmdline LIKE '%https_proxy=%';

bool connection_proxy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (cmdline.find("http_proxy=") != std::string::npos || cmdline.find("https_proxy=") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Setting proxy configuration detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070 - Linux Package Uninstall
// SELECT * FROM win_process_events WHERE 
//     (
//         cmdline LIKE '%erase%' OR 
//         cmdline LIKE '%remove%' OR 
//         cmdline LIKE '%--remove %' OR 
//         cmdline LIKE '%purge%' OR 
//         cmdline LIKE '% -r %' OR 
//         cmdline LIKE '% -e %'
//     ) AND 
//     (
//         path LIKE '%erase%' OR 
//         path LIKE '%/apt%' OR 
//         path LIKE '%/apt-get%' OR 
//         path LIKE '%/dpkg%' OR 
//         path LIKE '%/rpm%'
//     );
