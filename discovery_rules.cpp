#include "discovery_rules.h"
#include <sstream>

// -------------------------------------------------- Discovery ------------------------------------------------------

// T1033 - ESXi Network Configuration Discovery Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%network%' AND cmdline LIKE '%get%' AND cmdline LIKE '%list%');
// False Positives - Legitimate administration activities

bool ESXi_network_configuration_discovery_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("network") != std::string::npos && process_event.entry.cmdline.find("get") != std::string::npos && process_event.entry.cmdline.find("list") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'network' flag in order to retrieve information about the network configuration.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1033 - ESXi Storage Information Discovery Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%storage%' AND cmdline LIKE '%get%' AND cmdline LIKE '%list%');
// False Positives - Legitimate administration activities

bool ESXi_storage_information_discovery_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("storage") != std::string::npos && process_event.entry.cmdline.find("get") != std::string::npos && process_event.entry.cmdline.find("list") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'storage' flag in order to retrieve information about the storage status and other related information.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1033 - ESXi System Information Discovery Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%system%' AND cmdline LIKE '%get%' AND cmdline LIKE '%list%');
// False Positives - Legitimate administration activities

bool ESXi_system_information_discovery_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("system") != std::string::npos && process_event.entry.cmdline.find("get") != std::string::npos && process_event.entry.cmdline.find("list") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'system' flag in order to retrieve information about the different component of the system like accounts, modules, etc";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1033 - ESXi VM List Discovery Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%vm process%' AND cmdline LIKE '%list%');
// False Positives - Legitimate administration activities

bool ESXi_VM_list_discovery_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("vm process") != std::string::npos && process_event.entry.cmdline.find("list") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'vm' flag in order to retrieve information about the installed VMs.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1033 - ESXi VSAN Information Discovery Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%vsan%' AND cmdline LIKE '%get%' AND cmdline LIKE '%list%');
// False Positives - Legitimate administration activities

bool ESXi_VSAN_information_discovery_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("vsan") != std::string::npos && process_event.entry.cmdline.find("get") != std::string::npos && process_event.entry.cmdline.find("list") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'vsan' flag in order to retrieve information about virtual storage.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1033 - ESXi VSAN Information Discovery Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%grep%' AND (cmdline LIKE '%aarch64%' OR cmdline LIKE '%arm%' OR cmdline LIKE '%i386%' OR cmdline LIKE '%i686%' OR cmdline LIKE '%mips%' OR cmdline LIKE '%x86_64%'));

bool OS_architecture_discovery_via_grep(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("grep") != std::string::npos && (cmdline.find("aarch64") != std::string::npos || cmdline.find("i386") != std::string::npos || cmdline.find("i686") != std::string::npos || cmdline.find("mips") != std::string::npos || cmdline.find("x86_64") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'vsan' flag in order to retrieve information about virtual storage.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1083 - Apt GTFOBin Abuse - Linux
// SELECT * FROM bpf_process_events WHERE ((path LIKE '%apt%' OR path LIKE '%apt-get%') AND cmdline LIKE '%APT::Update::Pre-Invoke::=%');

bool apt_GTFOBin_abuse_linux(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string cmdline = process_event.entry.cmdline;

    if ((process_event.entry.path.find("apt") != std::string::npos || process_event.entry.path.find("apt-get") != std::string::npos) && cmdline.find("APT::Update::Pre-Invoke::=") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected usage of 'apt' and 'apt-get' as a GTFOBin to execute and proxy command and binary execution.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1083 - Vim GTFOBin Abuse - Linux
// SELECT * FROM bpf_process_events WHERE ((path LIKE '%vim%' OR path LIKE '%rvim%' OR path LIKE '%vimdiff%') AND (cmdline LIKE '% -c %' OR cmdline LIKE '% --cmd%') AND (cmdline LIKE '%:!/%' OR cmdline LIKE '%:py %' OR cmdline LIKE '%:lua %' OR cmdline LIKE '%/bin/sh%' OR cmdline LIKE '%/bin/bash%' OR cmdline LIKE '%/bin/dash%' OR cmdline LIKE '%/bin/zsh%' OR cmdline LIKE '%/bin/fish%'));

bool vim_GTFOBin_abuse_linux(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("vim") != std::string::npos || path.find("rvim") != std::string::npos || path.find("vimdiff") != std::string::npos) && (cmdline.find(" -c ") != std::string::npos || cmdline.find(" --cmd") != std::string::npos) && (cmdline.find(":!/") != std::string::npos || cmdline.find(":py ") != std::string::npos || cmdline.find(":lua ") != std::string::npos || cmdline.find("/bin/sh") != std::string::npos || cmdline.find("/bin/bash") != std::string::npos || cmdline.find("/bin/dash") != std::string::npos || cmdline.find("/bin/zsh") != std::string::npos || cmdline.find("/bin/fish") != std::string::npos))

    {
        std::stringstream ss;

        ss << "Detected usage of 'vim' and it's siblings as a GTFOBin to execute and proxy command and binary execution.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1082 - Potential Container Discovery Via Inodes Listing
// SELECT * FROM bpf_process_events WHERE path LIKE '%/ls%' OR cmdline LIKE '% -*i%' AND cmdline LIKE '% -*d%' AND cmdline LIKE '% /%';

bool potential_container_discovery_via_inodes_listing(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("/ls") != std::string::npos && cmdline.find(" -*i") != std::string::npos && cmdline.find(" -*d") != std::string::npos && cmdline.find(" /") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected listing of the inodes of the '/' directory.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1046 - Linux Network Service Scanning Tools Execution
// SELECT * FROM bpf_process_events WHERE ((path LIKE '%/nc%' OR path LIKE '%/ncat%' OR path LIKE '%/netcat%' OR path LIKE '%/socat%') AND NOT (cmdline LIKE '% --listen %' AND cmdline LIKE '% -l %')) OR (path LIKE '%/autorecon%' OR path LIKE '%/hping%' OR path LIKE '%/hping2%' OR path LIKE '%/hping3%' OR path LIKE '%/naabu%' OR path LIKE '%/nmap%' OR path LIKE '%/nping%' OR path LIKE '%/telnet%');

bool linux_network_service_scanning_tools_execution(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (((path.find("/nc") != std::string::npos || path.find("/ncat") != std::string::npos || path.find("/netcat") != std::string::npos || path.find("/socat") != std::string::npos) && !(cmdline.find(" --listen ") != std::string::npos && cmdline.find(" -l ") != std::string::npos)) || (path.find("/autorecon") != std::string::npos || path.find("/hping") != std::string::npos || path.find("/hping2") != std::string::npos || path.find("/hping3") != std::string::npos || path.find("/naabu") != std::string::npos || path.find("/nmap") != std::string::npos || path.find("/nping") != std::string::npos || path.find("/telnet") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of network scanning and reconnaisance tools.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1082 - System Information Discovery
// SELECT * FROM bpf_process_events WHERE (path LIKE '%/uname%' OR path LIKE '%/hostname%' OR path LIKE '%/uptime%' OR path LIKE '%/lspci%' OR path LIKE '%/dmidecode%' OR path LIKE '%/lscpu%' OR path LIKE '%/lsmod%');


bool linux_system_information_discovery(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;

    if (path.find("/uname") != std::string::npos || path.find("/hostname") != std::string::npos || path.find("/uptime") != std::string::npos || path.find("/lspci") != std::string::npos || path.find("/dmidecode") != std::string::npos || path.find("/lscpu") != std::string::npos || path.find("/lsmod") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected system information discovery commands.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1049 - System Network Connections Discovery - Linux
// SELECT * FROM bpf_process_events WHERE (path LIKE '%/who%' OR path LIKE '%/w%' OR path LIKE '%/last%' OR path LIKE '%/lsof%' OR path LIKE '%/netstat%') AND NOT (path LIKE '%/usr/bin/landscape-sysinfo%' OR path LIKE '%/who%');

bool system_network_connections_discovery_linux(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("/who") != std::string::npos || path.find("/last") != std::string::npos || path.find("/lsof") != std::string::npos || path.find("/netstat") != std::string::npos) && !(path.find("/usr/bin/landscape-sysinfo") != std::string::npos || path.find("/who") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected usage of system utilities to discover system network connections.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1016 - System Network Discovery - Linux
// SELECT * FROM bpf_process_events WHERE ((path LIKE '%/firewall-cmd%' OR path LIKE '%/ufw%' OR path LIKE '%/iptables%' OR path LIKE '%/netstat%' OR path LIKE '%/ss%' OR path LIKE '%/ip%' OR path LIKE '%/ifconfig%' OR path LIKE '%/systemd-resolve%' OR path LIKE '%/route%') OR cmdline LIKE '%/etc/resolv.conf%');


bool system_network_discovery_linux(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("/firewall-cmd") != std::string::npos || path.find("/ufw") != std::string::npos || path.find("/iptables") != std::string::npos || path.find("/netstat") != std::string::npos || path.find("/ss") != std::string::npos || path.find("/ip") != std::string::npos || path.find("/ifconfig") != std::string::npos || path.find("/systemd-resolve") != std::string::npos || path.find("/route") != std::string::npos) || cmdline.find("/etc/resolv.conf") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected enumeration of local network configuration.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1018 - Linux Remote System Discovery
// SELECT * FROM process_events WHERE (path LIKE '%/arp%' OR path LIKE '%/ping%') AND cmdline LIKE '%-a%';

bool linux_remote_system_discovery(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("/arp") != std::string::npos && path.find("/ping") != std::string::npos && cmdline.find("-a") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Linux Remote System Discovery";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1518.001 - Security Software Discovery
// SELECT * FROM process_events WHERE (path LIKE '%/grep%' OR path LIKE '%/egrep%') AND (cmdline LIKE '%nessusd%' OR cmdline LIKE '%td-agent%' OR cmdline LIKE '%packetbeat%' OR cmdline LIKE '%filebeat%' OR cmdline LIKE '%auditbeat%' OR cmdline LIKE '%osqueryd%' OR cmdline LIKE '%cbagentd%' OR cmdline LIKE '%falcond%');

bool security_software_dicovery(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("/grep") != std::string::npos || path.find("/egrep") != std::string::npos) && (cmdline.find("nessusd") != std::string::npos || cmdline.find("td-agent") != std::string::npos || cmdline.find("packetbeat") != std::string::npos || cmdline.find("filebeat") != std::string::npos || cmdline.find("auditbeat") != std::string::npos || cmdline.find("osqueryd") != std::string::npos || cmdline.find("cbagentd") != std::string::npos || cmdline.find("falcond") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Security Software Discovery";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1082 - Container Residence Discovery Via Proc Virtual FS
// SELECT * FROM process_events WHERE (path LIKE '%awk%' OR path LIKE '%/cat%' OR path LIKE '%grep%' OR path LIKE '%/head%' OR path LIKE '%/less%' OR path LIKE '%/more%' OR path LIKE '%/nl%' OR path LIKE '%/tail%') AND (cmdline LIKE '%/proc/2/%') AND (cmdline LIKE '%/proc/%') AND (cmdline LIKE '%/cgroup%' OR cmdline LIKE '%/sched%');

bool container_residence_discovery_via_proc_virtual_fs(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("awk") != std::string::npos || path.find("/cat") != std::string::npos || path.find("grep") != std::string::npos || path.find("/head") != std::string::npos || path.find("/less") != std::string::npos || path.find("/more") != std::string::npos || path.find("/nl") != std::string::npos || path.find("/tail") != std::string::npos) && (cmdline.find("/proc/2/") != std::string::npos) && (cmdline.find("/proc/") != std::string::npos) && (cmdline.find("/cgroup") != std::string::npos || cmdline.find("/sched") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Container Residence Discovery Via Proc Virtual FS";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1082 - Docker Container Discovery Via Dockerenv Listing
// SELECT * FROM process_events WHERE (path LIKE '%/dir%' OR path LIKE '%/cat%' OR path LIKE '%/find%' OR path LIKE '%/ls%' OR path LIKE '%/stat%' OR path LIKE '%/test%' OR path LIKE '%grep%') AND cmdline LIKE '%.dockerenv%';

bool docker_container_discovery_via_dockerenv_listing(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("/dir") != std::string::npos || path.find("/cat") != std::string::npos || path.find("/find") != std::string::npos || path.find("/ls") != std::string::npos || path.find("/stat") != std::string::npos || path.find("/test") != std::string::npos || path.find("grep") != std::string::npos) && (cmdline.find(".dockerenv") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Docker Container Discovery Via Dockerenv Listing";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1083 - Potential Discovery Activity Using Find
// SELECT * FROM process_events WHERE path LIKE '%/find%' AND ( cmdline LIKE '%-perm -4000%' OR cmdline LIKE '%-perm -2000%' OR cmdline LIKE '%-perm 0777%' OR cmdline LIKE '%-perm -222%' OR cmdline LIKE '%-perm -o w%' OR cmdline LIKE '%-perm -o x%' OR cmdline LIKE '%-perm -u=s%' OR cmdline LIKE '%-perm -g=s%');

bool potential_discovery_activity_using_find(const ProcessEvent &process_event, Event &rule_event)
{   
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("/find") != std::string::npos) && (cmdline.find("-perm -4000") != std::string::npos || cmdline.find("-perm -2000") != std::string::npos || cmdline.find("-perm 0777") != std::string::npos || cmdline.find("-perm -222") != std::string::npos || cmdline.find("-perm -o w") != std::string::npos || cmdline.find("-perm -o x") != std::string::npos || cmdline.find("-perm -u=s") != std::string::npos || cmdline.find("-perm -g=s") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Potential Discovery Activity Using Find";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1087.001 - Local System Accounts Discovery - Linux
// SELECT * FROM win_process_events WHERE (path LIKE '%/cat%' OR path LIKE '%/head%' OR path LIKE '%/tail%' OR path LIKE '%/more%' OR path LIKE '%/id%' OR path LIKE '%/lsof%') AND (cmdline LIKE '%/etc/passwd%' OR cmdline LIKE '%/etc/shadow%' OR cmdline LIKE '%/etc/sudoers%' OR cmdline LIKE '%-u%');

bool local_system_accounts_discovery_linux(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/cat") != std::string::npos || path.find("/head") != std::string::npos || path.find("/tail") != std::string::npos || path.find("/more") != std::string::npos || path.find("/id") != std::string::npos || path.find("/lsof") != std::string::npos) && (cmdline.find("/etc/passwd") != std::string::npos || cmdline.find("/etc/shadow") != std::string::npos || cmdline.find("/etc/sudoers") != std::string::npos || cmdline.find("-u") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Enumeration of local system accounts detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1069.001 - Local Groups Discovery - Linux
// SELECT * FROM win_process_events WHERE (path LIKE '%/cat%' OR path LIKE '%/head%' OR path LIKE '%/tail%' OR path LIKE '%/more%' OR path LIKE '%/groups%') AND (cmdline LIKE '%/etc/group%');

bool local_group_discovery_linux(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/cat") != std::string::npos || path.find("/head") != std::string::npos || path.find("/tail") != std::string::npos || path.find("/more") != std::string::npos || path.find("/groups") != std::string::npos) && (cmdline.find("/etc/group") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Enumeration of local system groups detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1082 - Potential GobRAT File Discovery Via Grep
// SELECT * FROM win_process_events WHERE (path LIKE '%/grep%') AND (cmdline LIKE '%apached%' OR cmdline LIKE '%frpc%' OR cmdline LIKE '%sshd.sh%' OR cmdline LIKE '%zone.arm%');

bool potential_gobrat_file_discovery_via_grep(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/grep") != std::string::npos) && (cmdline.find("apached") != std::string::npos || cmdline.find("frpc") != std::string::npos || cmdline.find("sshd.sh") != std::string::npos || cmdline.find("zone.arm") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Use of grep to discover specific files created by the GobRAT malware detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1057 - Process Discovery
// SELECT * FROM win_process_events WHERE path LIKE '%/ps%' OR path LIKE '%/top%';

// bool process_discovery(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;
//     std::string path = process_event.entry.path;

//     if (path.find("/ps") != std::string::npos || path.find("/top") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Process discovery commands detected !";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }