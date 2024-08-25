#include "execution_rules.h"
#include <sstream>

// ----------------------------------------------------- Execution ---------------------------------------------------------

// TA0002 - ESXi Admin Permission Assigned To Account Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%system%' AND cmdline LIKE '%permission%' AND cmdline LIKE '%set%' AND cmdline LIKE '%Admin%');

bool ESXi_admin_permission_assigned_to_account_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("system") != std::string::npos && process_event.entry.cmdline.find("permission") != std::string::npos && process_event.entry.cmdline.find("set") != std::string::npos && process_event.entry.cmdline.find("Admin") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'system' and 'permission' flags in order to assign admin permissions to an account.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// TA0002 - ESXi VM Kill Via ESXCLI
// SELECT * FROM bpf_process_events WHERE (path LIKE '%esxcli%' AND cmdline LIKE '%vm process%' AND cmdline LIKE '%kill%');

bool ESXi_VM_kill_via_ESXCLI(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("esxcli") != std::string::npos && process_event.entry.cmdline.find("vm process") != std::string::npos && process_event.entry.cmdline.find("kill") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected execution of the 'esxcli' command with the 'system' and 'permission' flags in order to assign admin permissions to an account.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1587 - Linux HackTool Execution
// SELECT * FROM bpf_process_events WHERE (((path LIKE '%/crackmapexec%' OR path LIKE '%/havoc%' OR path LIKE '%/merlin-agent%' OR path LIKE '%/merlinServer-Linux-x64%' OR path LIKE '%/msfconsole%' OR path LIKE '%/msfvenom%' OR path LIKE '%/ps-empire server%' OR path LIKE '%/ps-empire%' OR path LIKE '%/sliver-client%' OR path LIKE '%/sliver-server%' OR path LIKE '%/Villain.py%') OR (path LIKE '%/cobaltstrike%' OR path LIKE '%/teamserver%') OR (path LIKE '%/autorecon%' OR path LIKE '%/httpx%' OR path LIKE '%/legion%' OR path LIKE '%/naabu%' OR path LIKE '%/netdiscover%' OR path LIKE '%/nmap%' OR path LIKE '%/nuclei%' OR path LIKE '%/recon-ng%' OR path LIKE '%/zenmap%') OR (path LIKE '%/sniper%') OR (path LIKE '%/dirb%' OR path LIKE '%/dirbuster%' OR path LIKE '%/eyewitness%' OR path LIKE '%/feroxbuster%' OR path LIKE '%/ffuf%' OR path LIKE '%/gobuster%' OR path LIKE '%/wfuzz%' OR path LIKE '%/whatweb%') OR (path LIKE '%/joomscan%' OR path LIKE '%/nikto%' OR path LIKE '%/wpscan%') OR (path LIKE '%/aircrack-ng%' OR path LIKE '%/bloodhound-python%' OR path LIKE '%/bpfdos%' OR path LIKE '%/ebpfki%' OR path LIKE '%/evil-winrm%' OR path LIKE '%/hashcat%' OR path LIKE '%/hoaxshell.py%' OR path LIKE '%/hydra%' OR path LIKE '%/john%' OR path LIKE '%/ncrack%' OR path LIKE '%/nxc-ubuntu-latest%' OR path LIKE '%/pidhide%' OR path LIKE '%/pspy32%' OR path LIKE '%/pspy32s%' OR path LIKE '%/pspy64%' OR path LIKE '%/pspy64s%' OR path LIKE '%/setoolkit%' OR path LIKE '%/sqlmap%' OR path LIKE '%/writeblocker%') OR (path LIKE '%/linpeas%')));

bool linux_hacktool_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if ((path.find("/crackmapexec") != std::string::npos || path.find("/havoc") != std::string::npos || path.find("/merlin-agent") != std::string::npos || path.find("/merlinServer-Linux-x64") != std::string::npos || path.find("/msfconsole") != std::string::npos || path.find("/msfvenom") != std::string::npos || path.find("/ps-empire server") != std::string::npos || path.find("/ps-empire") != std::string::npos || path.find("/sliver-client") != std::string::npos || path.find("/sliver-server") != std::string::npos || path.find("/Villain.py") != std::string::npos) || (path.find("/cobaltstrike") != std::string::npos || path.find("/teamserver") != std::string::npos) || (path.find("/autorecon") != std::string::npos || path.find("/httpx") != std::string::npos || path.find("/legion") != std::string::npos || path.find("/naabu") != std::string::npos || path.find("/netdiscover") != std::string::npos || path.find("/nmap") != std::string::npos || path.find("/nuclei") != std::string::npos || path.find("/recon-ng") != std::string::npos || path.find("/zenmap") != std::string::npos) || (path.find("/sniper") != std::string::npos) || (path.find("/dirb") != std::string::npos || path.find("/dirbuster") != std::string::npos || path.find("/eyewitness") != std::string::npos || path.find("/feroxbuster") != std::string::npos || path.find("/ffuf") != std::string::npos || path.find("/gobuster") != std::string::npos || path.find("/wfuzz") != std::string::npos || path.find("/whatweb") != std::string::npos) || (path.find("/joomscan") != std::string::npos || path.find("/nikto") != std::string::npos || path.find("/wpscan") != std::string::npos) || (path.find("/aircrack-ng") != std::string::npos || path.find("/bloodhound-python") != std::string::npos || path.find("/bpfdos") != std::string::npos || path.find("/ebpfki") != std::string::npos || path.find("/evil-winrm") != std::string::npos || path.find("/hashcat") != std::string::npos || path.find("/hoaxshell.py") != std::string::npos || path.find("/hydra") != std::string::npos || path.find("/john") != std::string::npos || path.find("/ncrack") != std::string::npos || path.find("/nxc-ubuntu-latest") != std::string::npos || path.find("/pidhide") != std::string::npos || path.find("/pspy32") != std::string::npos || path.find("/pspy32s") != std::string::npos || path.find("/pspy64") != std::string::npos || path.find("/pspy64s") != std::string::npos || path.find("/setoolkit") != std::string::npos || path.find("/sqlmap") != std::string::npos || path.find("/writeblocker") != std::string::npos) || (path.find("/linpeas") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected known hacktool execution based on image name.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059.004 - Interactive Bash Suspicious Children
// SELECT * FROM bpf_process_events WHERE cmdline LIKE '%bash -i%' AND ((cmdline LIKE '%-c import %' OR cmdline LIKE '%base64%' OR cmdline LIKE '%pty.spawn%') OR (path LIKE '%whoami%' OR path LIKE '%iptables%' OR path LIKE '%/ncat%' OR path LIKE '%/nc%' OR path LIKE '%/netcat%'));

bool interactive_bash_suspicious_children(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("bash -i") != std::string::npos && ((cmdline.find("-c import ") != std::string::npos || cmdline.find("base64") != std::string::npos || cmdline.find("pty.spawn") != std::string::npos) || (path.find("whoami") != std::string::npos || path.find("iptables") != std::string::npos || path.find("/ncat") != std::string::npos || path.find("/nc") != std::string::npos || path.find("/netcat") != std::string::npos)))
    {
        std::stringstream ss;

        ss << "Detected suspicious interactive bash as a parent to rather uncommon child processes.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Suspicious Java Children Processes
// SELECT * FROM bpf_process_events WHERE path LIKE '%/java%' AND (cmdline LIKE '%/bin/sh%' OR cmdline LIKE '%bash%' OR cmdline LIKE '%dash%' OR cmdline LIKE '%ksh%' OR cmdline LIKE '%zsh%' OR cmdline LIKE '%csh%' OR cmdline LIKE '%fish%' OR cmdline LIKE '%curl%' OR cmdline LIKE '%wget%' OR cmdline LIKE '%python%');

bool suspicious_java_children_processes(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("/java") != std::string::npos && (cmdline.find("/bin/sh") != std::string::npos || cmdline.find("bash") != std::string::npos || cmdline.find("dash") != std::string::npos || cmdline.find("ksh") != std::string::npos || cmdline.find("zsh") != std::string::npos || cmdline.find("csh") != std::string::npos || cmdline.find("fish") != std::string::npos || cmdline.find("curl") != std::string::npos || cmdline.find("wget") != std::string::npos || cmdline.find("python") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected java process spawning suspicious children.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Shell Execution Of Process Located In Tmp Directory
// SELECT * FROM bpf_process_events WHERE (path LIKE '%/tmp/%' AND (path LIKE '%/bash%' OR path LIKE '%/csh%' OR path LIKE '%/dash%' OR path LIKE '%/fish%' OR path LIKE '%/ksh%' OR path LIKE '%/sh%' OR path LIKE '%/zsh%'));

bool shell_execution_of_process_located_in_tmp_directory(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("/tmp/") != std::string::npos && (path.find("/bash") != std::string::npos || path.find("/csh") != std::string::npos || path.find("/dash") != std::string::npos || path.find("/fish") != std::string::npos || path.find("/ksh") != std::string::npos || path.find("/sh") != std::string::npos || path.find("/zsh") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of shells from a parent process located in a temporary directory.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Execution Of Script Located In Potentially Suspicious Directory
// SELECT * FROM bpf_process_events WHERE (cmdline LIKE '%/tmp/%' AND cmdline LIKE '% -c %' AND (path LIKE '%/bash%' OR path LIKE '%/csh%' OR path LIKE '%/dash%' OR path LIKE '%/fish%' OR path LIKE '%/ksh%' OR path LIKE '%/sh%' OR path LIKE '%/zsh%'));

bool execution_of_script_located_in_potentially_suspicious_directory(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("/tmp/") != std::string::npos && cmdline.find(" -c ") != std::string::npos && (path.find("/bash") != std::string::npos || path.find("/csh") != std::string::npos || path.find("/dash") != std::string::npos || path.find("/fish") != std::string::npos || path.find("/ksh") != std::string::npos || path.find("/sh") != std::string::npos || path.find("/zsh") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected executions of scripts located in potentially suspicious locations via a shell.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Potential Xterm Reverse Shell
// SELECT * FROM bpf_process_events WHERE path LIKE '%xterm%' AND cmdline LIKE '%-display%' AND cmdline LIKE '%:1%';

bool potential_xterm_reverse_shell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("xterm") != std::string::npos && cmdline.find("-display") != std::string::npos && cmdline.find(":1") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected usage of 'xterm' as a potential reverse shell tunnel.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Potential Netcat Reverse Shell Execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%nc%' OR cmdline LIKE '%ncat%' OR cmdline LIKE '%netcat%') AND (cmdline LIKE '%-c%' OR cmdline LIKE '%-e%') AND (cmdline LIKE '%ash%' OR cmdline LIKE '%bash%' OR cmdline LIKE '%bsh%' OR cmdline LIKE '%csh%' OR cmdline LIKE '%ksh%' OR cmdline LIKE '%pdksh%' OR cmdline LIKE '%sh%' OR cmdline LIKE '%tcsh%' OR cmdline LIKE '%/bin/ash%' OR cmdline LIKE '%/bin/bash%' OR cmdline LIKE '%/bin/bsh%' OR cmdline LIKE '%/bin/csh%' OR cmdline LIKE '%/bin/ksh%' OR cmdline LIKE '%/bin/pdksh%' OR cmdline LIKE '%/bin/sh%' OR cmdline LIKE '%/bin/tcsh%' OR cmdline LIKE '%/bin/zsh%' OR cmdline LIKE '%$IFSash%' OR cmdline LIKE '%$IFSbash%' OR cmdline LIKE '%$IFSbsh%' OR cmdline LIKE '%$IFScsh%' OR cmdline LIKE '%$IFSksh%' OR cmdline LIKE '%$IFSpdksh%' OR cmdline LIKE '%$IFSsh%' OR cmdline LIKE '%$IFStcsh%' OR cmdline LIKE '%$IFSzsh%'));

bool potential_netcat_reverse_shell_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("nc") != std::string::npos || cmdline.find("ncat") != std::string::npos || cmdline.find("netcat") != std::string::npos) && (cmdline.find("-c") != std::string::npos || cmdline.find("-e") != std::string::npos) &&
        (cmdline.find(" ash") != std::string::npos ||
         cmdline.find(" bash") != std::string::npos ||
         cmdline.find(" bsh") != std::string::npos ||
         cmdline.find(" csh") != std::string::npos ||
         cmdline.find(" ksh") != std::string::npos ||
         cmdline.find(" pdksh") != std::string::npos ||
         cmdline.find(" sh") != std::string::npos ||
         cmdline.find(" tcsh") != std::string::npos ||
         cmdline.find("/bin/ash") != std::string::npos ||
         cmdline.find("/bin/bash") != std::string::npos ||
         cmdline.find("/bin/bsh") != std::string::npos ||
         cmdline.find("/bin/csh") != std::string::npos ||
         cmdline.find("/bin/ksh") != std::string::npos ||
         cmdline.find("/bin/pdksh") != std::string::npos ||
         cmdline.find("/bin/sh") != std::string::npos ||
         cmdline.find("/bin/tcsh") != std::string::npos ||
         cmdline.find("/bin/zsh") != std::string::npos ||
         cmdline.find("$IFSash") != std::string::npos ||
         cmdline.find("$IFSbash") != std::string::npos ||
         cmdline.find("$IFSbsh") != std::string::npos ||
         cmdline.find("$IFScsh") != std::string::npos ||
         cmdline.find("$IFSksh") != std::string::npos ||
         cmdline.find("$IFSpdksh") != std::string::npos ||
         cmdline.find("$IFSsh") != std::string::npos ||
         cmdline.find("$IFStcsh") != std::string::npos ||
         cmdline.find("$IFSzsh") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected a potential reverse shell connection using netcat.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Potential Perl Reverse Shell Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%perl%' AND cmdline LIKE '%-e%' AND ((cmdline LIKE '%fdopen(%' AND cmdline LIKE '%::Socket::INET%') OR (cmdline LIKE '%Socket%' AND cmdline LIKE '%connect%' AND cmdline LIKE '%open%' AND cmdline LIKE '%exec%')));

bool potential_perl_reverse_shell_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("perl") != std::string::npos && cmdline.find("-e") != std::string::npos && ((cmdline.find("fdopen(") != std::string::npos && cmdline.find("::Socket::INET") != std::string::npos) || (cmdline.find("Socket") != std::string::npos && cmdline.find("connect") != std::string::npos && cmdline.find("open") != std::string::npos && cmdline.find("exec") != std::string::npos)))
    {
        std::stringstream ss;

        ss << "Detected a potential reverse shell connection using Perl.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Potential PHP Reverse Shell
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%php%' AND cmdline LIKE '%-r%' AND cmdline LIKE '%fsockopen%' AND (cmdline LIKE '%ash%' OR cmdline LIKE '%bash%' OR cmdline LIKE '%bsh%' OR cmdline LIKE '%csh%' OR cmdline LIKE '%ksh%' OR cmdline LIKE '%pdksh%' OR cmdline LIKE '%sh%' OR cmdline LIKE '%tcsh%' OR cmdline LIKE '%zsh%'));

bool potential_php_reverse_shell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("php") != std::string::npos && cmdline.find("-r") != std::string::npos && cmdline.find("fsockopen") != std::string::npos &&
        (cmdline.find("ash") != std::string::npos ||
         cmdline.find("bash") != std::string::npos ||
         cmdline.find("bsh") != std::string::npos ||
         cmdline.find("csh") != std::string::npos ||
         cmdline.find("ksh") != std::string::npos ||
         cmdline.find("pdksh") != std::string::npos ||
         cmdline.find("sh") != std::string::npos ||
         cmdline.find("tcsh") != std::string::npos ||
         cmdline.find("zsh") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected a potential reverse shell connection using PHP.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Potential Python Reverse Shell
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%python%' AND cmdline LIKE '%-c%' AND cmdline LIKE '%import%' AND cmdline LIKE '%pty%' AND cmdline LIKE '%spawn(%' AND cmdline LIKE '%.connect%');

bool potential_python_reverse_shell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("python") != std::string::npos && cmdline.find("-c") != std::string::npos && cmdline.find("import") != std::string::npos && cmdline.find("pty") != std::string::npos && cmdline.find("spawn(") != std::string::npos && cmdline.find(".connect") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected a potential reverse shell connection using Python.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 .004 - Suspicious Reverse Shell Command Line
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%BEGIN {s = "/inet/tcp/0/%' OR cmdline LIKE '%bash -i >& /dev/tcp/%' OR cmdline LIKE '%bash -i >& /dev/udp/%' OR cmdline LIKE '%sh -i >$ /dev/udp/%' OR cmdline LIKE '%sh -i >$ /dev/tcp/%' OR cmdline LIKE '%&& while read line 0<&5; do%' OR cmdline LIKE '%/bin/bash -c exec 5<>/dev/tcp/%' OR cmdline LIKE '%/bin/bash -c exec 5<>/dev/udp/%' OR cmdline LIKE '%nc -e /bin/sh %' OR cmdline LIKE '%/bin/sh | nc%' OR cmdline LIKE '%rm -f backpipe; mknod /tmp/backpipe p && nc %' OR cmdline LIKE '%;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))%' OR cmdline LIKE '%;STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;%' OR cmdline LIKE '%/bin/sh -i <&3 >&3 2>&3%' OR cmdline LIKE '%uname -a; w; id; /bin/bash -i%' OR cmdline LIKE '%$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()};%' OR cmdline LIKE '%;os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(''HISTFILE'',''/dev/null'');%' OR cmdline LIKE '%.to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)%' OR cmdline LIKE '%;while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print%' OR cmdline LIKE '%socat exec:''bash -li'',pty,stderr,setsid,sigint,sane tcp:%' OR cmdline LIKE '%rm -f /tmp/p; mknod /tmp/p p &&%' OR cmdline LIKE '% | /bin/bash | telnet %' OR cmdline LIKE '%,echo=0,raw tcp-listen:%' OR cmdline LIKE '%nc -lvvp %' OR cmdline LIKE '%xterm -display 1%');

bool suspicious_reverse_shell_command_line(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("BEGIN {s = \"/inet/tcp/0/") != std::string::npos || 
    cmdline.find("bash -i >& /dev/tcp/") != std::string::npos || 
    cmdline.find("bash -i >& /dev/udp/") != std::string::npos || 
    cmdline.find("sh -i >$ /dev/udp/") != std::string::npos || 
    cmdline.find("sh -i >$ /dev/tcp/") != std::string::npos || 
    cmdline.find("&& while read line 0<&5; do") != std::string::npos || 
    cmdline.find("/bin/bash -c exec 5<>/dev/tcp/") != std::string::npos || 
    cmdline.find("/bin/bash -c exec 5<>/dev/udp/") != std::string::npos || 
    cmdline.find("nc -e /bin/sh ") != std::string::npos || 
    cmdline.find("/bin/sh | nc") != std::string::npos || 
    cmdline.find("rm -f backpipe; mknod /tmp/backpipe p && nc ") != std::string::npos || 
    cmdline.find(";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i))))") != std::string::npos || 
    cmdline.find(";STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;") != std::string::npos || 
    cmdline.find("/bin/sh -i <&3 >&3 2>&3") != std::string::npos || 
    cmdline.find("uname -a; w; id; /bin/bash -i") != std::string::npos || 
    cmdline.find("$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()};") != std::string::npos || 
    cmdline.find(";os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(''HISTFILE'',''/dev/null'');") != std::string::npos || 
    cmdline.find(".to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)") != std::string::npos || 
    cmdline.find(";while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print") != std::string::npos || 
    cmdline.find("socat exec:''bash -li'',pty,stderr,setsid,sigint,sane tcp:") != std::string::npos || 
    cmdline.find("rm -f /tmp/p; mknod /tmp/p p &&") != std::string::npos || 
    cmdline.find(" | /bin/bash | telnet ") != std::string::npos || 
    cmdline.find(",echo=0,raw tcp-listen:") != std::string::npos || 
    cmdline.find("nc -lvvp ") != std::string::npos || 
    cmdline.find("xterm -display 1") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected suspicious shell commands or program code that may be executed or used in command line to establish a reverse shell.";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// T1059 - Potential Ruby Reverse Shell
// SELECT * FROM process_events WHERE (path LIKE '%ruby%' AND cmdline LIKE '%-e%' AND cmdline LIKE '%rsocket%' AND cmdline LIKE '%TCPSocket%' AND (cmdline LIKE '% ash%' OR cmdline LIKE '% bash%' OR cmdline LIKE '% bsh%' OR cmdline LIKE '% csh%' OR cmdline LIKE '% ksh%' OR cmdline LIKE '% pdksh%' OR cmdline LIKE '% sh%' OR cmdline LIKE '% tcsh%'));

bool potential_ruby_reverse_shell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("ruby") != std::string::npos && cmdline.find("-e") != std::string::npos && cmdline.find("rsocket") != std::string::npos && cmdline.find("TCPSocket") != std::string::npos && (cmdline.find("ash") != std::string::npos || cmdline.find("bash") != std::string::npos || cmdline.find("bsh") != std::string::npos || cmdline.find("csh") != std::string::npos || cmdline.find("ksh") != std::string::npos || cmdline.find("pdksh") != std::string::npos || cmdline.find("sh") != std::string::npos || cmdline.find("tcsh") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Potential Ruby Reverse Shell";
        rule_event.metadata = ss.str();

        return true;
    }
    return false;
}

// Potentially Suspicious Named Pipe Created Via Mkfifo
// SELECT * FROM win_process_events WHERE (path LIKE '%/mkfifo%') AND (cmdline LIKE '%/tmp/%');

bool potentially_suspicious_named_pipe_created_via_mkfifo(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/mkfifo") != std::string::npos && cmdline.find("/tmp/") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Creation of a new named pipe using the 'mkfifo' utility in a potentially suspicious location detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Named Pipe Created Via Mkfifo
// SELECT * FROM win_process_events WHERE (path LIKE '%/mkfifo%');

bool named_pipe_created_via_mkfifo(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/mkfifo") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Creation of a new named pipe using the 'mkfifo' utility detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Suspicious Nohup Execution
// SELECT * FROM win_process_events WHERE (path LIKE '%/nohup%' AND cmdline LIKE '%/tmp/%');

bool suspicious_nohup_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/nohup") != std::string::npos && cmdline.find("/tmp/") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of binaries located in potentially suspicious locations via 'nohup' detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059.004 - Nohup Execution
// SELECT * FROM win_process_events WHERE path LIKE '%/nohup%';

bool nohup_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("/nohup") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of nohup which could be leveraged by an attacker to keep a process running or break out from restricted environments detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059 - Python Spawning Pretty TTY
// SELECT * FROM win_process_events WHERE 
//     (
//         path LIKE '%/python%' OR 
//         path LIKE '%/python2%' OR 
//         path LIKE '%/python3%' OR 
//         path LIKE '%/python2.%' OR 
//         path LIKE '%/python3.%'
//     ) AND 
//     (
//         cmdline LIKE '%import pty%' OR 
//         cmdline LIKE '%.spawn(%' OR 
//         cmdline LIKE '%from pty import spawn%'
//     );

bool python_spawning_pretty_tty(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("/python") != std::string::npos || path.find("/python2") != std::string::npos || path.find("/python3") != std::string::npos || path.find("/python2.") != std::string::npos || path.find("/python3.") != std::string::npos) && (cmdline.find("import pty") != std::string::npos || cmdline.find(".spawn(") != std::string::npos || cmdline.find("from pty import spawn") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Python spawning a pretty tty which could be indicative of potential reverse shell activity detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}