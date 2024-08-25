#include "win_defence_evasion_rules.h"
#include <sstream>

// DEFENSE EVASION

// T1197 - BITS jobs
//  select action, path, cmdline, parent_path from win_process_events where path like "%bitsadmin%" and (parent_path like "%cmd%" or parent_path like "%powershell%");

bool BITS_jobs(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("bitsadmin") != std::string::npos && (process_event.entry.parent_path.find("cmd") != std::string::npos || process_event.entry.parent_path.find("powershell") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Background Intelligent Transfer Service Abused";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1078.001 - Valid accounts: Default accounts
// select action, path, cmdline, parent_path from win_process_events where cmdline like '%guest%/add%' and cmdline like '%reg%add%';

bool escalate_guest(const ProcessEvent &process_event, Event &rule_event)
{
    if ((process_event.entry.cmdline.find("guest") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos) && ((process_event.entry.cmdline.find("reg") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos) && (process_event.entry.path.find("cmd") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Default guest account privilege escalated";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// bool escalate_guest(const ProcessEvent &process_event, Event &rule_event)
// {
//     if((process_event.entry.cmdline.find("guest") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos) || (process_event.entry.cmdline.find("reg") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos && process_event.entry.path.find("reg.exe")!= std::string::npos ))
//     {
//         std::stringstream ss;
//         ss << "Default guest account privilege escalated";
//         rule_event.metadata = ss.str();

//         return true;
//     }

//     return false;
// }

// T1112 - Modify Registry
// select action, path, cmdline, parent_path from win_process_events where cmdline like "%reg%add%";

bool registry_modification(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("reg") != std::string::npos && process_event.entry.cmdline.find("add") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Registry modification for possibly malicious purpose";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// select path, parent_path, cmdline, win_process_events where cmdline like '%ExecutionPolicy Bypass%';
// select path, parent_path, cmdline from win_process_events where cmdline like '%reg%' and cmdline like '%password%';

// bool unsecured_credentials(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.cmdline.find("ExecutionPolicy Bypass") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Unsecure credential access";
//         rule_event.metadata = ss.str();

//         return true;
//     }

//     if(process_event.entry.cmdline.find("reg") != std::string::npos && process_event.entry.cmdline.find("password"))
//     {
//         std::stringstream ss;
//         ss << "Unsecure credential access";
//         rule_event.metadata = ss.str();

//         return true;
//     }

//     return false;
// }

// T1202 - Indirect command Execution
//  select action, path, parent_path from win_process_events where cmdline like "%pcalua%" and cmdline like "%calc.exe%" and cmdline like "%cmd.exe%";

bool indirect_command_execution(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("pcalua.exe") != std::string::npos && process_event.entry.cmdline.find("calc.exe") != std::string::npos && process_event.entry.cmdline.find("cmd.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Possible indirect program or command execution via pcalua.exe";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1550.003 - Use Alternate Authentication Material
//  select * from win_process_events where (cmdline like '%mimikatz%' and cmdline like '%kerberos::ptt%') OR (cmdline like '%rubeus%' and cmdline like '%PsExec.exe%');

bool alternate_authentication(const ProcessEvent &process_event, Event &rule_event)
{
    if ((process_event.entry.cmdline.find("mimikatz") != std::string::npos && process_event.entry.cmdline.find("kerberos::ptt") != std::string::npos) || (process_event.entry.cmdline.find("rubeus.exe") != std::string::npos && process_event.entry.cmdline.find("PsExec.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Possible alternate authentication using Kerberos ticket";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1070 - Indicator Removal
//  select path, PARENT_path, cmdline from win_process_events where action="PROC_CREATE" and path like '%fsutil%' and cmdline like '%deletejournal%';

bool indicator_removal(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.action == "PROC_CREATE" && process_event.entry.path.find("fsutil") != std::string::npos && process_event.entry.cmdline.find("deletejournal") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Possible indicator removal using fsutil";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1562.006 - Impair Defenses: Indicator Blocking
// select * from win_process_events where cmdline like '%PsExec.exe%' and cmdline like '%logman%' and parent_path like '%powershell.exe%';

// bool disable_powershell_etw(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.action == "PROC_CREATE" && process_event.entry.parent_path.find("PSEXESVC") != std::string::npos && process_event.entry.path.find("logman") != std::string::npos && (process_event.entry.cmdline.find("stop") != std::string::npos || process_event.entry.cmdline.find("update") != std::string::npos || process_event.entry.cmdline.find("delete") != std::string::npos))
//     {
//         std::stringstream ss;
//         ss << "Microsoft Powershell ETW provider disabled using logman.exe";
//         rule_event.metadata = ss.str();
//         return true;
//     }

//     return false;
// }

bool disable_powershell_etw(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("PsExec.exe") != std::string::npos && process_event.entry.cmdline.find("logman") != std::string::npos && process_event.entry.parent_path.find("powershell.exe"))
    {
        std::stringstream ss;
        ss << "Microsoft Powershell ETW provider disabled using logman.exe";
        rule_event.metadata = ss.str();
        return true;
    }

    return false;
}

// T1134.002 - Create process with token
//  select * from win_process_events where parent_path like '%powershell%' and cmdline like '%lsass%' and cmdline like '%cmd%' ;

// bool create_process_with_token(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.parent_path.find("lsass.exe") != std::string::npos && process_event.entry.path.find("cmd.exe") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Access tokens used to run programs under a different user";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

bool create_process_with_token(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.parent_path.find("powershell.exe") != std::string::npos && process_event.entry.cmdline.find("lsass") != std::string::npos && process_event.entry.cmdline.find("Set-ExecutionPolicy") != std::string::npos && process_event.entry.cmdline.find("cmd.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Access tokens used to run programs under a different user";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055.012 - Process Hollowing
// select * from win_process_events where parent_path like '%powershell%' and cmdline like '%notepad%' and cmdline like '%powershell%' and cmdline like '%cmd%';

// bool process_hollowing(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.parent_path.find("WINWORD.EXE") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Possible process hollowing";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

bool process_hollowing(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("powershell.exe") != std::string::npos && process_event.entry.cmdline.find("notepad.exe") != std::string::npos && process_event.entry.cmdline.find("powershell.exe") != std::string::npos && process_event.entry.cmdline.find("cmd.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Possible process hollowing";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification
// select * from win_process_events where path like '%icacls.exe%';  (Can't verify if it's actually malicious)

bool grant_access_to_C(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("icacls.exe") != std::string::npos && process_event.entry.cmdline.find("Everyone") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Granted full access to C drive";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.001 - Hide Artifacts: Hidden Files and Directories
// select * from win_process_events where parent_path like '%cmd.exe%' and cmdline like '%attrib.exe%' and cmdline like '%temp%';

// bool hide_artifacts(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.action == "FILE_CREATE" && process_event.entry.process_name.find("WINWORD.exe") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Binaries hidden inside of files stored in Office document";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

// gets detected but also triggers for t1222.001
// bool hide_artifacts(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.action == "PROC_TERMINATE" && (process_event.entry.path.find("attrib.exe") != std::string::npos)  && (process_event.entry.cmdline.find("cmd.exe") != std::string::npos || process_event.entry.cmdline.find("attrib.exe") != std::string::npos))
//     {
//         std::stringstream ss;
//         ss << "Binaries hidden inside of files stored in Office document";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

bool hide_artifacts(const ProcessEvent &process_event, Event &rule_event)
{
    if ((process_event.entry.path.find("cmd.exe") != std::string::npos) && (process_event.entry.cmdline.find("cmd.exe") != std::string::npos && process_event.entry.cmdline.find("attrib.exe") != std::string::npos && process_event.entry.cmdline.find("temp") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Binaries hidden inside of files stored in Office document";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Masquerading
//  select * from win_process_events where path like '%powershell%' and ((cmdline like '%copy-item%' and cmdline like '%destination%') OR cmdline like '%Expand-Archive%');
bool masquerading(const ProcessEvent &process_event, Event &rule_event)
{

    std::string cmdline = process_event.entry.cmdline;
    if (process_event.entry.path.find("powershell.exe") != std::string::npos && ((cmdline.find("copy-item") != std::string::npos && cmdline.find("destination") != std::string::npos) || cmdline.find("Expand-Archive") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Object location manipulated for evading defense";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Trusted Developer Utilities Proxy Execution
//  select * from win_process_events where path like '%jsc.exe%' and cmdline like '%jsc.exe%';

bool proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("jsc.exe") != std::string::npos && process_event.entry.cmdline.find("jsc.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Object location manipulated for evading defense";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
//  select * from win_process_events where cmdline like '%reg.exe%' and cmdline like '%eventvwr.msc%';
bool bypass_user_account_control(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("reg.exe") != std::string::npos && process_event.entry.cmdline.find("eventvwr.msc") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Object location manipulated for evading defense";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1220 - XSL Script Processing
//  select * from win_process_events where path like '%WMIC%' and cmdline like '%wmic%' and cmdline like '%FORMAT%';

// bool xsl_script_processing(const ProcessEvent &process_event, Event &rule_event)
// {
//     if (process_event.entry.path.find("WMIC") != std::string::npos && process_event.entry.cmdline.find("wmic") != std::string::npos && process_event.entry.cmdline.find("FORMAT") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Scripts are embedded inside XSL files";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

// T1218.005 - System Binary Proxy Execution: Mshta
//  select * from win_process_events where path like '%mshta.exe%' and cmdline like '%mshta.exe%';

bool mshta(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("mshta.exe") != std::string::npos && process_event.entry.cmdline.find("mshta") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Proxy Execution of .hta files using mshta.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - System Binary Proxy Execution: Regsvr32
//  select * from win_process_events where path like '%regsvr32%' and (cmdline like '%Temp%' and cmdline like '%scrobj.dll%');

bool system_binary_proxy_execution_regsvr32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("regsvr32") != std::string::npos && cmdline.find("Temp") != std::string::npos) || (path.find("regsvr32") != std::string::npos && cmdline.find("scrobj.dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "regsvr32.exe used for proxy execution of malicious code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.007 - System Binary Proxy Execution: Msiexec
//  select * from win_process_events where (path like '%cmd.exe%' or path like '%msiexec%') and cmdline like '%msiexec%';

bool system_binary_proxy_execution_msiexec(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if ((path.find("cmd.exe") != std::string::npos && cmdline.find("msiexec") != std::string::npos) || (path.find("msiexec") != std::string::npos && cmdline.find("msiexec") != std::string::npos))
    {
        std::stringstream ss;
        ss << "msiexec.exe used for proxy execution of malicious payloads";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127.001 - Trusted Developer Utilities Proxy Execution: MSBuild
//  select * from win_process_events where parent_path like '%cmd.exe%' and path like '%MSBuild% and cmdline like '%msbuild.exe%';

bool proxy_execution_msbuild(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.parent_path.find("cmd.exe") != std::string::npos && process_event.entry.path.find("MSBuild") != std::string::npos && process_event.entry.cmdline.find("msbuild.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "MSBuild used for proxy execution of code through Windows utility";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - System Binary Proxy Execution
//  select * from win_process_events where path like '%gpscript%' and cmdline like '%Gpscript%' and (cmdline like '%startup%' or cmdline like '%logon%');

bool system_binary_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("gpscript") != std::string::npos && process_event.entry.cmdline.find("Gpscript") != std::string::npos && (process_event.entry.cmdline.find("startup") != std::string::npos || process_event.entry.cmdline.find("logon") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Proxy execution done for malicious content using signed binaries";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - System Binary Proxy Execution: Rundll32
// select * from win_process_events where path like '%rundll32.exe%' and cmdline like '%rundll32.exe%' and cmdline like '%desk.cpl%' and cmdline like '%.scr%';

bool system_binary_proxy_execution_rundll32(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("rundll32.exe") != std::string::npos && process_event.entry.cmdline.find("rundll32.exe") != std::string::npos && process_event.entry.cmdline.find("desk.cpl") != std::string::npos && process_event.entry.cmdline.find(".scr") != std::string::npos)
    {

        std::stringstream ss;
        ss << "rundll32.exe used for proxy execution of malicious payloads";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.002 - Hijack Execution Flow: DLL Side-Loading
//  select * from win_process_events where cmdline like '%dotnet%' and cmdline like '%echo%' and cmdline like '%.dll%';

bool dll_side_loading(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("dotnet") != std::string::npos && cmdline.find("echo") != std::string::npos && cmdline.find(".dll") != std::string::npos)
    {

        std::stringstream ss;
        ss << "Malicious payloads executed by side loading DLLs";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.004 - Hide Artifacts: NTFS File Attributes
//  select * from win_process_events where cmdline like '%echo%' and cmdline like '%adstest.txt%';

bool ntfs_file_attributes(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("adstest.txt") != std::string::npos && cmdline.find("echo") != std::string::npos)
    {

        std::stringstream ss;
        ss << "NTFS file attributes used to hide malicious data";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.003 - Indicator Removal: Clear Command History
//  select * from win_process_events where (cmdline like '%Remove-Item%' and cmdline like '%(Get-PSReadlineOption).HistorySavePath%') or cmdline like '%Set-PSReadlineOption%';

bool clear_command_history(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("Remove-Item") != std::string::npos && cmdline.find("(Get-PSReadlineOption).HistorySavePath") != std::string::npos) || (cmdline.find("Set-PSReadlineOption") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Command history cleared to conceal malicious activities";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Obfuscated Files or Information
//  select * from win_process_events where cmdline like '%IEX%' and cmdline like '%OriginalCommand%' and cmdline like '%Debug%';

bool obfuscated_files_or_information(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("IEX") != std::string::npos && cmdline.find("OriginalCommand") != std::string::npos && cmdline.find("Debug") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Content of files obfuscated";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Process Injection
//  select * from win_process_events where cmdline like '%mimikatz.exe%' and cmdline like '%lsadump%' and cmdline like '%inject%';

bool process_injection(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("mimikatz.exe") != std::string::npos && cmdline.find("lsadump") != std::string::npos && cmdline.find("inject") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Codes injected in processes to elevate privileges ";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 - Indicator Removal: File Deletion
//  select * from win_process_events where (cmdline like '%Remove-Item%' and cmdline like '%Get-ChildItem%') or (cmdline like '%New-Item%' and cmdline like '%Remove-Item%');

bool indicator_removal_file_deletion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("Remove-Item") != std::string::npos && cmdline.find("Get-ChildItem") != std::string::npos) || (cmdline.find("New-Item") != std::string::npos && cmdline.find("Remove-Item") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Files deleted after malicious intrusion activity";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.003 - Hide Artifacts: Hidden Window
//  select * from win_process_events where cmdline like '%Start-Process%' and cmdline like '%WindowStyle%' and cmdline like '%hidden%';

bool hidden_window_hide_artifacts(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Start-Process") != std::string::npos && cmdline.find("WindowStyle") != std::string::npos && cmdline.find("hidden") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Hidden windows used to conceal malicious activity";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Impair Defenses: Disable or Modify Tools
//  select * from win_process_events where (path like '%fltMC.exe%' or path like '%cmd.exe%') and (cmdline like '%fltmc.exe%' and cmdline like '%SysmonDrv%');

bool impair_defenses_disable_modify_tools(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("cmd.exe") != std::string::npos || path.find("fltMC.exe") != std::string::npos) && (cmdline.find("fltmc.exe") != std::string::npos && cmdline.find("SysmonDrv") != std::string::npos))
    {

        std::stringstream ss;
        ss << "Security tools disabled or modified to avoid detection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.004 - Subvert Trust Controls: Install Root Certificate
//  select * from win_process_events where cmdline like '%Import-Certificate%' and cmdline like '%Cert:\\LocalMachine\\Root%';

bool install_root_certificate(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Import-Certificate") != std::string::npos && cmdline.find("Cert:\\LocalMachine\\Root") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Root certificate installed to avoid detection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.004 - System Binary Proxy Execution: InstallUtil
//  select * from win_process_events where cmdline like '%Invoke-Build%' and cmdline like '%InvokeInstallUtilAssembly%';

bool system_binary_proxy_execution_installutil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Invoke-Build") != std::string::npos && cmdline.find("InvokeInstallUtilAssembly") != std::string::npos)
    {
        std::stringstream ss;
        ss << "InstallUtil used for proxy execution of code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1140 - Deobfuscate/Decode Files or Information
//  select * from win_process_events where cmdline like '%certutil%' and cmdline like '%encode%' and cmdline like '%decode%';

bool decode_files_or_information(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("certutil") != std::string::npos && cmdline.find("encode") != std::string::npos && cmdline.find("decode") != std::string::npos)
    {
        std::stringstream ss;
        ss << "";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: NetWire RAT Registry Key Creation
// select * from win_process_events where cmdline like '%HKCU:\\Software\\Netwire%';

bool modify_registry_netwire(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("HKCU:\\Software\\Netwire") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Registry modified using netwire for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Ursnif Malware Registry Key Creation
//  select * from win_process_events where cmdline like '%HKCU\\Software\\AppDataLow\\Software\\Microsoft%' and path like '%reg.exe%';

bool modify_registry_ursnif(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("HKCU\\Software\\AppDataLow\\Software\\Microsoft") != std::string::npos && process_event.entry.path.find("reg.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Registry modified using Ursnif Malware for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Terminal Server Client Connection History Cleared
//  select * from win_process_events where cmdline like '%Microsoft\\Terminal Server Client\\Default%' or cmdline like '%Microsoft\\Terminal Server Client\\Servers%';

bool modify_registry_terminal_server_client(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("Microsoft\\Terminal Server Client\\Default") != std::string::npos || process_event.entry.cmdline.find("Microsoft\\Terminal Server Client\\Servers") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Terminal Server Client Connection History Cleared for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Disable Windows Toast Notifications

// bool modify_registry_netwire(const ProcessEvent &process_event, Event &rule_event)
// {
//     if(process_event.entry.cmdline.find("HKCU:\\Software\\Netwire") != std::string::npos){
//          std::stringstream ss;
//         ss << "Registry modified using netwire for malicious purpose";
//         rule_event.metadata = ss.str();
//         return true;
//     }
// }

// T1112 - Modify Registry: BlackByte Ransomware Registry Changes

bool modify_registry_blackbyte(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") != std::string::npos && cmdline.find("LocalAccountTokenFilterPolicy") != std::string::npos && cmdline.find("EnableLinkedConnections") != std::string::npos && cmdline.find("LongPathsEnabled") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Registry modified using BlackByte Ransomeware for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Windows Add Registry Value to Load Service in Safe Mode

bool modify_registry_load_service_safemode(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Registry modified to load service in safe mode";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Disable Windows Registry Tool

bool modify_registry_disable_win_registry_tool(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") != std::string::npos && (cmdline.find("DisableRegistryTools") != std::string::npos || cmdline.find("DisableNotificationCenter") != std::string::npos || cmdline.find("DisableChangePassword") != std::string::npos || cmdline.find("DisableTaskmgr") != std::string::npos || cmdline.find("DisableLockWorkstation") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Windows registry tool disabled";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Disable Windows Security Center Notifications

bool modify_registry_disable_win_security_notifications(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.cmdline.find("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell") != std::string::npos && process_event.entry.cmdline.find("UseActionCenterExperience") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Windows Security center notifications disabled for malicious purposes";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Modify Registry: Windows Group Policy Feature

bool modify_registry_win_group_policy_feature(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explore") != std::string::npos && (cmdline.find("HideSCAVolume") != std::string::npos || cmdline.find("HideSCAPower") != std::string::npos || cmdline.find("HideSCAHealth") != std::string::npos || cmdline.find("HideSCANetwork") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Registry modified to load service in safe mode";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Impair Defenses: Disable or Modify Tools, AMSI Bypass - Remove AMSI Provider Reg Key

bool impair_defenses_disable_modify_tools_AMSI_Byspass(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}") != std::string::npos)
    {

        std::stringstream ss;
        ss << "Security tools disabled or modified to avoid detection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Impair Defenses: Disable or Modify Tools, Disable Microsoft Office Security Features

bool impair_defenses_disable_modify_tools_office_security(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Software\\Microsoft\\Office") != std::string::npos && cmdline.find("VBAWarnings") != std::string::npos && cmdline.find("DisableInternetFilesInPV") != std::string::npos && cmdline.find("DisableUnsafeLocationsInPV") != std::string::npos && cmdline.find("DisableAttachementsInPV") != std::string::npos)
    {

        std::stringstream ss;
        ss << "Security tools disabled or modified to avoid detection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Impair Defenses: Disable or Modify System Firewall, Disable Microsoft Defender Firewall

bool impair_defenses_disable_defender_firewall(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile") != std::string::npos && cmdline.find("EnableFirewall") != std::string::npos)
    {

        std::stringstream ss;
        ss << "Microsoft Defender FIrewall disabled to avoid detection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.012 - Hijack Execution Flow: COR_PROFILER, User scope COR_PROFILER

bool user_scope_cor_profile(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("COR_ENABLE_PROFILING") != std::string::npos && cmdline.find("COR_PROFILER") != std::string::npos)
    {

        std::stringstream ss;
        ss << "COR_PROFILER environment used for hijack execution flow of programs";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.001 - Hide Artifacts: Hidden Files and Directories , Hide Files Through Registry

bool hide_artifacts_through_registry(const ProcessEvent &process_event, Event &rule_event)
{
    if (process_event.entry.path.find("CurrentVersion\\Explorer\\Advanced") != std::string::npos && process_event.entry.cmdline.find("ShowSuperHidden") != std::string::npos && process_event.entry.cmdline.find("Hidden") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Show hidden files switch is disabled in the registry";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Impair Defenses: Disable or Modify Tools, Disable Microsoft Office Security Features, Tamper with Windows Defender

bool impair_defenses_tamper_win_defender(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("SOFTWARE\\Policies\\Microsoft\\Windows Defender") != std::string::npos && cmdline.find("DisableAntiSpyware") != std::string::npos) || (cmdline.find("DisableRealtimeMonitoring") != std::string::npos && cmdline.find("DisableBehaviorMonitoring") != std::string::npos && cmdline.find("DisableScriptScanning") != std::string::npos && cmdline.find("DisableBlockAtFirstSeen") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Windows defender is disabled from starting up at reboot";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.004 - Subvert Trust Controls: Install Root Certificate,Install root CA on Windows with certutil

bool install_root_certificate_win_certutil(const ProcessEvent &process_event, Event &rule_event)
{

    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("certutil.exe") != std::string::npos && cmdline.find("certutil.exe") != std::string::npos && cmdline.find("addstore") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Root Certificate created using certutil";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 - Indicator Removal: File Deletion, Delete a single file

bool indicator_removal_del_single_file(const ProcessEvent &process_event, Event &rule_event)
{

    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("cmd.exe") != std::string::npos && cmdline.find("del") != std::string::npos && cmdline.find("/f") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Single file deleted from the temporary directory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059.001 - PowerShell Downgrade Attack
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%-version 2%' and cmdline like '%-Command Write-Host%'

bool powerShell_downgrade_attack(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Get-WmiObject") != std::string::npos && cmdline.find("Win32_Shadowcopy") != std::string::npos && cmdline.find("Delete()") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Powershell downgrade attack";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Tamper Windows Defender - PSClassic
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Set-MpPreference %' and cmdline like '%DisableRealtimeMonitoring%' and cmdline like '%DisableScriptScanning%' and cmdline like '%DisableBlockAtFirstSeen%'

bool tamper_windows_defender(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Set-MpPreference") != std::string::npos && cmdline.find("DisableRealtimeMonitoring") != std::string::npos && cmdline.find("DisableScriptScanning") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Windows defender has been tampered, scheduled scanning and other parts may be affected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - AMSI Bypass Pattern Assembly GetType
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%[Ref].Assembly.GetType%' and cmdline like '%SetValue($null,$true)%' and cmdline like '%NonPublic,Static%'

bool AMSI_bypass_pattern_assembly_getType(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("[Ref].Assembly.GetType") != std::string::npos && cmdline.find("SetValue($null,$true)") != std::string::npos && cmdline.find("NonPublic,Static") != std::string::npos)
    {
        std::stringstream ss;
        ss << "AMSI bypass PowerShell scripts have been compromised";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1497.001 - Powershell Detect Virtualization Environment
// select * from win_process_events where cmdline like ('%powershell.exe%' and cmdline like '%Get-WmiObject%' and cmdline like '%MSAcpi_ThermalZoneTemperature%');

bool powershell_detect_virtualization_environment(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-WmiObject") != std::string::npos && cmdline.find("MSAcpi_ThermalZoneTemperature") != std::string::npos)
    {
        std::stringstream ss;
        ss << "AMSI bypass PowerShell scripts have been compromised";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Disable-WindowsOptionalFeature Command PowerShell
// select * from win_process_events where cmdline like ('%powershell.exe%' and (cmdline like '%Disable-WindowsOptionalFeature%' and cmdline like '%-Online%' and cmdline like '%-FeatureName%') and (cmdline like '%Windows-Defender-Gui%' or cmdline like '%Windows-Defender-Features%' or '%Windows-Defender%' or '%Windows-Defender-ApplicationGuard%'));

bool disable_WindowsOptionalFeature_command_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Disable-WindowsOptionalFeature") != std::string::npos && cmdline.find("-Online") != std::string::npos && cmdline.find("-FeatureName") != std::string::npos) && (cmdline.find("Windows-Defender-Gui") != std::string::npos || (cmdline.find("Windows-Defender-Features") != std::string::npos || cmdline.find("Windows-Defender") != std::string::npos || cmdline.find("Windows-Defender-ApplicationGuard") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "AMSI bypass PowerShell scripts have been compromised";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059.001 - NTFS Alternate Data Stream
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Add-Content' and cmdline like '%-Stream%' and cmdline like '%Get-Content%' and cmdline like '%Invoke-Expression%'); (to be checked)

bool NTFS_alternate_data_stream(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Add-Content") != std::string::npos && cmdline.find("-Stream") != std::string::npos && cmdline.find("Get-Content") != std::string::npos && cmdline.find("Windows-Defender-Gui") != std::string::npos && (cmdline.find("Invoke-Expression") != std::string::npos))
    {
        std::stringstream ss;
        ss << "File created with alternate data stream and might get executed";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.005 - Suspicious Invoke-Item From Mount-DiskImage
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Mount-DiskImage' and cmdline like '%-ImagePath %' and cmdline like '%Get-Volume%' and cmdline like '%DriveLetter%' and cmdline like '%invoke-item%'); (to be checked)

bool suspicious_invoke_item_from_mount_diskImage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Mount-DiskImage") != std::string::npos && cmdline.find("-ImagePath ") != std::string::npos && cmdline.find("Get-Volume") != std::string::npos && cmdline.find("DriveLetter") != std::string::npos && (cmdline.find("invoke-item") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Files of format (.iso, .vhd) may be abused to deliver malicious payloads";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.004 - Powershell Store File In Alternate Data Stream
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%-ItemType Directory%' and cmdline like '%Start-Process%' and cmdline like '%-FilePath%' and cmdline like '%"$env:comspec"%' and cmdline like '%-ArgumentList%';

bool powershell_store_file_in_alternate_data_stream(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("-ItemType Directory") != std::string::npos && cmdline.find("Start-Process") != std::string::npos && cmdline.find("FilePath") != std::string::npos && cmdline.find("$env:comspec") != std::string::npos && (cmdline.find("-ArgumentList") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Files stored in alternate data streams";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059.001 - Potential PowerShell Obfuscation Using Character Join
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% -Value (-join(%' and cmdline like '%InvokeReturnAsIs()%' and cmdline like '%-Alias%';

bool potential_powershell_obfuscation_using_character_join(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("-Value (-join(") != std::string::npos && cmdline.find("InvokeReturnAsIs()") != std::string::npos && cmdline.find("-Alias") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell obfuscation done using character join";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059.001 - Suspicious Eventlog Clear
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% Get-EventLog%' and cmdline like '%Clear-EventLog%';

bool suspicious_eventlog_clear(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-EventLog") != std::string::npos && cmdline.find("Clear-EventLog") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell event logs are cleared";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.006 - Suspicious Hyper-V Cmdlets
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '% New-VM%' or cmdline like '%Set-VMFirmware%' or cmdline like '%Start-VM%'));

bool suspicious_hyper_v_cmdlets(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("New-VM") != std::string::npos || cmdline.find("Set-VMFirmware") != std::string::npos || cmdline.find("Start-VM") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Virtual machine stopped and deleted"; // To be checked
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1006 - Suspicious IO.FileStream
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% New-Object%' and cmdline like '%IO.FileStream%' and cmdline like '%-InputObject%');

bool suspicious_io_fileStream(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Object") != std::string::npos && cmdline.find("IO.FileStream") != std::string::npos && cmdline.find("-InputObject") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Direct access to files may have been given";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.005 - PowerShell Deleted Mounted Share
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '% Remove-SmbShare%' or cmdline like '%Remove-FileShare%'));

bool powershell_deleted_mounted_share(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Remove-SmbShare") != std::string::npos || cmdline.find("Remove-FileShare") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Shared connections might be removed to clean up traces of the operation";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.005 - Suspicious Unblock-File
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% Unblock-File%' and cmdline like '%-Path%');

bool suspicious_unblock_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Unblock-File") != std::string::npos && cmdline.find("-Path") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Removed the Zone.Identifier alternate data stream which identifies the file as downloaded from the internet";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.003 - Suspicious PowerShell WindowStyle Option
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% Start-Process%' and cmdline like '%-WindowStyle%' and cmdline like '%hidden%');

bool suspicious_powershell_windowStyle_option(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Start-Process") != std::string::npos && cmdline.find("-WindowStyle") != std::string::npos && cmdline.find("hidden") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Hidden windows might be used to conceal malicious activity";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Tamper Windows Defender - ScriptBlockLogging
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% Set-MpPreference%' and cmdline like '%1%' and (cmdline like '%DisableRealtimeMonitoring%' or cmdline like '%DisableBehaviorMonitoring%' or cmdline like '%DisableScriptScanning %' or cmdline like '%DisableBlockAtFirstSeen%'));

bool tamper_windows_defender_ScriptBlockLogging(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Set-MpPreference") != std::string::npos && cmdline.find("1") != std::string::npos && (cmdline.find("DisableRealtimeMonitoring") != std::string::npos || cmdline.find("DisableBehaviorMonitoring") != std::string::npos || cmdline.find("DisableScriptScanning") != std::string::npos || cmdline.find("DisableBlockAtFirstSeen") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Windows defender tampered";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.006 - Powershell Timestomp
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% .CreationTime =%' and cmdline like '%.LastWriteTime =%' and cmdline like '%.LastAccessTime =%');

bool powershell_timestomp(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("CreationTime =") != std::string::npos && cmdline.find(".LastWriteTime =") != std::string::npos && cmdline.find(".LastAccessTime =") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Timestomps of files might be modified";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

//  T1218.007 - PowerShell WMI Win32_Product Install MSI
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% .Invoke-CimMethod%' and cmdline like '%-ClassName%' and cmdline like '%Win32_Product%' and cmdline like '%-MethodName%' and cmdline like '%.msi%') ;

bool powershell_WMI_Win32_product_install_MSI(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Invoke-CimMethod") != std::string::npos && cmdline.find("-ClassName") != std::string::npos && cmdline.find("Win32_Product") != std::string::npos && cmdline.find("-MethodName") != std::string::npos && cmdline.find(".msi") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of Local MSI file with embedded JScript";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

//  T1562.004 - Windows Firewall Profile Disabled
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '% .Set-NetFirewallProfile%' and cmdline like '%-Enabled %' and cmdline like '%False%');

bool windows_firewall_profile_disabled(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Set-NetFirewallProfile") != std::string::npos && cmdline.find("-Enabled ") != std::string::npos && cmdline.find("False") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Windows Firewall Profile Disabled";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Regsvr32 Network Activity - DNS
// select * from win_process_events where (cmdline like '%cmd.exe%' and cmdline like '%regsvr32.exe%' and cmdline like '%Start-Process%' and cmdline like '%-FilePath%' and cmdline like '%"$env:comspec"%' and cmdline like '%-ArgumentList%';

bool regsvr32_network_activity_dns(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos && cmdline.find("regsvr32.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Regsvr32 network activity";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.003 - CMSTP Execution Process Access
// select * from win_process_events where (cmdline like '%cmd.exe%' and cmdline like '%cmstp.exe%' and cmdline like '%uacbypass.inf%';

bool cmstp_execution_process_access(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos && cmdline.find("cmstp.exe") != std::string::npos && cmdline.find("uacbypass.inf") != std::string::npos)
    {
        std::stringstream ss;
        ss << "CMSTP Execution Process Access";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Malware Shellcode in Verclsid Target Process
// select * from win_process_events where (cmdline like '%cmd.exe%' and cmdline like '%verclsid.exe%';

bool malware_shellcode_in_verclsid_target_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos && cmdline.find("verclsid.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Malware Shellcode in Verclsid Target Process";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Potential Shellcode Injection
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%lsass.exe%' and cmdline like '%ntdll.dll%';

bool potential_shellcode_injection(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos && cmdline.find("lsass.exe") != std::string::npos && cmdline.find("ntdll.dll") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential Shellcode Injection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Defence Evasion rules

// T1140 - PowerShell Decompress Commands
// select * from win_process_events where (cmdline like '%Expand-Archive%');

bool powershell_decompress_commands(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Expand-Archive") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Suspicious files might be decompressed";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module
// // select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%rundll32.exe%' and cmdline like '%shell32.dll%' and cmdline like '%shellexec_rundll%';

bool invoke_obfuscation_RUNDLL_LAUNCHER_powershell_module(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("rundll32.exe") != std::string::npos && cmdline.find("shell32.dll") != std::string::npos && cmdline.find("shellexec_rundll") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powershell obfuscation detected via RUNDLL Launcher"; // To be reviewed
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation Via Use MSHTA - PowerShell Module
// // select * from win_process_events where cmdline like '%set%' and cmdline like '%mshta%' and cmdline like '%vbscript:createobject%' and cmdline like '%.run%' and cmdline like '%(window.close)%';

bool invoke_obfuscation_via_use_mshta_powershell_module(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("set") != std::string::npos && cmdline.find("mshta") != std::string::npos && cmdline.find("vbscript:createobject") != std::string::npos && cmdline.find(".run") != std::string::npos && cmdline.find("(window.close)") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powershell obfuscation detected via use MSHTA"; // To be reviewed
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation Via Use MSHTA - PowerShell Module
// // select * from win_process_events where cmdline like '%ModuleContents=function Get-VMRemoteFXPhysicalVideoAdapter {%';

bool potential_RemoteFXvGPUDisablement_abuse_powershell_module(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("ModuleContents=function Get-VMRemoteFXPhysicalVideoAdapter {") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Module Contents are set to 'function Get-VMRemoteFXPhysicalVideoAdapter'";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - SyncAppvPublishingServer Bypass Powershell Restriction - PS Module
// select * from win_process_events where cmdline like '%SyncAppvPublishingServer.exe%';

bool SyncAppvPublishingServer_bypass_powershell_restriction_PS_module(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("SyncAppvPublishingServer.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell execution restrictions might be bypassed by using SyncAppvPublishingServer";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.003 - Clearing Windows Console History
// select * from win_process_events where cmdline like '%Clear-History%' or cmdline like '%	ConsoleHost_history.txt%' or cmdline like '%(Get-PSReadlineOption).HistorySavePath%';

bool clearing_windows_console_history(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Clear-History") != std::string::npos || cmdline.find("ConsoleHost_history.txt") != std::string::npos || cmdline.find("(Get-PSReadlineOption).HistorySavePath") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Windows console history cleared";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.003 - Disable Powershell Command History
// select * from win_process_events where cmdline like '%Remove-Module%' and cmdline like '%	psreadline%';

bool disable_powershell_command_history(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Remove-Module") != std::string::npos && cmdline.find("psreadline") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powershell command history has been disabled";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1620 - Potential In-Memory Execution Using Reflection.Assembly
// select * from win_process_events where cmdline like '%[Reflection.Assembly]::load%';

bool potential_in_memory_execution_using_reflection_assembly(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("[Reflection.Assembly]::load") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Loads assemblies in memory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock
// select * from win_process_events where cmdline like '%powershell.exe%' and cmdline like '%Invoke-ATHRemoteFXvGPUDisablementCommand%';

bool potential_RemoteFXvGPUDisablement_EXE_abuse(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Invoke-ATHRemoteFXvGPUDisablementCommand") != std::string::npos)
    {
        std::stringstream ss;
        ss << "'RemoteFXvGPUDisablement.exe' is abused"; // To be reviewed.
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1222 - PowerShell Script Change Permission Via Set-Acl - PsScript
// select * from win_process_events where cmdline like '%Set-Acl%' and cmdline like '%-AclObject%' and cmdline like '%-Path%';

bool powershell_script_change_permission_via_set_acl_PsScript(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Set-Acl") != std::string::npos && cmdline.find("-AclObject") != std::string::npos && cmdline.find("-Path") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Permissions of files/folders have been changed."; // To be reviewed.
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Troubleshooting Pack Cmdlet Execution
// select * from win_process_events where cmdline like '%Invoke-TroubleshootingPack%' and cmdline like '%C:\Windows\Diagnostics\System\PCW%' and cmdline like '%-AnswerFile%' and cmdline like '%-Unattended%';

bool troubleshooting_pack_cmdlet_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Invoke-TroubleshootingPack") != std::string::npos && cmdline.find("C:\\Windows\\Diagnostics\\System\\PCW") != std::string::npos && cmdline.find("-AnswerFile") != std::string::npos && cmdline.find("-Unattended") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Permissions of files/folders have been changed."; // To be reviewed.
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036.003 - Suspicious Start-Process PassThru
// select * from win_process_events where cmdline like '%Start-Process%' and cmdline like '%-PassThru%' and cmdline like '%-FilePath%';

bool suspicious_start_process_passthru(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Start-Process") != std::string::npos && cmdline.find("-PassThru") != std::string::npos && cmdline.find("-FilePath") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powershell uses PassThru option to start in background"; // To be reviewed.
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.004 - Suspicious X509Enrollment - Ps Script
// select * from win_process_events where cmdline like '%X509Enrollment.CBinaryConverter%';

bool suspicious_X509Enrollment_ps_script(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("X509Enrollment.CBinaryConverter") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powershell uses PassThru option to start in background"; // To be reviewed.
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Network Connection Initiated By AddinUtil.EXE
// select * from win_process_events where cmdline like '%addinutil.exe%';

bool network_connection_initiated_by_AddinUtil_EXE(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("addinutil.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected network connections made by the Add-In deployment cache updating utility (AddInutil.exe)";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.001 - HH.EXE Network Connections
// select * from win_process_events where cmdline like '%\hh.exe%' and cmdline like '.chm';

bool HH_EXE_network_connections(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\hh.exe") != std::string::npos && cmdline.find(".chm") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected network connections made by the 'hh.exe' process, indicating the execution/download of remotely hosted .chm files)";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Wuauclt Network Connection
// select * from win_process_events where cmdline like '%wuauclt%' and cmdline like 'UpdateDeploy.dll/ClassId';

bool wuauclt_network_connection(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("wuauclt") != std::string::npos && !(cmdline.find("UpdateDeploy.dll/ClassId") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making a network connections."; // To be reviewed
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Load Arbitrary DLL via Wuauclt
// select * from win_process_events where cmdline like '%wuauclt.exe%' and cmdline like '%/UpdateDeploymentProvider%' and cmdline like '%/RunHandlerComServer%';

bool load_arbitrary_DLL_via_wuauclt(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("wuauclt.exe") != std::string::npos && cmdline.find("/UpdateDeploymentProvider") != std::string::npos && cmdline.find("/RunHandlerComServer") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Wuauclt.exe used to load an arbitrary DLL";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.004 - Execute From Alternate Data Streams
// select * from win_process_events where cmdline like '%makecab%' and cmdline like '%.cab%' and cmdline like '%reg%' and cmdline like '%regedit%' and cmdline like '%esentutl.exe%';

bool execute_from_alternate_data_streams(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("makecab") != std::string::npos && cmdline.find(".cab") != std::string::npos && cmdline.find("reg") != std::string::npos && cmdline.find(".cab") != std::string::npos && cmdline.find("reg") != std::string::npos && cmdline.find("regedit") != std::string::npos && cmdline.find("esentutl.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution from Alternate data streams";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1140 - Potential Commandline Obfuscation Using Escape Characters
// select * from win_process_events where cmdline like '%h^t^t^p%' and cmdline like '%h"t"t"p%';

bool potential_commandline_obfuscation_using_escape_characters(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("h^t^t^p") != std::string::npos && cmdline.find("h\"t\"t\"p") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects commandline obfuscation using known escape characters";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059 - Suspicious RASdial Activity
// select * from win_process_events where path like '%rasdial.exe%';

bool suspicious_rasdial_activity(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("rasdial.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected suspicious process related to RASdial";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation CLIP+ Launcher

bool invoke_obfuscation_clip_plus_launcher(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("cmd") != std::string::npos && cmdline.find("&&") != std::string::npos && cmdline.find("clipboard]::") != std::string::npos) && (cmdline.find("-f") != std::string::npos || cmdline.find("/c") != std::string::npos || cmdline.find("/r") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated use of Clip.exe to execute Powershell";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation Obfuscated IEX Invocation

bool invoke_obfuscation_obfuscated_iex_invocation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\$PSHome\\[\\s*\\d{1,3}\\s*\\]\\s*\\+\\s*\\$PSHome\\[") != std::string::npos || cmdline.find("\\$ShellId\\[\\s*\\d{1,3}\\s*\\]\\s*\\+\\s*\\$ShellId\\[") != std::string::npos || cmdline.find("\\$env:Public\\[\\s*\\d{1,3}\\s*\\]\\s*\\+\\s*\\$env:Public\\[") != std::string::npos || cmdline.find("\\$env:ComSpec\\[(\\s*\\d{1,3}\\s*,){2}") != std::string::npos || cmdline.find("\\*mdr\\*\\W\\s*\\)\\.Name") != std::string::npos || cmdline.find("\\$VerbosePreference\\.ToString\\(") != std::string::npos || cmdline.find("\\[String\\]\\s*\\$VerbosePreference") != std::string::npos)
    {
        std::stringstream ss;
        ss << "A variation of an obfuscated powershell IEX invocation code detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation STDIN+ Launcher

bool invoke_obfuscation_stdin_launcher(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("cmd") != std::string::npos && cmdline.find("powershell") != std::string::npos && cmdline.find("input") != std::string::npos && cmdline.find("$") != std::string::npos) && (cmdline.find("/c") != std::string::npos || cmdline.find("/r") != std::string::npos || cmdline.find("noexit") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated use of stdin to execute teminal";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.005 - Unmount Share Via Net.EXE
// select * from win_process_events where ((path like '%\\net.exe%' or path like '%\\net1.exe%') and (cmdline like '%share%' and cmdline like '%/delete%'));

bool unmount_share_via_net_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos) && (cmdline.find("share") != std::string::npos && cmdline.find("/delete") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Unmount Share Via Net.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation VAR+ Launcher

bool invoke_obfuscation_var_plus_launcher(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("cmd") != std::string::npos && cmdline.find("set") != std::string::npos && cmdline.find("-f") != std::string::npos) && (cmdline.find("/c") != std::string::npos || cmdline.find("/r") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated use of Environment variables to execute teminal";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation COMPRESS OBFUSCATION

bool invoke_obfuscation_compress_obfuscation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("new-object") != std::string::npos && cmdline.find("text.encoding]::ascii") != std::string::npos) && (cmdline.find("system.io.compression.deflatestream") != std::string::npos || cmdline.find("system.io.streamreader") != std::string::npos || cmdline.find("readtoend(") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated use of Environment variables to execute teminal";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation Via stdin

bool invoke_obfuscation_via_stdin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("set") != std::string::npos && cmdline.find("&&") != std::string::npos) && (cmdline.find("environment") != std::string::npos || cmdline.find("invoke") != std::string::npos || cmdline.find("input") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated use of Environment variables to execute teminal";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation Via Use Clip

bool invoke_obfuscation_via_use_clip(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("echo") != std::string::npos && cmdline.find("clip") != std::string::npos && cmdline.find("&&") != std::string::npos) && (cmdline.find("clipboard") != std::string::npos || cmdline.find("invoke") != std::string::npos || cmdline.find("i`") != std::string::npos || cmdline.find("n`") != std::string::npos || cmdline.find("v`") != std::string::npos || cmdline.find("o`") != std::string::npos || cmdline.find("k`") != std::string::npos || cmdline.find("e`") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated Powershell via use Clip.exe in Scripts detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// // T1027 - Invoke-Obfuscation Via Use MSHTA

// bool invoke_obfuscation_via_use_clip(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

//     if ((cmdline.find("echo") != std::string::npos && cmdline.find("clip") != std::string::npos && cmdline.find("&&") != std::string::npos) || cmdline.find("clipboard") != std::string::npos || cmdline.find("invoke") != std::string::npos || cmdline.find("i`") != std::string::npos || cmdline.find("n`") != std::string::npos || cmdline.find("v`") != std::string::npos || cmdline.find("o`") != std::string::npos || cmdline.find("k`") != std::string::npos || cmdline.find("e`") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Obfuscated Powershell via use Clip.exe in Scripts detected";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

// T1027 - Invoke-Obfuscation Via Use MSHTA

bool invoke_obfuscation_via_use_mshta(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("set") != std::string::npos && cmdline.find("&&") != std::string::npos && cmdline.find("mshta") != std::string::npos && cmdline.find("vbscript:createobject") != std::string::npos && cmdline.find(".run") != std::string::npos && cmdline.find("(window.close)") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Obfuscated Powershell via use MSHTA in Scripts detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION

bool invoke_obfuscation_var_plus_plus_obfuscation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("&&set") != std::string::npos && cmdline.find("cmd") != std::string::npos && cmdline.find("/c") != std::string::npos && cmdline.find("-f") != std::string::npos) || cmdline.find("{0}") != std::string::npos || cmdline.find("{1}") != std::string::npos || cmdline.find("{2}") != std::string::npos || cmdline.find("{3}") != std::string::npos || cmdline.find("{4}") != std::string::npos || cmdline.find("{5}") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Obfuscated Powershell via VAR++ launcher detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Raccine Uninstall
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%taskkill%' AND cmdline LIKE '%RaccineSettings.exe%') OR (cmdline LIKE '%reg.exe%' AND cmdline LIKE '%delete%' AND cmdline LIKE '%Raccine Tray%') OR (cmdline LIKE '%schtasks%' AND cmdline LIKE '%/DELETE%' AND cmdline LIKE '%Raccine Rules Updater%');

bool raccine_uninstall(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("taskkill") != std::string::npos && cmdline.find("RaccineSettings.exe") != std::string::npos) || (cmdline.find("reg.exe") != std::string::npos && cmdline.find("delete") != std::string::npos && cmdline.find("Raccine Tray") != std::string::npos) || (cmdline.find("schtasks") != std::string::npos && cmdline.find("/DELETE") != std::string::npos && cmdline.find("Raccine Rules Updater") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected commands that uninstall Raccine Protection tool";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1060 - DumpStack.log Defender Evasion
// SELECT * FROM win_process_events WHERE path LIKE '%\\DumpStack.log%' AND cmdline LIKE '%-o DumpStack.log%';

bool dumpStack_log_defender_evasion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\DumpStack.log") != std::string::npos && cmdline.find("-o DumpStack.log") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the use of the filename DumpStack.log to evade Microsoft Defender (Defender ignores files name DumpStack.log)";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - New Firewall Rule Added Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND (parent_path LIKE 'C:\\Windows\\Temp\\asgard2-agent\\%' AND parent_path LIKE '%\\thor64.exe%') AND (cmdline LIKE '% firewall%' AND cmdline LIKE '% add%') AND (cmdline LIKE '%\\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow "program=C:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe" enable=yes profile=Any%' OR cmdline LIKE '%\\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow "program=C:\\Program Files\\Dropbox\\Client\\Dropbox.exe" enable=yes profile=Any%') AND cmdline LIKE '%advfirewall firewall show rule name=all%');

bool new_firewall_rule_added_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\netsh.exe") != std::string::npos && (parent_path.find("C:\\Windows\\Temp\\asgard2-agent\\") != std::string::npos && parent_path.find("\\thor64.exe") != std::string::npos) && (cmdline.find(" firewall") != std::string::npos && cmdline.find(" add") != std::string::npos) && (cmdline.find("\\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=C:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe\" enable=yes profile=Any") != std::string::npos || cmdline.find("\\netsh.exe advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=C:\\Program Files\\Dropbox\\Client\\Dropbox.exe\" enable=yes profile=Any") != std::string::npos) && cmdline.find("advfirewall firewall show rule name=all") != std::string::npos)
    {
        std::stringstream ss;
        ss << "New Firewall Rule Added Via Netsh.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - RDP Connection Allowed Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND (cmdline LIKE '% firewall%' AND cmdline LIKE '% add%' AND cmdline LIKE '%tcp%' AND cmdline LIKE '%3389%') AND (cmdline LIKE '%advfirewall%' AND cmdline LIKE '%rule%' AND cmdline LIKE '%allow%') AND cmdline LIKE '%portopening%');

bool rdp_connection_allowed_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\netsh.exe") != std::string::npos && (cmdline.find(" firewall") != std::string::npos && cmdline.find(" add") != std::string::npos && cmdline.find("tcp") != std::string::npos && cmdline.find("3389") != std::string::npos) && (cmdline.find("advfirewall") != std::string::npos && cmdline.find("rule") != std::string::npos && cmdline.find("allow") != std::string::npos) && cmdline.find("portopening") != std::string::npos)
    {
        std::stringstream ss;
        ss << "RDP Connection Allowed Via Netsh.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Firewall Rule Deleted Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND parent_path LIKE '%\\Dropbox.exe%' AND (cmdline LIKE '%firewall%' AND cmdline LIKE '%delete%') AND cmdline LIKE '%name=Dropbox%');

bool firewall_rule_deleted_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\netsh.exe") != std::string::npos && parent_path.find("\\Dropbox.exe") != std::string::npos && (cmdline.find("firewall") != std::string::npos && cmdline.find("delete") != std::string::npos) && cmdline.find("name=Dropbox") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Firewall Rule Deleted Via Netsh.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Firewall Disabled via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND cmdline LIKE '%firewall%' AND cmdline LIKE '%set%' AND cmdline LIKE '%opmode%' AND cmdline LIKE '%disable%' AND cmdline LIKE '%advfirewall%' AND cmdline LIKE '%state%' AND cmdline LIKE '%off%');

bool firewall_disabled_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\netsh.exe") != std::string::npos && cmdline.find("firewall") != std::string::npos && cmdline.find("set") != std::string::npos && cmdline.find("opmode") != std::string::npos && cmdline.find("disable") != std::string::npos && cmdline.find("advfirewall") != std::string::npos && cmdline.find("state") != std::string::npos && cmdline.find("off") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Firewall Disabled via Netsh.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Netsh Allow Group Policy on Microsoft Defender Firewall
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND cmdline LIKE '%firewall%' AND cmdline LIKE '%set%' AND cmdline LIKE '%rule%' AND cmdline LIKE '%group=%' AND cmdline LIKE '%advfirewall%' AND cmdline LIKE '%new%' AND cmdline LIKE '%enable=Yes%');

bool netsh_allow_group_policy_on_microsoft_defender_firewall(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\netsh.exe") != std::string::npos && (cmdline.find("firewall") != std::string::npos && cmdline.find("set") != std::string::npos) && cmdline.find("rule") != std::string::npos && cmdline.find("group=") != std::string::npos && cmdline.find("advfirewall") != std::string::npos && cmdline.find("new") != std::string::npos && cmdline.find("enable=Yes") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Netsh Allow Group Policy on Microsoft Defender Firewall";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.004 - Firewall Rule Update Via Netsh.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\netsh.exe%' AND cmdline LIKE '%firewall%' AND cmdline LIKE '%set%');

bool firewall_rule_update_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\netsh.exe") != std::string::npos && (cmdline.find("firewall") != std::string::npos && cmdline.find("set") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Firewall Rule Update Via Netsh.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562 - ETW Logging Tamper In .NET Processes
// SELECT * FROM win_process_events WHERE cmdline LIKE '%COMPlus_ETWEnabled%' OR cmdline LIKE '%COMPlus_ETWFlags%';

bool ETW_logging_tamper_in_NET_processes(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("COMPlus_ETWEnabled") != std::string::npos || cmdline.find("COMPlus_ETWFlags") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected changes to environment variables related to ETW logging";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.006 - Disable of ETW Trace
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/c%' AND cmdline LIKE '%cmd.exe%' AND cmdline LIKE '%logman%' AND cmdline LIKE '%trace%' AND cmdline LIKE '%provider%';

bool disable_of_ETW_trace(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("/c") != std::string::npos && cmdline.find("cmd.exe") != std::string::npos && cmdline.find("logman") != std::string::npos && cmdline.find("trace") != std::string::npos && cmdline.find("provider") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected changes to environment variables related to ETW logging";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Suspicious Execution From GUID Like Folder Names
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%\\Temp%' AND ((cmdline LIKE '%\\{%' AND cmdline LIKE '%}\\%') OR (path LIKE '%\\{%' AND path LIKE '%}\\%')));

bool suspicious_execution_from_GUID_like_folder_names(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (cmdline.find("\\Temp") != std::string::npos && ((cmdline.find("\\{") != std::string::npos && cmdline.find("}\\") != std::string::npos) || (path.find("\\{") != std::string::npos && path.find("}\\") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected potential suspicious execution of a GUID like folder name located in a suspicious location such as %TEMP%";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564 - Parent in Public Folder Suspicious Process
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%C:\\Users\\Public\\%' AND (cmdline LIKE '%cmd.exe /c %' OR cmdline LIKE '%cmd.exe /r %' OR cmdline LIKE '%cmd.exe /k %' OR cmdline LIKE '%cmd /c %' OR cmdline LIKE '%cmd /r %' OR cmdline LIKE '%cmd /k %'));

bool parent_in_public_folder_suspicious_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("C:\\Users\\Public\\") != std::string::npos && (cmdline.find("cmd.exe /c ") != std::string::npos || cmdline.find("cmd.exe /r ") != std::string::npos || cmdline.find("cmd.exe /k ") != std::string::npos || cmdline.find("cmd /c ") != std::string::npos || cmdline.find("cmd /r ") != std::string::npos || cmdline.find("cmd /k ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious processes with parent images locacted in C:\\Users\\Public folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564 - Parent in Public Folder Suspicious Process
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/c%' AND cmdline LIKE '%::$index_allocation%';

bool potential_hidden_directory_creation_via_NTFS_INDEX_ALLOCATION_stream_CLI(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("/c") != std::string::npos && cmdline.find("::$index_allocation") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected activity that prevents access to folders or files from tooling such as 'explorer.exe' or 'powershell.exe'";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1211 - Writing Of Malicious Files To The Fonts Folder
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/c%' AND cmdline LIKE '%::$index_allocation%';

bool writing_of_malicious_files_to_the_fonts_folder(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("echo") != std::string::npos || cmdline.find("copy") != std::string::npos || cmdline.find("type") != std::string::npos || cmdline.find("file createnew") != std::string::npos || cmdline.find("cacls") != std::string::npos) && (cmdline.find("C:\\Windows\\Fonts\\") != std::string::npos) && (cmdline.find(".sh") != std::string::npos || cmdline.find(".exe") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".bin") != std::string::npos || cmdline.find(".bat") != std::string::npos || cmdline.find(".cmd") != std::string::npos || cmdline.find(".js") != std::string::npos || cmdline.find(".msh") != std::string::npos || cmdline.find(".reg") != std::string::npos || cmdline.find(".scr") != std::string::npos || cmdline.find(".ps") != std::string::npos || cmdline.find(".vb") != std::string::npos || cmdline.find(".jar") != std::string::npos || cmdline.find(".pl") != std::string::npos || cmdline.find(".inf") != std::string::npos || cmdline.find(".cpl") != std::string::npos || cmdline.find(".hta") != std::string::npos || cmdline.find(".msi") != std::string::npos || cmdline.find(".vbs") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected activity that prevents access to folders or files from tooling such as 'explorer.exe' or 'powershell.exe'";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564 - Parent in Public Folder Suspicious Process
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%reg%' AND cmdline LIKE '%add%') OR (cmdline LIKE '%powershell%' AND cmdline LIKE '%set-itemproperty%' AND cmdline LIKE '%sp%' AND cmdline LIKE '%new-itemproperty%')) AND (cmdline LIKE '%ControlSet%' AND cmdline LIKE '%Services%');

bool non_privileged_usage_of_reg_or_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (((cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos) || (cmdline.find("powershell") != std::string::npos && cmdline.find("set-itemproperty") != std::string::npos && cmdline.find("sp") != std::string::npos && cmdline.find("new-itemproperty") != std::string::npos)) && (cmdline.find("ControlSet") != std::string::npos && cmdline.find("Services") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected non-privileged Usage of Reg or Powershell";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Add SafeBoot Keys Via Reg Utility
// SELECT * FROM win_process_events WHERE path LIKE '%reg.exe%' AND cmdline LIKE '%\SYSTEM\CurrentControlSet\Control\SafeBoot%' AND (cmdline LIKE '% add %' OR cmdline LIKE '% add %');

bool add_safeboot_keys_via_reg_utility(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("reg.exe") != std::string::npos && cmdline.find("\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot") != std::string::npos && (cmdline.find(" copy ") != std::string::npos || cmdline.find(" add ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of reg.exe allowing ransomware to work in safe mode";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// CVE.2023.21746 Hacktool - LocalPotato Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%.exe -i C:\%' AND cmdline LIKE '%-o Windows\%';

bool hacktool_localpotato_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\LocalPotato.exe") != std::string::npos) && (cmdline.find(".exe -i C:\\") != std::string::npos && cmdline.find("-o Windows\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "LocalPotato Execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Hacktool - Powertool Execution
// SELECT * FROM win_process_events WHERE path LIKE '%PowerTool.exe%' OR path LIKE '%PowerTool64.exe%';

bool hacktool_powertool_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("PowerTool.exe") != std::string::npos || path.find("PowerTool64.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powertool execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND (cmdline LIKE '%SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths%' OR cmdline LIKE '%SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths%') AND (cmdline LIKE '%ADD %' AND cmdline LIKE '%/t %' AND cmdline LIKE '%REG_DWORD %' AND cmdline LIKE '%/v %' AND cmdline LIKE '%/d %' AND cmdline LIKE '%0%');

bool suspicious_windows_defender_folder_exclusion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && (cmdline.find("SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths") != std::string::npos || cmdline.find("SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths") != std::string::npos) && (cmdline.find("ADD ") != std::string::npos && cmdline.find("/t ") != std::string::npos && cmdline.find("REG_DWORD ") != std::string::npos && cmdline.find("/v ") != std::string::npos && cmdline.find("/d ") != std::string::npos && cmdline.find("0") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of reg.exe to add Defender folder exclusions";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - SafeBoot Registry Key Deleted Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%reg.exe%' AND cmdline LIKE '%\SYSTEM\CurrentControlSet\Control\SafeBoot%' AND cmdline LIKE '% delete %';

bool safeboot_registry_key_deleted_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("reg.exe") != std::string::npos && cmdline.find("\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot") != std::string::npos && cmdline.find(" delete ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of reg.exe to prevent safeboot execution of security products";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Service Registry Key Deleted Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%reg.exe%' AND cmdline LIKE '%\SYSTEM\CurrentControlSet\services\%' AND cmdline LIKE '% delete %';

bool service_registry_key_deleted_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("reg.exe") != std::string::npos && cmdline.find("\\SYSTEM\\CurrentControlSet\\services\\") != std::string::npos && cmdline.find(" delete ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of reg.exe to remove AV software services";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Security Service Disabled Via Reg.EXE
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%reg%' AND cmdline LIKE '%add%') AND ((cmdline LIKE '%d 4%' AND cmdline LIKE '%v Start%') AND (cmdline LIKE '%\AppIDSvc%' OR cmdline LIKE '%\MsMpSvc%' OR cmdline LIKE '%\NisSrv%' OR cmdline LIKE '%\SecurityHealthService%' OR cmdline LIKE '%\Sense%' OR cmdline LIKE '%\UsoSvc%' OR cmdline LIKE '%\WdBoot%' OR cmdline LIKE '%\WdFilter%' OR cmdline LIKE '%\WdNisDrv%' OR cmdline LIKE '%\WdNisSvc%' OR cmdline LIKE '%\WinDefend%' OR cmdline LIKE '%\wscsvc%' OR cmdline LIKE '%\wuauserv%'));

bool security_service_disabled_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos) && ((cmdline.find("d 4") != std::string::npos && cmdline.find("v Start") != std::string::npos) && (cmdline.find("\\AppIDSvc") != std::string::npos || cmdline.find("\\MsMpSvc") != std::string::npos || cmdline.find("\\NisSrv") != std::string::npos || cmdline.find("\\SecurityHealthService") != std::string::npos || cmdline.find("\\Sense") != std::string::npos || cmdline.find("\\UsoSvc") != std::string::npos || cmdline.find("\\WdBoot") != std::string::npos || cmdline.find("\\WdFilter") != std::string::npos || cmdline.find("\\WdNisDrv") != std::string::npos || cmdline.find("\\WdNisSvc") != std::string::npos || cmdline.find("\\WinDefend") != std::string::npos || cmdline.find("\\wscsvc") != std::string::npos || cmdline.find("\\wuauserv") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected execution of reg.exe to disable security services";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Potential Suspicious Registry File Imported Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND cmdline LIKE '% import %' AND (cmdline LIKE '%C:\Users\%' OR cmdline LIKE '%%temp%%' OR cmdline LIKE '%%tmp%%' OR cmdline LIKE '%%appdata%%' OR cmdline LIKE '%\AppData\Local\Temp\%' OR cmdline LIKE '%C:\Windows\Temp\%' OR cmdline LIKE '%C:\ProgramData\%');

bool suspicious_registry_file_imported_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && cmdline.find(" import ") != std::string::npos && (cmdline.find("C:\\Users\\") != std::string::npos || cmdline.find("temp") != std::string::npos || cmdline.find("%tmp%") != std::string::npos || cmdline.find("appdata") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("C:\\Windows\\Temp\\") != std::string::npos || cmdline.find("C:\\ProgramData\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected import of '.reg' files from suspicious paths";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Disabled RestrictedAdminMode For RDS - ProcCreation
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\System\CurrentControlSet\Control\Lsa\%' AND cmdline LIKE '%DisableRestrictedAdmin%' AND cmdline LIKE '% 1%';

bool disabled_restrictedadminmode_for_rds(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\System\\CurrentControlSet\\Control\\Lsa\\") != std::string::npos && cmdline.find("DisableRestrictedAdmin") != std::string::npos && cmdline.find(" 1") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected activation of DisableRestrictedAdmin to desable RestrictedAdmin mode";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.010 - LSA PPL Protection Disabled Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND (cmdline LIKE '%\System\CurrentControlSet\Control\Lsa\%' OR (cmdline LIKE '% add %' AND cmdline LIKE '% /d 0%' AND cmdline LIKE '% /v RunAsPPL %'));

bool lsa_ppl_protection_disabled_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && (cmdline.find("\\System\\CurrentControlSet\\Control\\Lsa\\") != std::string::npos || (cmdline.find(" add ") != std::string::npos && cmdline.find(" /d 0") != std::string::npos && cmdline.find(" /v RunAsPPL ") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected usage of reg.exe to disable PPL protection on the LSA process";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1484.001 - Modify Group Policy Settings
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND cmdline LIKE '%\SOFTWARE\Policies\Microsoft\Windows\System%' AND (cmdline LIKE '%GroupPolicyRefreshTimeDC%' OR cmdline LIKE '%GroupPolicyRefreshTimeOffsetDC%' OR cmdline LIKE '%GroupPolicyRefreshTime%' OR cmdline LIKE '%GroupPolicyRefreshTimeOffset%' OR cmdline LIKE '%EnableSmartScreen%' OR cmdline LIKE '%ShellSmartScreenLevel%');

bool modify_group_policy_settings(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && cmdline.find("\\SOFTWARE\\Policies\\Microsoft\\Windows\\System") != std::string::npos && (cmdline.find("GroupPolicyRefreshTimeDC") != std::string::npos || cmdline.find("GroupPolicyRefreshTimeOffsetDC") != std::string::npos || cmdline.find("GroupPolicyRefreshTime") != std::string::npos || cmdline.find("GroupPolicyRefreshTimeOffset") != std::string::npos || cmdline.find("EnableSmartScreen") != std::string::npos || cmdline.find("ShellSmartScreenLevel") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected malicious GPO modifications";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.004 - Use NTFS Short Name in Command Line
// SELECT * FROM win_process_events WHERE cmdline LIKE '%~1.exe%' OR cmdline LIKE '%~1.bat%' OR cmdline LIKE '%~1.msi%' OR cmdline LIKE '%~1.vbe%' OR cmdline LIKE '%~1.vbs%' OR cmdline LIKE '%~1.dll%' OR cmdline LIKE '%~1.ps1%' OR cmdline LIKE '%~1.js%' OR cmdline LIKE '%~1.hta%' OR cmdline LIKE '%~2.exe%' OR cmdline LIKE '%~2.bat%' OR cmdline LIKE '%~2.msi%' OR cmdline LIKE '%~2.vbe%' OR cmdline LIKE '%~2.vbs%' OR cmdline LIKE '%~2.dll%' OR cmdline LIKE '%~2.ps1%' OR cmdline LIKE '%~2.js%' OR cmdline LIKE '%~2.hta%';

bool use_NTFS_short_name_in_command_ine(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (cmdline.find("~1.exe") != std::string::npos ||
        cmdline.find("~1.bat") != std::string::npos ||
        cmdline.find("~1.msi") != std::string::npos ||
        cmdline.find("~1.vbe") != std::string::npos ||
        cmdline.find("~1.vbs") != std::string::npos ||
        cmdline.find("~1.dll") != std::string::npos ||
        cmdline.find("~1.ps1") != std::string::npos ||
        cmdline.find("~1.js") != std::string::npos ||
        cmdline.find("~1.hta") != std::string::npos ||
        cmdline.find("~2.exe") != std::string::npos ||
        cmdline.find("~2.bat") != std::string::npos ||
        cmdline.find("~2.msi") != std::string::npos ||
        cmdline.find("~2.vbe") != std::string::npos ||
        cmdline.find("~2.vbs") != std::string::npos ||
        cmdline.find("~2.dll") != std::string::npos ||
        cmdline.find("~2.ps1") != std::string::npos ||
        cmdline.find("~2.js") != std::string::npos ||
        cmdline.find("~2.hta") != std::string::npos && !(parent_path.find("\\WebEx\\WebexHost.exe") != std::string::npos ||
                                                         parent_path.find("\\thor\\thor64.exe") != std::string::npos || cmdline.find("C:\\xampp\\vcredist\\VCREDI~1.EXE") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of NTFS Short Name in Command Line";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1021.001 - Potential Tampering With RDP Related Registry Keys Via Reg.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND (cmdline LIKE '% add %' AND cmdline LIKE '%\CurrentControlSet\Control\Terminal Server%' AND cmdline LIKE '%REG_DWORD%' AND cmdline LIKE '% /f%') && ((cmdline LIKE '%Licensing Core%' AND cmdline LIKE '%EnableConcurrentSessions%') || (cmdline LIKE '%WinStations\RDP-Tcp%' OR cmdline LIKE '%MaxInstanceCount%' OR cmdline LIKE '%fEnableWinStation%' OR cmdline LIKE '%TSUserEnabled%' OR cmdline LIKE '%TSEnabled%' OR cmdline LIKE '%TSAppCompat%' OR cmdline LIKE '%IdleWinStationPoolCount%' OR cmdline LIKE '%TSAdvertise%' OR cmdline LIKE '%AllowTSConnections%' OR cmdline LIKE '%fSingleSessionPerUser%' OR cmdline LIKE '%fDenyTSConnections%'));

bool tampering_with_rdp_related_registry_keys_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && (cmdline.find(" add ") != std::string::npos && cmdline.find("\\CurrentControlSet\\Control\\Terminal Server") != std::string::npos && cmdline.find("REG_DWORD") != std::string::npos && cmdline.find(" /f") != std::string::npos) && ((cmdline.find("Licensing Core") != std::string::npos && cmdline.find("EnableConcurrentSessions") != std::string::npos) || (cmdline.find("WinStations\\RDP-Tcp") != std::string::npos || cmdline.find("MaxInstanceCount") != std::string::npos || cmdline.find("fEnableWinStation") != std::string::npos || cmdline.find("TSUserEnabled") != std::string::npos || cmdline.find("TSEnabled") != std::string::npos || cmdline.find("TSAppCompat") != std::string::npos || cmdline.find("IdleWinStationPoolCount") != std::string::npos || cmdline.find("TSAdvertise") != std::string::npos || cmdline.find("AllowTSConnections") != std::string::npos || cmdline.find("fSingleSessionPerUser") != std::string::npos || cmdline.find("fDenyTSConnections") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected the execution of reg.exe for enabling/disabling the RDP service by tampering with values";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036.002 - Potential Defense Evasion Via Right-to-Left Override
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\\u202e%';

bool potential_defense_evasion_via_right_to_left_override(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\u202e") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the presence of the 'u202E' character, which causes a terminal, browser, or operating system to render text in a right-to-left sequence. This is used as an obfuscation and masquerading techniques.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Suspicious Windows Service Tampering
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%net.exe%' AND cmdline LIKE '%sc.exe%' AND (cmdline LIKE '%stop%' OR cmdline LIKE '%delete%' OR cmdline LIKE '%pause%')) OR (cmdline LIKE '%powershell%' AND cmdline LIKE '%Stop-Service%' AND cmdline LIKE '%Remove-Service%'));

bool suspicious_windows_service_tampering(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("net.exe") != std::string::npos && cmdline.find("sc.exe") != std::string::npos && (cmdline.find("stop") != std::string::npos || cmdline.find("delete") != std::string::npos || cmdline.find("pause") != std::string::npos)) || (cmdline.find("powershell") != std::string::npos && cmdline.find("Stop-Service") != std::string::npos && cmdline.find("Remove-Service") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the usage of binaries such as 'net', 'sc' or 'powershell' in order to stop, pause or delete critical or important Windows services";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Process Creation Using Sysnative Folder
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Sysnative%');

bool process_creation_using_sysnative_folder(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Sysnative") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected process creation events that use the Sysnative folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.002 - Tasks Folder Evasion
// SELECT * FROM win_process_events WHERE cmdline LIKE '%echo%' AND cmdline LIKE '%copy%' AND cmdline LIKE '%type%' AND cmdline LIKE '%file createnew%' AND cmdline LIKE '%\\Tasks%';

bool tasks_folder_evasion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("echo ") != std::string::npos &&
        cmdline.find("copy ") != std::string::npos &&
        cmdline.find("type ") != std::string::npos &&
        cmdline.find("file createnew") != std::string::npos &&
        cmdline.find("\\Tasks") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected task folder evasion"; // To be reviewed
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Suspicious Userinit Child Process
// SELECT * FROM win_process_events WHERE parent_path LIKE '%userinit.exe%' AND cmdline LIKE '%\\netlogon%';

bool suspicious_userinit_child_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("userinit.exe") != std::string::npos &&
        cmdline.find("\\netlogon") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected a suspicious child process of userinit";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Execution via WorkFolders.exe
// SELECT * FROM win_process_events WHERE path LIKE '%\\control.exe%' AND parent_path LIKE '%\\WorkFolders.exe%';

bool execution_via_workFolders_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (path.find("\\control.exe") != std::string::npos && parent_path.find("\\WorkFolders.exe") != std::string::npos && !(path.find("C:\\Windows\\System32\\control.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected use of WorkFolders.exe to execute an arbitrary control.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036.005 - Suspicious Svchost Process
// SELECT * FROM win_process_events WHERE path LIKE '%\\svchost.exe%' AND (cmdline LIKE '%\\services.exe%' OR cmdline LIKE '%\\MsMpEng.exe%' OR cmdline LIKE '%\\Mrt.exe%' OR cmdline LIKE '%\\rpcnet.exe%' OR cmdline LIKE '%\\ngen.exe%' OR cmdline LIKE '%\\TiWorker.exe%');

bool suspicious_svchost_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\svchost.exe") != std::string::npos &&
        (cmdline.find("\\services.exe") != std::string::npos ||
         cmdline.find("\\MsMpEng.exe") != std::string::npos ||
         cmdline.find("\\Mrt.exe") != std::string::npos ||
         cmdline.find("\\rpcnet.exe") != std::string::npos ||
         cmdline.find("\\ngen.exe") != std::string::npos ||
         cmdline.find("\\TiWorker.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a suspicious svchost process start";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1134.004 - HackTool - PPID Spoofing SelectMyParent Tool Execution

bool hacktool_ppid_spoofing_selectmyparent_tool_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("PPID-spoof") != std::string::npos && cmdline.find("ppid_spoof") != std::string::npos && cmdline.find("spoof-ppid") != std::string::npos && cmdline.find("spoof_ppid") != std::string::npos && cmdline.find("ppidspoof") != std::string::npos && cmdline.find("spoofppid") != std::string::npos && cmdline.find("spoofedppid") != std::string::npos && cmdline.find("-spawnto") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of parent process ID spoofing tools like Didier Stevens tool SelectMyParent detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// TA0005 - Kernel Memory Dump Via LiveKD
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\livekd.exe%' OR path LIKE '%\\livekd64.exe%') AND cmdline LIKE '%/m%' AND cmdline LIKE '%-m%');

bool kernel_memory_dump_via_liveKD(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\livekd.exe") != std::string::npos || path.find("\\livekd64.exe") != std::string::npos) && cmdline.find("/m") != std::string::npos && cmdline.find("-m") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of LiveKD with the ' - m ' flag to potentially dump the kernel memory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.001 - Potential SysInternals ProcDump Evasion
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%procdump%' AND cmdline LIKE '%.dmp%') AND (cmdline LIKE '%copy%' OR cmdline LIKE '%move%');

bool potential_sysInternals_procDump_evasion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("procdump") != std::string::npos && cmdline.find(".dmp") != std::string::npos) && (cmdline.find("copy") != std::string::npos || cmdline.find("move") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected uses of the SysInternals ProcDump utility in which ProcDump gets renamed, or a dump file is moved or copied to a different name";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Reg Add Suspicious Paths
// SELECT * FROM win_process_events WHERE path LIKE '%\reg.exe%' AND (cmdline LIKE '%\AppDataLow\Software\Microsoft\%' OR cmdline LIKE '%\Policies\Microsoft\Windows\OOBE%' OR cmdline LIKE '%\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon%' OR cmdline LIKE '%\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon%' OR cmdline LIKE '%\CurrentControlSet\Control\SecurityProviders\WDigest%' OR cmdline LIKE '%\Microsoft\Windows Defender\%');

bool reg_add_suspicious_paths(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && (cmdline.find("\\AppDataLow\\Software\\Microsoft\\") != std::string::npos || cmdline.find("\\Policies\\Microsoft\\Windows\\OOBE") != std::string::npos || cmdline.find("\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") != std::string::npos || cmdline.find("\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon") != std::string::npos || cmdline.find("\\CurrentControlSet\\Control\\SecurityProviders\\WDigest") != std::string::npos || cmdline.find("\\Microsoft\\Windows Defender\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected use of reg.exe utility to add or modify new keys or subkeys";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Disabled Volume Snapshots
// SELECT * FROM win_process_events WHERE cmdline LIKE '%reg%' AND cmdline LIKE '% add %' AND cmdline LIKE '%\Services\VSS\Diag%' AND cmdline LIKE '%/d Disabled%';

bool disabled_volume_snapshots(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("reg") != std::string::npos && cmdline.find(" add ") != std::string::npos && cmdline.find("\\Services\\VSS\\Diag") != std::string::npos && cmdline.find("/d Disabled") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected temporary turning off of Volume Snapshots";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562 - Write Protect For Storage Disabled
// SELECT * FROM win_process_events WHERE cmdline LIKE '%reg add%' AND cmdline LIKE '%\system\currentcontrolset\control%' AND cmdline LIKE '%write protection%' AND cmdline LIKE '%0%' && (cmdline LIKE '%storage%' OR cmdline LIKE '%storagedevicepolicies%');

bool write_protect_for_storage_disabled(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("reg add") != std::string::npos && cmdline.find("\\system\\currentcontrolset\\control") != std::string::npos && cmdline.find("write protection") != std::string::npos && cmdline.find("0") != std::string::npos && (cmdline.find("storage") != std::string::npos || cmdline.find("storagedevicepolicies") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected temporary turning off of Volume Snapshots";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574 - DLL Execution Via Register-cimprovider.exe
// SELECT * FROM win_process_events WHERE path LIKE '%register-cimprovider.exe%' AND cmdline LIKE '%-path%' AND cmdline LIKE '%dll%';

bool dll_execution_via_register_cimprovider(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("register-cimprovider.exe") != std::string::npos && cmdline.find("-path") != std::string::npos && cmdline.find("dll") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected using register-cimprovider.exe to execute arbitrary dll file.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// // T1003.001 - Potential LSASS Process Dump Via Procdump
// // SELECT * FROM win_process_events WHERE (cmdline LIKE '%-ma%' OR cmdline LIKE '%/ma%') AND cmdline LIKE '%ls%';

// bool potential_LSASS_process_dump_via_procdump(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

//     if ((cmdline.find("-ma") != std::string::npos || cmdline.find("/ma") != std::string::npos) && cmdline.find("ls") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Detected suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process.";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

// T1562.001 - Sysinternals PsSuspend Suspicious Execution
// SELECT * FROM win_process_events WHERE (path LIKE '%\\pssuspend.exe%' OR path LIKE '%\\pssuspend64.exe%') AND cmdline LIKE '%msmpeng.exe%';

bool sysinternals_psSuspend_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.cmdline;

    if ((path.find("\\pssuspend.exe") != std::string::npos || path.find("\\pssuspend64.exe") != std::string::npos) && cmdline.find("msmpeng.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected suspicious execution of Sysinternals PsSuspend, where the utility is used to suspend critical processes such as AV or EDR to bypass defenses.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool hacktool_sharpevtmute_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\SharpEvtMute.exe") != std::string::npos) && cmdline.find("--Encoded --Filter \"") != std::string::npos || cmdline.find("--Filter \"rule") != std::string::npos)
    {
        std::stringstream ss;
        ss << "SharpEvtHook presence detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Unload Sysmon Filter Driver
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%cmd.exe%' AND cmdline LIKE '%/c%') AND cmdline LIKE '%fltmc.exe%' AND cmdline LIKE '%unload%' AND cmdline LIKE '%SysmonDrv%');

bool sysmon_configuration_update(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos &&
        cmdline.find("/c") != std::string::npos &&
        cmdline.find("fltmc.exe") != std::string::npos &&
        cmdline.find("unload") != std::string::npos &&
        cmdline.find("SysmonDrv") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected updates to Sysmon's configuration.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Uninstall Sysinternals Sysmon
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%cmd.exe%' AND cmdline LIKE '%/C%' AND cmdline LIKE '%sysmon%' AND cmdline LIKE '%-u%');

bool uninstall_sysinternal_sysmon(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos &&
        cmdline.find("/C") != std::string::npos &&
        cmdline.find("sysmon") != std::string::npos &&
        cmdline.find("-u") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected removal of sysmon, which could potentially lead to defence evasion.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1222.001 - Suspicious Recursive Takeown
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%takeown.exe%' AND cmdline LIKE '%/f%' AND cmdline LIKE '%/r%');

bool suspicious_recursive_takeown(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("takeown.exe") != std::string::npos &&
        cmdline.find("/f") != std::string::npos &&
        cmdline.find("/r") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected modification of the filesystem permissions of specified file or folder to take ownership of the object.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Taskkill Symantec Endpoint Protection
// SELECT * FROM win_process_events WHERE cmdline LIKE '%taskkill%' AND cmdline LIKE '% /F %' AND cmdline LIKE '% /IM %' AND cmdline LIKE '%ccSvcHst.exe%';

bool taskkill_symantec_endpoint_protection(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("taskkill") != std::string::npos &&
        cmdline.find("/F") != std::string::npos &&
        cmdline.find("/IM") != std::string::npos &&
        cmdline.find("ccSvcHst.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected one of the possible scenarios for disabling Symantec Endpoint Protection.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Taskmgr as LOCAL_SYSTEM
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%') AND cmdline LIKE '%\\taskmgr.exe%';

bool taskmgr_LOCAL_SYSTEM(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("AUTHORI") != std::string::npos ||
         cmdline.find("AUTORI") != std::string::npos) &&
        cmdline.find("\\taskmgr.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the creation of taskmgr.exe process in context of LOCAL_SYSTEM.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 UAC Bypass using ChangePK and SLUI
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%\\changepk.exe%' AND cmdline LIKE '%\\slui.exe%') OR (cmdline LIKE '%\\uacme%' AND cmdline LIKE '%\\61%' AND cmdline LIKE '%Akagi64.exe%');

bool uac_bypass_using_changePK_and_SLUI(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("\\changepk.exe") != std::string::npos &&
         cmdline.find("\\slui.exe") != std::string::npos) ||
        (cmdline.find("\\uacme") != std::string::npos &&
         cmdline.find("\\61") != std::string::npos && cmdline.find("Akagi64.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a UAC bypass that uses changepk.exe and slui.exe (UACMe 61)";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - UAC Bypass Using Disk Cleanup
// SELECT * FROM win_process_events WHERE cmdline LIKE '%iex(new-object%' AND cmdline LIKE '%UACBypass%' AND cmdline LIKE '%-technique%' AND cmdline LIKE '%DiskCleanup%';

bool uac_bypass_using_disk_cleanup(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("iex(new-object") != std::string::npos && cmdline.find("UACBypass") != std::string::npos &&
        cmdline.find("-technique") != std::string::npos && cmdline.find("DiskCleanup") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected a UAC bypass using Disk Cleanup.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Potential Provisioning Registry Key Abuse For Binary Proxy Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%SOFTWARE\Microsoft\Provisioning\Commands\%';

bool potential_provisioning_registry_key_abuse_for_binary_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("SOFTWARE\\Microsoft\\Provisioning\\Commands\\") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected potential abuse of the provisioning registry key";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Potential PowerShell Execution Policy Tampering - ProcCreation
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%\ShellIds\Microsoft.PowerShell\ExecutionPolicy%' OR cmdline LIKE '%\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy%') AND (cmdline LIKE '%Bypass%' OR cmdline LIKE '%RemoteSigned%' OR cmdline LIKE '%Unrestricted%');

bool potential_powerShell_execution_policy_tampering_proccreation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy") != std::string::npos || cmdline.find("\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy") != std::string::npos) && (cmdline.find("Bypass") != std::string::npos || cmdline.find("RemoteSigned") != std::string::npos || cmdline.find("Unrestricted") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected changes to the PowerShell execution policy registry key";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Potential Regsvr32 Commandline Flag Anomaly
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND (cmdline LIKE '% /i:%' OR cmdline LIKE '% -i:%') AND NOT (cmdline LIKE '% /n %' OR cmdline LIKE '% -n %');

bool potential_regsvr32_commandline_flag_anomaly(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\regsvr32.exe") != std::string::npos && (cmdline.find(" /i:") != std::string::npos || cmdline.find(" -i:") != std::string::npos) && !(cmdline.find(" /n ") != std::string::npos || cmdline.find(" -n ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a potential command line flag anomaly related to 'regsvr32'";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Potentially Suspicious Regsvr32 HTTP IP Pattern
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND (cmdline LIKE '% /i:http://1%' OR cmdline LIKE '% /i:http://2%' OR cmdline LIKE '% /i:http://3%' OR cmdline LIKE '% /i:http://4%' OR cmdline LIKE '% /i:http://5%' OR cmdline LIKE '% /i:http://6%' OR cmdline LIKE '% /i:http://7%' OR cmdline LIKE '% /i:http://8%' OR cmdline LIKE '% /i:http://9%' OR cmdline LIKE '% /i:https://1%' OR cmdline LIKE '% /i:https://2%' OR cmdline LIKE '% /i:https://3%' OR cmdline LIKE '% /i:https://4%' OR cmdline LIKE '% /i:https://5%' OR cmdline LIKE '% /i:https://6%' OR cmdline LIKE '% /i:https://7%' OR cmdline LIKE '% /i:https://8%' OR cmdline LIKE '% /i:https://9%' OR cmdline LIKE '% -i:http://1%' OR cmdline LIKE '% -i:http://2%' OR cmdline LIKE '% -i:http://3%' OR cmdline LIKE '% -i:http://4%' OR cmdline LIKE '% -i:http://5%' OR cmdline LIKE '% -i:http://6%' OR cmdline LIKE '% -i:http://7%' OR cmdline LIKE '% -i:http://8%' OR cmdline LIKE '% -i:http://9%' OR cmdline LIKE '% -i:https://1%' OR cmdline LIKE '% -i:https://2%' OR cmdline LIKE '% -i:https://3%' OR cmdline LIKE '% -i:https://4%' OR cmdline LIKE '% -i:https://5%' OR cmdline LIKE '% -i:https://6%' OR cmdline LIKE '% -i:https://7%' OR cmdline LIKE '% -i:https://8%' OR cmdline LIKE '% -i:https://9%');

bool potentially_suspicious_regsvr32_http_ip_pattern(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\regsvr32.exe") != std::string::npos && (cmdline.find(" /i:http://1") != std::string::npos || cmdline.find(" /i:http://2") != std::string::npos || cmdline.find(" /i:http://3") != std::string::npos || cmdline.find(" /i:http://4") != std::string::npos || cmdline.find(" /i:http://5") != std::string::npos || cmdline.find(" /i:http://6") != std::string::npos || cmdline.find(" /i:http://7") != std::string::npos || cmdline.find(" /i:http://8") != std::string::npos || cmdline.find(" /i:http://9") != std::string::npos || cmdline.find(" /i:https://1") != std::string::npos || cmdline.find(" /i:https://2") != std::string::npos || cmdline.find(" /i:https://3") != std::string::npos || cmdline.find(" /i:https://4") != std::string::npos || cmdline.find(" /i:https://5") != std::string::npos || cmdline.find(" /i:https://6") != std::string::npos || cmdline.find(" /i:https://7") != std::string::npos || cmdline.find(" /i:https://8") != std::string::npos || cmdline.find(" /i:https://9") != std::string::npos || cmdline.find(" -i:http://1") != std::string::npos || cmdline.find(" -i:http://2") != std::string::npos || cmdline.find(" -i:http://3") != std::string::npos || cmdline.find(" -i:http://4") != std::string::npos || cmdline.find(" -i:http://5") != std::string::npos || cmdline.find(" -i:http://6") != std::string::npos || cmdline.find(" -i:http://7") != std::string::npos || cmdline.find(" -i:http://8") != std::string::npos || cmdline.find(" -i:http://9") != std::string::npos || cmdline.find(" -i:https://1") != std::string::npos || cmdline.find(" -i:https://2") != std::string::npos || cmdline.find(" -i:https://3") != std::string::npos || cmdline.find(" -i:https://4") != std::string::npos || cmdline.find(" -i:https://5") != std::string::npos || cmdline.find(" -i:https://6") != std::string::npos || cmdline.find(" -i:https://7") != std::string::npos || cmdline.find(" -i:https://8") != std::string::npos || cmdline.find(" -i:https://9") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected regsvr32 execution to download and install DLLs located remotely where the address is an IP address.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Potentially Suspicious Regsvr32 HTTP/FTP Pattern
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\regsvr32.exe%' AND (cmdline LIKE '% /i%' OR cmdline LIKE '% -i%') AND (cmdline LIKE '%ftp%' OR cmdline LIKE '%http%');

bool potentially_suspicious_regsvr32_http_ftp_pattern(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\regsvr32.exe") != std::string::npos && (cmdline.find(" /i") != std::string::npos || cmdline.find(" -i") != std::string::npos) && (cmdline.find("ftp") != std::string::npos || cmdline.find("http") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected regsvr32 execution to download/install/register new DLLs that are hosted on Web or FTP servers.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Suspicious Regsvr32 Execution From Remote Share
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND cmdline LIKE '% \\\\%';

bool suspicious_regsvr32_execution_from_remote_share(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\regsvr32.exe") != std::string::npos && cmdline.find(" \\\\\\\\") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected regsvr32.exe to execute DLL hosted on remote shares";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Potentially Suspicious Child Process Of Regsvr32
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\regsvr32.exe%' AND (path LIKE '%\calc.exe%' OR path LIKE '%\cscript.exe%' OR path LIKE '%\explorer.exe%' OR path LIKE '%\mshta.exe%' OR path LIKE '%\net.exe%' OR path LIKE '%\net1.exe%' OR path LIKE '%\nltest.exe%' OR path LIKE '%\notepad.exe%' OR path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%' OR path LIKE '%\reg.exe%' OR path LIKE '%\schtasks.exe%' OR path LIKE '%\werfault.exe%' OR path LIKE '%\wscript.exe%') AND NOT (path LIKE '%\werfault.exe%' AND cmdline LIKE '% -u -p %');

bool potentially_suspicious_child_process_of_regsvr32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\regsvr32.exe") != std::string::npos && (path.find("\\calc.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\explorer.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\net.exe") != std::string::npos || path.find("\\net1.exe") != std::string::npos || path.find("\\nltest.exe") != std::string::npos || path.find("\\notepad.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\reg.exe") != std::string::npos || path.find("\\schtasks.exe") != std::string::npos || path.find("\\werfault.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos) && !(path.find("\\werfault.exe") != std::string::npos && cmdline.find(" -u -p ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected potentially suspicious child processes of 'regsvr32.exe'.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Regsvr32 Execution From Potential Suspicious Location
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND (cmdline LIKE '%:\ProgramData\%' OR cmdline LIKE '%:\Temp\%' OR cmdline LIKE '%:\Users\Public\%' OR cmdline LIKE '%:\Windows\Temp\%' OR cmdline LIKE '%\AppData\Local\Temp\%' OR cmdline LIKE '%\AppData\Roaming\%');

bool regsvr32_execution_from_potential_suspicious_location(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\regsvr32.exe") != std::string::npos && (cmdline.find(":\\ProgramData\\") != std::string::npos || cmdline.find(":\\Temp\\") != std::string::npos || cmdline.find(":\\Users\\Public\\") != std::string::npos || cmdline.find(":\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Roaming\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of regsvr32 where the DLL is located in a potentially suspicious location.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Regsvr32 DLL Execution With Suspicious File Extension
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND (cmdline LIKE '%.bin%' OR cmdline LIKE '%.bmp%' OR cmdline LIKE '%.cr2%' OR cmdline LIKE '%.dat%' OR cmdline LIKE '%.eps%' OR cmdline LIKE '%.gif%' OR cmdline LIKE '%.ico%' OR cmdline LIKE '%.jpeg%' OR cmdline LIKE '%.jpg%' OR cmdline LIKE '%.nef%' OR cmdline LIKE '%.orf%' OR cmdline LIKE '%.png%' OR cmdline LIKE '%.raw%' OR cmdline LIKE '%.sr2%' OR cmdline LIKE '%.temp%' OR cmdline LIKE '%.tif%' OR cmdline LIKE '%.tiff%' OR cmdline LIKE '%.tmp%' OR cmdline LIKE '%.rtf%' OR cmdline LIKE '%.txt%');

bool regsvr32_dll_execution_with_suspicious_file_extension(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\regsvr32.exe") != std::string::npos && (cmdline.find(".bin") != std::string::npos || cmdline.find(".bmp") != std::string::npos || cmdline.find(".cr2") != std::string::npos || cmdline.find(".dat") != std::string::npos || cmdline.find(".eps") != std::string::npos || cmdline.find(".gif") != std::string::npos || cmdline.find(".ico") != std::string::npos || cmdline.find(".jpeg") != std::string::npos || cmdline.find(".jpg") != std::string::npos || cmdline.find(".nef") != std::string::npos || cmdline.find(".orf") != std::string::npos || cmdline.find(".png") != std::string::npos || cmdline.find(".raw") != std::string::npos || cmdline.find(".sr2") != std::string::npos || cmdline.find(".temp") != std::string::npos || cmdline.find(".tif") != std::string::npos || cmdline.find(".tiff") != std::string::npos || cmdline.find(".tmp") != std::string::npos || cmdline.find(".rtf") != std::string::npos || cmdline.find(".txt") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the execution of regsvr32.exe with DLL files masquerading as other files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.003 - Bypass UAC via CMSTP
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%\\cmstp.exe%' OR cmdline LIKE '%CMSTP.EXE%') AND (cmdline LIKE '%/s%' OR cmdline LIKE '%-s%') AND (cmdline LIKE '%/au%' OR cmdline LIKE '%-au%');

bool bypass_UAC_via_CMSTP(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("\\cmstp.exe") != std::string::npos ||
         cmdline.find("CMSTP.EXE") != std::string::npos) &&
        (cmdline.find("/s") != std::string::npos ||
         cmdline.find("-s") != std::string::npos) &&
        (cmdline.find("/au") != std::string::npos ||
         cmdline.find("-au") != std::string::npos))

    {
        std::stringstream ss;
        ss << "Detected UAC Bypass using CMSTP.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.003 - Bypass UAC via CMSTP
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\\DllHost.exe%' AND (cmdline LIKE '%/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}%' OR cmdline LIKE '%/Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}%' OR cmdline LIKE '%/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}%' OR cmdline LIKE '%/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}%' OR cmdline LIKE '%/Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}%');

bool cmstp_UAC_bypass_via_COM_object_access(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\DllHost.exe") != std::string::npos && (cmdline.find("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}") != std::string::npos || cmdline.find("/Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}") != std::string::npos || cmdline.find("/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}") != std::string::npos || cmdline.find("/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") != std::string::npos || cmdline.find("/Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - UAC Bypass Tools Using ComputerDefaults
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell.exe%' AND cmdline LIKE '%New-Item%' AND cmdline LIKE '%New-ItemProperty%' AND cmdline LIKE '%Set-ItemProperty%' AND cmdline LIKE '%C:\\Windows\\System32\\%' AND cmdline LIKE '%C:\\Windows\\System32\\ComputerDefaults.exe%';

bool uac_bypass_tools_using_computerDefaults(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos &&
        cmdline.find("New-Item") != std::string::npos &&
        cmdline.find("New-ItemProperty") != std::string::npos &&
        cmdline.find("Set-ItemProperty") != std::string::npos &&
        cmdline.find("C:\\Windows\\System32\\") != std::string::npos &&
        cmdline.find("C:\\Windows\\System32\\ComputerDefaults.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - UAC Bypass Using DismHost
// SELECT * FROM win_process_events WHERE parent_path LIKE 'C:\\Users\\%' AND parent_path LIKE '\\AppData\\Local\\Temp\\%' AND parent_path LIKE '\\DismHost.exe%';

bool uac_bypass_using_dismHost(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;

    if ((parent_path.find("C:\\Users\\") != std::string::npos &&
         parent_path.find("\\AppData\\Local\\Temp\\") != std::string::npos &&
         parent_path.find("\\DismHost.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Potential Arbitrary Code Execution Via Node.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\node.exe%' AND (cmdline LIKE '% -e%' OR cmdline LIKE '% --eval%' OR (cmdline LIKE '%.exec%' AND cmdline LIKE '%net.socket%' AND cmdline LIKE '%.connect%' AND cmdline LIKE '%child_process%')));

bool potential_arbitrary_code_execution_via_node_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\node.exe") != std::string::npos &&
        (cmdline.find(" -e") != std::string::npos ||
         cmdline.find(" --eval") != std::string::npos ||
         (cmdline.find(".exec") != std::string::npos &&
          cmdline.find("net.socket") != std::string::npos &&
          cmdline.find(".connect") != std::string::npos &&
          cmdline.find("child_process") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Potential Arbitrary Code Execution Via Node.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Node Process Executions
// SELECT * FROM win_process_events WHERE (path LIKE '%\\Adobe Creative Cloud Experience\\libs\\node.exe%' AND cmdline LIKE '%Adobe Creative Cloud Experience\\js%');

bool node_process_executions(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\Adobe Creative Cloud Experience\\libs\\node.exe") != std::string::npos && !(cmdline.find("Adobe Creative Cloud Experience\\js") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Node Process Executions";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool hacktool_wmiexec_default_powershell_command(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc") != std::string::npos)
    {
        std::stringstream ss;
        ss << "The execution of PowerShell with a specific flag sequence that is used by the Wmiexec script detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool hacktool_xordump_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\xordump.exe") != std::string::npos) && cmdline.find("-process lsass.exe") != std::string::npos || cmdline.find("-m comsvcs") != std::string::npos || cmdline.find("-m dbghelp") != std::string::npos || cmdline.find("-m dbgcore") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Suspicious use of XORDump process memory dumping utility detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool potential_homoglyph_attack_using_lookalike_characters(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("\\u0410") != std::string::npos || cmdline.find("\\u0412") != std::string::npos || cmdline.find("\\u0415") != std::string::npos || cmdline.find("\\u041a") != std::string::npos || cmdline.find("\\u041c") != std::string::npos || cmdline.find("\\u041d") != std::string::npos || cmdline.find("\\u041e") != std::string::npos || cmdline.find("\\\u0420") != std::string::npos || cmdline.find("\\u0421") != std::string::npos || cmdline.find("\\u0422") != std::string::npos || cmdline.find("\\u0425") != std::string::npos || cmdline.find("\\u0405") != std::string::npos || cmdline.find("\\u0406") != std::string::npos || cmdline.find("\\u0408") != std::string::npos || cmdline.find("\\u04ae") != std::string::npos || cmdline.find("\\u04c0") != std::string::npos || cmdline.find("\\u050C") != std::string::npos || cmdline.find("\\u051a") != std::string::npos || cmdline.find("\\u051c") != std::string::npos || cmdline.find("\\u0391") != std::string::npos || cmdline.find("\\u0392") != std::string::npos || cmdline.find("\\u0395") != std::string::npos || cmdline.find("\\u0396") != std::string::npos || cmdline.find("\\u0397") != std::string::npos || cmdline.find("\\u0399") != std::string::npos || cmdline.find("\\u039a") != std::string::npos || cmdline.find("\\u039c") != std::string::npos || cmdline.find("\\u039d") != std::string::npos || cmdline.find("\\u039f") != std::string::npos || cmdline.find("\\u03a1") != std::string::npos || cmdline.find("\\u03a4") != std::string::npos || cmdline.find("\\u03a5") != std::string::npos || cmdline.find("\\u03a7") != std::string::npos || cmdline.find("\\u0430") != std::string::npos || cmdline.find("\\u0435") != std::string::npos || cmdline.find("\\u043e") != std::string::npos || cmdline.find("\\u0440") != std::string::npos || cmdline.find("\\u0441") != std::string::npos || cmdline.find("\\u0445") != std::string::npos || cmdline.find("\\u0455") != std::string::npos || cmdline.find("\\u0456") != std::string::npos || cmdline.find("\\u04cf") != std::string::npos || cmdline.find("\\u0458") != std::string::npos || cmdline.find("\\u04bb") != std::string::npos || cmdline.find("\\u0501") != std::string::npos || cmdline.find("\\u051b") != std::string::npos || cmdline.find("\\u051d") != std::string::npos || cmdline.find("\\u03bf") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential Homoglyph Attack detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - Bypass UAC using Event Viewer (PowerShell)
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%powershell.exe%' AND
// cmdline LIKE '%New-Item%' AND
// cmdline LIKE '%Set-ItemProperty%' AND
// cmdline LIKE '%\\software\\classes\\mscfile\\shell\\open\\command%' AND
// cmdline LIKE '%C:\\Windows\\System32\\eventvwr.msc%';

bool bypass_UAC_using_event_viewer_powerShell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos &&
        cmdline.find("New-Item") != std::string::npos &&
        cmdline.find("Set-ItemProperty") != std::string::npos &&
        cmdline.find("\\software\\classes\\mscfile\\shell\\open\\command") != std::string::npos &&
        cmdline.find("C:\\Windows\\System32\\eventvwr.msc") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the pattern of UAC Bypass using Event Viewer via PowerShell.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - Bypass UAC using Event Viewer (cmd)
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%cmd.exe%' AND
// cmdline LIKE '%/C%' AND
// cmdline LIKE '%/d%' AND
// cmdline LIKE '%/f%' AND
// cmdline LIKE '%eventvwr.msc%';

bool bypass_UAC_using_event_viewer_cmd(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("cmd.exe") != std::string::npos &&
         cmdline.find("/C") != std::string::npos &&
         cmdline.find("/d") != std::string::npos &&
         cmdline.find("/f") != std::string::npos &&
         cmdline.find("eventvwr.msc") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the pattern of UAC Bypass using Event Viewer via cmd.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1548.002 - UAC Bypass Using Event Viewer RecentViews
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%\\Event Viewer\\RecentViews%' OR cmdline LIKE '%\\EventV~1\\RecentViews%') AND cmdline LIKE '%>%';

bool uac_bypass_using_event_viewer_recentViews(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("\\Event Viewer\\RecentViews") != std::string::npos || cmdline.find("\\EventV~1\\RecentViews") != std::string::npos) && cmdline.find(">") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the pattern of UAC Bypass using Event Viewer RecentViews.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.010 - Scripting/CommandLine Process Spawned Regsvr32
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND (parent_path LIKE '%\cmd.exe%' OR parent_path LIKE '%\cscript.exe%' OR parent_path LIKE '%\mshta.exe%' OR parent_path LIKE '%\powershell_ise.exe%' OR parent_path LIKE '%\powershell.exe%' OR parent_path LIKE '%\pwsh.exe%' OR parent_path LIKE '%\wscript.exe%') AND  NOT (parent_path LIKE '%C:\Windows\System32\cmd.exe%' AND cmdline LIKE '% /s C:\Windows\System32\RpcProxy\RpcProxy.dll%');

bool scripting_commandline_process_spawned_regsvr32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\regsvr32.exe") != std::string::npos && (parent_path.find("\\cmd.exe") != std::string::npos || parent_path.find("\\cscript.exe") != std::string::npos || parent_path.find("\\mshta.exe") != std::string::npos || parent_path.find("\\powershell_ise.exe") != std::string::npos || parent_path.find("\\powershell.exe") != std::string::npos || parent_path.find("\\pwsh.exe") != std::string::npos || parent_path.find("\\wscript.exe") != std::string::npos) && !(parent_path.find("C:\\Windows\\System32\\cmd.exe") != std::string::npos && cmdline.find(" /s C:\\Windows\\System32\\RpcProxy\\RpcProxy.dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a command line and scripting engines/process spawning a 'regsvr32' instance.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574 - Regsvr32 DLL Execution With Uncommon Extension
// SELECT * FROM win_process_events WHERE path LIKE '%\regsvr32.exe%' AND  NOT (cmdline LIKE '%.ax%' OR cmdline LIKE '%.cpl%' OR cmdline LIKE '%.dll%' OR cmdline LIKE '%.ocx%' OR cmdline LIKE '%.ppl%' OR cmdline LIKE '%.bav%');

bool regsvr32_dll_execution_with_uncommon_extension(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\regsvr32.exe") != std::string::npos && !(cmdline.find(".ax") != std::string::npos || cmdline.find(".cpl") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".ocx") != std::string::npos || cmdline.find(".ppl") != std::string::npos || cmdline.find(".bav") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a 'regsvr32' execution where the DLL doesn't contain a common file extension.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574 - Remote Access Tool - RURAT Execution From Unusual Location
// SELECT * FROM win_process_events WHERE (path LIKE '%\rutserv.exe%' OR path LIKE '%\rfusclient.exe%') AND NOT (path LIKE '%C:\Program Files\Remote Utilities%' OR path LIKE '%C:\Program Files (x86)\Remote Utilities%');

bool remote_access_tool_rurat_execution_from_unusual_location(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if ((path.find("\\rutserv.exe") != std::string::npos || path.find("\\rfusclient.exe") != std::string::npos) && !(path.find("C:\\Program Files\\Remote Utilities") != std::string::npos || path.find("C:\\Program Files(x86)\\Remote Utilities") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of Remote Utilities RAT (RURAT) from an unusual location.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218.008 - Suspicious Driver/DLL Installation Via Odbcconf.EXE
// select * from win_process_events where (cmdline like '%INSTALLDRIVER%' and cmdline like '%.dll%');

bool suspicious_driver_ddl_installation_via_odbccnf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find("INSTALLDRIVER") != std::string::npos && cmdline.find(".dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Suspicious Driver/DLL Installation Via Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - Driver/DLL Installation Via Odbcconf.EXE
// select * from win_process_events where (cmdline like '%INSTALLDRIVER%' and cmdline like '%.dll%');

bool driver_ddl_installation_via_odbccnf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find("INSTALLDRIVER") != std::string::npos && cmdline.find(".dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Driver/DLL Installation Via Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - Odbcconf.EXE Suspicious DLL Location
// select * from win_process_events where
//(cmdline like '%:\\PerfLogs\\%' or
// cmdline like '%:\\ProgramData\\%' or
// cmdline like '%:\\Temp\\%' or
// cmdline like '%:\\User\\Public\\%' or
// cmdline like '%:\\Windows\\Registration\\CRMLog%' or
// cmdline like '%:\\Windows\\System32\\com\\dmp\\%' or
// cmdline like '%:\\Windows\\System32\\FxsTmp\\%' or
// cmdline like '%:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\%' or
// cmdline like '%:\\Windows\\System32\\spool\\drivers\\color\\%' or
// cmdline like '%:\\Windows\\System32\\spool\\PRINTERS\\%' or
// cmdline like '%:\\Windows\\System32\\spool\\SERVERS\\%' or
// cmdline like '%:\\Windows\\System32\\Tasks_Migrated\\%' or
// cmdline like '%:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' or
// cmdline like '%:\\Windows\\SysWOW64\\com\\dmp\\%' or
// cmdline like '%:\\Windows\\SysWOW64\\FxsTmp\\%' or
// cmdline like '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\%' or
// cmdline like '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' or
// cmdline like '%:\\Windows\\Tasks\\%' or
// cmdline like '%:\\Windows\\Temp\\%' or
// cmdline like '%:\\Windows\\Tracing\\%' or
// cmdline like '%\\Appdata\\Local\\Temp\\%' or
// cmdline like '%\\Appdata\\Roaming\\%');

bool odbcconf_exe_suspicious_dll_location(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find(":\\PerfLogs\\") != std::string::npos || cmdline.find(":\\ProgramData\\") != std::string::npos || cmdline.find(":\\Temp\\") != std::string::npos || cmdline.find(":\\User\\Public\\") != std::string::npos || cmdline.find(":\\Windows\\Registration\\CRMLog") != std::string::npos || cmdline.find(":\\Windows\\System32\\com\\dmp\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\FxsTmp\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\spool\\drivers\\color\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\spool\\PRINTERS\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\spool\\SERVERS\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\Tasks_Migrated\\") != std::string::npos || cmdline.find(":\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\") != std::string::npos || cmdline.find(":\\Windows\\SysWOW64\\com\\dmp\\") != std::string::npos || cmdline.find(":\\Windows\\SysWOW64\\FxsTmp\\") != std::string::npos || cmdline.find(":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\") != std::string::npos || cmdline.find(":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\") != std::string::npos || cmdline.find(":\\Windows\\Tasks\\") != std::string::npos || cmdline.find(":\\Windows\\Temp\\") != std::string::npos || cmdline.find(":\\Windows\\Tracing\\") != std::string::npos || cmdline.find("\\Appdata\\Local\\Temp\\") != std::string::npos || cmdline.find("\\Appdata\\Roaming\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Odbcconf.EXE Suspicious DLL Location";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - Potentially Suspicious DLL Registered Via Odbcconf.EXE
// select * from win_process_events where
//(cmdline like '%REGSVR%' and cmdline like '%.dll%');

bool potentially_suspicious_dll_registered_via_odbcconf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find("REGSVR") != std::string::npos && cmdline.find(".dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potentially Suspicious DLL Registered Via Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - New DLL Registered Via Odbcconf.EXE
// select * from win_process_events where
//(cmdline like '%REGSVR%' and cmdline like '%.dll%');

bool new_dll_registered_via_odbcconf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find("REGSVR") != std::string::npos && cmdline.find(".dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "New DLL Registered Via Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - Suspicious Response File Execution Via Odbcconf.EXE
// select * from win_process_events where
//((cmdline like '% -f%' or
// cmdline like '% /f%') and
// cmdline like '%.rsp%' and
// cmdline like '%.exe /E /F "C:\\WINDOWS\\system32\\odbcconf.tmp%');

bool suspicious_response_file_execution_via_odbcconf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find(" -f") != std::string::npos || cmdline.find(" /f") != std::string::npos) && cmdline.find(".rsp") != std::string::npos && cmdline.find(".exe /E /F \"C:\\WINDOWS\\system32\\odbcconf.tmp") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Suspicious Response File Execution Via Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - Response File Execution Via Odbcconf.EXE
// select * from win_process_events where
//((cmdline like '% -f%' or
// cmdline like '% /f%') and
// cmdline like '%.rsp%');

bool response_file_execution_via_odbcconf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\odbcconf.exe") != std::string::npos && (cmdline.find(" -f") != std::string::npos || cmdline.find(" /f") != std::string::npos) && cmdline.find(".rsp") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Response File Execution Via Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.008 - Uncommon Child Process Spawned By Odbcconf.EXE
// select * from win_process_events where
// cmdline like '%\\odbcconf.exe%';

bool uncommon_child_process_spawned_by_odbcconf_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\odbcconf.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Uncommon Child Process Spawned By Odbcconf.EXE";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Potential Arbitrary File Download Using Office Application
// SELECT * FROM win_process_events WHERE (path LIKE '%\\EXCEL.EXE%' OR path LIKE '%\\POWERPNT.EXE%' OR path LIKE '%\\WINWORD.exe%') AND (cmdline LIKE '%http://%' OR cmdline LIKE '%https://%');

bool potential_arbitrary_file_download_using_office_application(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\EXCEL.EXE") != std::string::npos && path.find("\\POWERPNT.EXE") != std::string::npos && path.find("\\WINWORD.exe") != std::string::npos && (cmdline.find("http://") != std::string::npos || cmdline.find("https://") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Arbitrary File Download Using Office Application";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Potentially Suspicious Office Document Executed From Trusted Location
// SELECT * FROM win_process_events WHERE (path LIKE '%\\EXCEL.EXE%' OR path LIKE '%\\POWERPNT.EXE%' OR path LIKE '%\\WINWORD.exe%') AND (parent_path LIKE '%\\explorer.exe%' OR parent_path LIKE '%\\dopus.exe%') AND (cmdline LIKE '%\\AppData\\Roaming\\Microsoft\\Templates%' OR cmdline LIKE '%\\AppData\\Roaming\\Microsoft\\Word\\Startup\\%' OR cmdline LIKE '%\\Microsoft Office\\root\\Templates\\%' OR cmdline LIKE '%\\Microsoft Office\\Templates\\%');

bool potentially_suspicious_office_document_executed_from_trusted_location(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\EXCEL.EXE") != std::string::npos && path.find("\\POWERPNT.EXE") != std::string::npos && path.find("\\WINWORD.exe") != std::string::npos && parent_path.find("\\explorer.exe") != std::string::npos && parent_path.find("\\dopus.exe") != std::string::npos && cmdline.find("\\AppData\\Roaming\\Microsoft\\Templates") != std::string::npos || cmdline.find("\\AppData\\Roaming\\Microsoft\\Word\\Startup\\") != std::string::npos || cmdline.find("\\Microsoft Office\\root\\Templates\\") != std::string::npos || cmdline.find("\\Microsoft Office\\Templates\\") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potentially Suspicious Office Document Executed From Trusted Location";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574 - Renamed AutoHotkey.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%AutoHotkey%') AND NOT (path LIKE '%\AutoHotkey.exe%' OR path LIKE '%\AutoHotkey32.exe%' OR path LIKE '%\AutoHotkey32_UIA.exe%' OR path LIKE '%\AutoHotkey64.exe%' OR path LIKE '%\AutoHotkey64_UIA.exe%' OR path LIKE '%\AutoHotkeyA32.exe%' OR path LIKE '%\AutoHotkeyA32_UIA.exe%' OR path LIKE '%\AutoHotkeyU32.exe%' OR path LIKE '%\AutoHotkeyU32_UIA.exe%' OR path LIKE '%\AutoHotkeyU64.exe%' OR path LIKE '%\\AutoHotkeyU64_UIA.exe%');

bool renamed_autohotkeyexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("AutoHotkey") != std::string::npos) &&
        !(path.find("\\AutoHotkey.exe") != std::string::npos ||
          path.find("\\AutoHotkey32.exe") != std::string::npos ||
          path.find("\\AutoHotkey32_UIA.exe") != std::string::npos ||
          path.find("\\AutoHotkey64.exe") != std::string::npos ||
          path.find("\\AutoHotkey64_UIA.exe") != std::string::npos ||
          path.find("\\AutoHotkeyA32.exe") != std::string::npos ||
          path.find("\\AutoHotkeyA32_UIA.exe") != std::string::npos ||
          path.find("\\AutoHotkeyU32.exe") != std::string::npos ||
          path.find("\\AutoHotkeyU32_UIA.exe") != std::string::npos ||
          path.find("\\AutoHotkeyU64.exe") != std::string::npos ||
          path.find("\\AutoHotkeyU64_UIA.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of a renamed autohotkey.exe binary based on PE metadata fields.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1027 - Renamed AutoIt Execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '% /AutoIt3ExecuteScript%' OR cmdline LIKE '% /ErrorStdOut%') OR (cmdline LIKE '%fdc554b3a8683918d731685855683ddf%' OR cmdline LIKE '%cd30a61b60b3d60cecdb034c8c83c290%' OR cmdline LIKE '%f8a00c72f2d667d2edbb234d0c0ae000%' OR cmdline LIKE '%IMPHASH=FDC554B3A8683918D731685855683DDF%' OR cmdline LIKE '%IMPHASH=CD30A61B60B3D60CECDB034C8C83C290%' OR cmdline LIKE '%IMPHASH=F8A00C72F2D667D2EDBB234D0C0AE000%') OR (cmdline LIKE '%AutoIt3%' OR cmdline LIKE '%AutoIt2%' OR cmdline LIKE '%AutoIt%')) AND NOT (path LIKE '%\AutoIt.exe%' OR path LIKE '%\AutoIt2.exe%' OR path LIKE '%\AutoIt3_x64.exe%' OR path LIKE '%\AutoIt3.exe%');

bool renamed_autoit_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (((cmdline.find(" /AutoIt3ExecuteScript") != std::string::npos || cmdline.find(" /ErrorStdOut") != std::string::npos) || (cmdline.find("fdc554b3a8683918d731685855683ddf") != std::string::npos || cmdline.find("cd30a61b60b3d60cecdb034c8c83c290") != std::string::npos || cmdline.find("f8a00c72f2d667d2edbb234d0c0ae000") != std::string::npos || cmdline.find("IMPHASH=FDC554B3A8683918D731685855683DDF") != std::string::npos || cmdline.find("IMPHASH=CD30A61B60B3D60CECDB034C8C83C290") != std::string::npos || cmdline.find("IMPHASH=F8A00C72F2D667D2EDBB234D0C0AE000") != std::string::npos) || (cmdline.find("AutoIt3") != std::string::npos || cmdline.find("AutoIt2") != std::string::npos || cmdline.find("AutoIt") != std::string::npos)) && !(path.find("\\AutoIt.exe") != std::string::npos || path.find("\\AutoIt2.exe") != std::string::npos || path.find("\\AutoIt3_x64.exe") != std::string::npos || path.find("\\AutoIt3.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed AutoIt2.exe or AutoIt3.exe.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036.003 - Potential Defense Evasion Via Rename Of Highly Relevant Binaries
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%Windows PowerShell%' OR cmdline LIKE '%pwsh%') AND (cmdline LIKE '%certutil%' OR cmdline LIKE '%cmstp%' OR cmdline LIKE '%cscript%' OR cmdline LIKE '%mshta%' OR cmdline LIKE '%msiexec%' OR cmdline LIKE '%powershell_ise%' OR cmdline LIKE '%powershell%' OR cmdline LIKE '%psexec%' OR cmdline LIKE '%psexec%' OR cmdline LIKE '%psexesvc%' OR cmdline LIKE '%pwsh%' OR cmdline LIKE '%reg%' OR cmdline LIKE '%regsvr32%' OR cmdline LIKE '%rundll32%' OR cmdline LIKE '%WerMgr%' OR cmdline LIKE '%wmic%' OR cmdline LIKE '%wscript%')) AND NOT (path LIKE '%\certutil.exe%' OR path LIKE '%\cmstp.exe%' OR path LIKE '%\cscript.exe%' OR path LIKE '%\mshta.exe%' OR path LIKE '%\msiexec.exe%' OR path LIKE '%\powershell_ise.exe%' OR path LIKE '%\powershell.exe%' OR path LIKE '%\psexec64.exe%' OR path LIKE '%\psexec.exe%' OR path LIKE '%\PSEXESVC.exe%' OR path LIKE '%\pwsh.exe%' OR path LIKE '%\reg.exe%' OR path LIKE '%\regsvr32.exe%' OR path LIKE '%\rundll32.exe%' OR path LIKE '%\wermgr.exe%' OR path LIKE '%\wmic.exe%' OR path LIKE '%\wscript.exe%');

bool potential_defense_evasion_via_rename_of_highly_relevant_binaries(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (((cmdline.find("Windows PowerShell") != std::string::npos || cmdline.find("pwsh") != std::string::npos) && (cmdline.find("certutil") != std::string::npos || cmdline.find("cmstp") != std::string::npos || cmdline.find("cscript") != std::string::npos || cmdline.find("mshta") != std::string::npos || cmdline.find("msiexec") != std::string::npos || cmdline.find("powershell_ise") != std::string::npos || cmdline.find("powershell") != std::string::npos || cmdline.find("psexec") != std::string::npos || cmdline.find("psexec") != std::string::npos || cmdline.find("psexesvc") != std::string::npos || cmdline.find("pwsh") != std::string::npos || cmdline.find("reg") != std::string::npos || cmdline.find("regsvr32") != std::string::npos || cmdline.find("rundll32") != std::string::npos || cmdline.find("WerMgr") != std::string::npos || cmdline.find("wmic") != std::string::npos || cmdline.find("wscript") != std::string::npos)) && !(path.find("\\certutil.exe") != std::string::npos || path.find("\\cmstp.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\msiexec.exe") != std::string::npos || path.find("\\powershell_ise.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\psexec64.exe") != std::string::npos || path.find("\\psexec.exe") != std::string::npos || path.find("\\PSEXESVC.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\reg.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\wermgr.exe") != std::string::npos || path.find("\\wmic.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed binary.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// Rule written correct yet getting triggered multiple times
// // T1036.003 - Potential Defense Evasion Via Binary Rename
// // SELECT * FROM win_process_events WHERE (cmdline LIKE '%Cmd%' OR cmdline LIKE '%CONHOST%' OR cmdline LIKE '%7z%' OR cmdline LIKE '%WinRAR%' OR cmdline LIKE '%wevtutil%' OR cmdline LIKE '%net%' OR cmdline LIKE '%net1%' OR cmdline LIKE '%netsh%' OR cmdline LIKE '%InstallUtil%') AND NOT (path LIKE '%\cmd.exe%' OR path LIKE '%\conhost.exe%' OR path LIKE '%\7z.exe%' OR path LIKE '%\WinRAR.exe%' OR path LIKE '%\wevtutil.exe%' OR path LIKE '%\net.exe%' OR path LIKE '%\net1.exe%' OR path LIKE '%\netsh.exe%' OR path LIKE '%\InstallUtil.exe%');

// bool potential_defense_evasion_via_binary_rename(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;
//     std::string path = process_event.entry.path;

//     if ((cmdline.find("Cmd") != std::string::npos || cmdline.find("CONHOST") != std::string::npos || cmdline.find("7z") != std::string::npos || cmdline.find("WinRAR.exe") != std::string::npos || cmdline.find("wevtutil") != std::string::npos || cmdline.find("net.exe") != std::string::npos || cmdline.find("net1.exe") != std::string::npos || cmdline.find("netsh.exe") != std::string::npos || cmdline.find("InstallUtil.exe") != std::string::npos) && !(path.find("\\cmd.exe") != std::string::npos || path.find("\\conhost.exe") != std::string::npos || path.find("\\7z.exe") != std::string::npos || path.find("\\WinRAR.exe") != std::string::npos || path.find("\\wevtutil.exe") != std::string::npos || path.find("\\net.exe") != std   ::string::npos || path.find("\\net1.exe") != std::string::npos || path.find("\\netsh.exe") != std::string::npos || path.find("\\InstallUtil.exe") != std::string::npos))
//     {
//         std::stringstream ss;

//         ss << "Detected the execution of a renamed binary.";
//         rule_event.metadata = ss.str();

//         return true;
//     }

//     return false;
// }

// T1528 - Renamed BrowserCore.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%BrowserCore%') AND NOT (path LIKE '%\BrowserCore.exe%');

bool renamed_browsercoreexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("BrowserCore") != std::string::npos) && !(path.find("\\BrowserCore.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected process creation with a renamed BrowserCore.exe";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036 - Renamed CreateDump Utility Execution
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%FX_VER_INTERNALNAME_STR%') OR (cmdline LIKE '% -u %' AND cmdline LIKE '% -f %' AND cmdline LIKE '%.dmp%') OR (cmdline LIKE '% --full %' AND cmdline LIKE '% --name %' AND cmdline LIKE '%.dmp%')) AND NOT (path LIKE '%\createdump.exe%');

bool renamed_createdump_utility_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (((cmdline.find("FX_VER_INTERNALNAME_STR") != std::string::npos) || (cmdline.find(" -u ") != std::string::npos && cmdline.find(" -f ") != std::string::npos && cmdline.find(".dmp") != std::string::npos) || (cmdline.find(" --full ") != std::string::npos && cmdline.find(" --name ") != std::string::npos && cmdline.find(".dmp") != std::string::npos)) && !(path.find("\\createdump.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036 - Renamed ZOHO Dctask64 Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%6834B1B94E49701D77CCB3C0895E1AFD%') AND NOT (path LIKE '%\dctask64.exe%');

bool renamed_zoho_dctask64_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("6834B1B94E49701D77CCB3C0895E1AFD") != std::string::npos) && !(path.find("\\dctask64.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected a renamed dctask64.exe used for process injection, command execution, process creation.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1055.001 - Renamed Mavinject.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%mavinject32%' OR cmdline LIKE '%mavinject64%') AND NOT (path LIKE '%\mavinject32.exe%' OR path LIKE '%\mavinject64.exe%');

bool renamed_mavinjectexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("mavinject32") != std::string::npos || cmdline.find("mavinject64") != std::string::npos) && !(path.find("\\mavinject32.exe") != std::string::npos || path.find("\\mavinject64.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed version of the 'Mavinject' process.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218 - Renamed MegaSync Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%megasync%') AND NOT (path LIKE '%\megasync.exe%');

bool renamed_megasync_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("megasync") != std::string::npos) && !(path.find("\\megasync.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed MegaSync.exe";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036.003 - Renamed Msdt.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%msdt%') AND NOT (path LIKE '%\msdt.exe%');

bool renamed_msdtexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("msdt") != std::string::npos) && !(path.find("\\msdt.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed 'Msdt.exe' binary";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036.003 - Renamed NetSupport RAT Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%client32%' OR cmdline LIKE '%a9d50692e95b79723f3e76fcf70d023e%' OR cmdline LIKE '%IMPHASH=A9D50692E95B79723F3E76FCF70D023E%') AND NOT (path LIKE '%\client32.exe%');

bool renamed_netsupport_rat_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("client32") != std::string::npos || cmdline.find("a9d50692e95b79723f3e76fcf70d023e") != std::string::npos || cmdline.find("IMPHASH=A9D50692E95B79723F3E76FCF70D023E") != std::string::npos) && !(path.find("\\client32.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed 'client32.exe'";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036.003 - Renamed Office Binary Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Excel%' OR cmdline LIKE '%MSACCESS%' OR cmdline LIKE '%OneNote%' OR cmdline LIKE '%POWERPNT%' OR cmdline LIKE '%WinWord%') AND NOT (path LIKE '%\EXCEL.exe%' OR path LIKE '%\MSACCESS.exe%' OR path LIKE '%\ONENOTE.EXE%' OR path LIKE '%\POWERPNT.EXE%' OR path LIKE '%\WINWORD.exe%');

bool renamed_office_binary_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("Excel") != std::string::npos || cmdline.find("MSACCESS") != std::string::npos || cmdline.find("OneNote") != std::string::npos || cmdline.find("POWERPNT") != std::string::npos || cmdline.find("WinWord") != std::string::npos) && !(path.find("\\EXCEL.exe") != std::string::npos || path.find("\\MSACCESS.exe") != std::string::npos || path.find("\\ONENOTE.EXE") != std::string::npos || path.find("\\POWERPNT.EXE") != std::string::npos || path.find("\\WINWORD.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed office binary";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1202 - Renamed PAExec Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%PAExec%' AND (cmdline LIKE '%11D40A7B7876288F919AB819CC2D9802%' OR cmdline LIKE '%6444f8a34e99b8f7d9647de66aabe516%' OR cmdline LIKE '%dfd6aa3f7b2b1035b76b718f1ddc689f%' OR cmdline LIKE '%1a6cca4d5460b1710a12dea39e4a592c%' OR cmdline LIKE '%IMPHASH=11D40A7B7876288F919AB819CC2D9802%' OR cmdline LIKE '%IMPHASH=6444f8a34e99b8f7d9647de66aabe516%' OR cmdline LIKE '%IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f%' OR cmdline LIKE '%IMPHASH=1a6cca4d5460b1710a12dea39e4a592c%')) AND NOT (path LIKE '%\paexec.exe%' OR path LIKE '%C:\Windows\PAExec-%');

bool renamed_paexec_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("PAExec") != std::string::npos && (cmdline.find("11D40A7B7876288F919AB819CC2D9802") != std::string::npos || cmdline.find("6444f8a34e99b8f7d9647de66aabe516") != std::string::npos || cmdline.find("dfd6aa3f7b2b1035b76b718f1ddc689f") != std::string::npos || cmdline.find("1a6cca4d5460b1710a12dea39e4a592c") != std::string::npos || cmdline.find("IMPHASH=11D40A7B7876288F919AB819CC2D9802") != std::string::npos || cmdline.find("IMPHASH=6444f8a34e99b8f7d9647de66aabe516") != std::string::npos || cmdline.find("IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f") != std::string::npos || cmdline.find("IMPHASH=1a6cca4d5460b1710a12dea39e4a592c") != std::string::npos)) && !(path.find("\\paexec.exe") != std::string::npos || path.find("C:\\Windows\\PAExec-") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of renamed version of PAExec.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036 - Renamed Plink Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Plink%' AND cmdline LIKE '% -l forward%' AND cmdline LIKE '% -P %' AND cmdline LIKE '% -R %') AND NOT (path LIKE '%\plink.exe%');

bool renamed_plink_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("Plink") != std::string::npos && cmdline.find(" -l forward") != std::string::npos && cmdline.find(" -P ") != std::string::npos && cmdline.find(" -R ") != std::string::npos) && !(path.find("\\plink.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed version of the Plink binary";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036 - Renamed Remote Utilities RAT (RURAT) Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%Remote Utilities%') AND NOT (path LIKE '%\rutserv.exe%' OR path LIKE '%\rfusclient.exe%');

bool renamed_remote_utilities_rat_rurat_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("Remote Utilities") != std::string::npos) && !(path.find("\\rutserv.exe") != std::string::npos || path.find("\\rfusclient.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of renamed Remote Utilities (RURAT) via Product PE header field";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1036.003 - Renamed ProcDump Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%procdump%' OR ((cmdline LIKE '% -ma %' OR cmdline LIKE '% /ma %') AND (cmdline LIKE '% -accepteula %' OR cmdline LIKE '% /accepteula %'))) AND NOT (path LIKE '%\procdump.exe%' OR path LIKE '%\procdump64.exe%');

bool renamed_procdump_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("procdump") != std::string::npos || ((cmdline.find(" -ma ") != std::string::npos || cmdline.find(" /ma ") != std::string::npos) && (cmdline.find(" -accepteula ") != std::string::npos || cmdline.find(" /accepteula ") != std::string::npos))) && !(path.find("\\procdump.exe") != std::string::npos || path.find("\\procdump64.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected the execution of a renamed ProcDump executable often used by attackers or malware";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1548.002 - UAC Bypass Using IEInstal - Process
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\ieinstal.exe%' OR path LIKE '%\\AppData\\Local\\Temp\\%') AND path LIKE '%consent.exe%';

bool uac_bypass_using_IEInstal_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\ieinstal.exe") != std::string::npos && path.find("\\AppData\\Local\\Temp\\") != std::string::npos && path.find("consent.exe") && std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected bypass of UAC using IEInstal Process.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1548.002 - UAC Bypass Using MSConfig Token Modification - Process
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\\AppData\\Local\\Temp\\pkgmgr.exe%' AND cmdline LIKE '%C:\\Windows\\system32\\msconfig.exe%';

bool uac_bypass_using_MSConfig_token_modification_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\AppData\\Local\\Temp\\pkgmgr.exe") != std::string::npos && cmdline.find("C:\\Windows\\system32\\msconfig.exe") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the pattern of UAC Bypass using a msconfig GUI hack.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1548.002 - UAC Bypass Using MSConfig Token Modification - Process
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\\pkgmgr.exe%' AND cmdline LIKE '%\\dism.exe%';

bool uac_bypass_using_PkgMgr_and_DISM(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\pkgmgr.exe") != std::string::npos && cmdline.find("\\dism.exe") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the pattern of UAC Bypass using PkgMgr and DISM.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1548.002 - UAC Bypass Using MSConfig Token Modification - Process
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\\AppData\\Local\\Temp\\system32\\winsat.exe%' AND cmdline LIKE '%C:\\Windows\\system32\\winsat.exe%';

bool uac_bypass_abusing_winsat_path_parsing_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\AppData\\Local\\Temp\\system32\\winsat.exe") != std::string::npos && cmdline.find("C:\\Windows\\system32\\winsat.exe") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the pattern of UAC Bypass using a path parsing issue in winsat.exe.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1548.002 - UAC Bypass Using MSConfig Token Modification - Process
// SELECT * FROM win_process_events WHERE cmdline LIKE '%powershell.exe%' AND cmdline LIKE '%C:\\ProgramData\\Package Cache%' AND cmdline LIKE '%\\WindowsSensor.exe%' AND cmdline LIKE '%/uninstall%' AND cmdline LIKE '%/quiet%' AND cmdline LIKE '%-recurse%';

bool uninstall_crowdstrike_falcon_sensor(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("C:\\ProgramData\\Package Cache") != std::string::npos && cmdline.find("\\WindowsSensor.exe") != std::string::npos &&
        cmdline.find("/uninstall") != std::string::npos &&
        cmdline.find("/quiet") != std::string::npos &&
        cmdline.find("-recurse") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the pattern of UAC Bypass using a path parsing issue in winsat.exe.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218 - Verclsid.exe Runs COM Object
// SELECT * FROM win_process_events WHERE path LIKE '%verclsid.exe%' AND cmdline LIKE '%/S%' AND cmdline LIKE '%/C%';

bool verclsid_exe_runs_COM_object(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("verclsid.exe") != std::string::npos && cmdline.find("/S") != std::string::npos && cmdline.find("/C") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected use of verclsid.exe to run COM Object via GUID.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1564.006 - Detect Virtualbox Driver Installation OR Starting Of VMs
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%VBoxRT.dll,RTR3Init%' OR cmdline LIKE '%VBoxC.dll%' OR cmdline LIKE '%VBoxDrv.sys%') AND (cmdline LIKE '%startvm%' OR cmdline LIKE '%controlvm%' OR cmdline LIKE '%modifyvm%');

bool detect_virtualbox_driver_installation_OR_starting_of_VMs(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("VBoxRT.dll,RTR3Init") != std::string::npos ||
         cmdline.find("VBoxC.dll") != std::string::npos ||
         cmdline.find("VBoxDrv.sys") != std::string::npos) &&
        (cmdline.find("startvm") != std::string::npos ||
         cmdline.find("controlvm") != std::string::npos ||
         cmdline.find("modifyvm") != std::string::npos))

    {
        std::stringstream ss;

        ss << "Detected virtual environment (VM) where adversaries can carry out malicious operations";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218 - Verclsid.exe Runs COM Object
// SELECT * FROM win_process_events WHERE path LIKE '%\\VBoxDrvInst.exe%' AND cmdline LIKE '%driver%' AND cmdline LIKE '%executeinf%';

bool suspicious_VBoxDrvInst_exe_parameters(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\VBoxDrvInst.exe") != std::string::npos &&
        cmdline.find("driver") != std::string::npos &&
        cmdline.find("executeinf") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected VBoxDrvInst.exe run with parameters allowing processing INF file, allowing to create values in the registry and install drivers.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218 - VsCode Child Process Anomaly
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\code.exe%' AND (path LIKE '%Invoke-Expressions%' OR path LIKE '%IEX%' OR path LIKE '%Invoke-Command%' OR path LIKE '%ICM%' OR path LIKE '%DownloadString%' OR path LIKE '%rundll32%' OR path LIKE '%regsvr32%' OR path LIKE '%wscript%' OR path LIKE '%cscript%' OR path LIKE '%C:\\Users\\Public\\%' OR path LIKE '%C:\\Windows\\Temp\\%' OR path LIKE '%C:\\Temp\\%'));

bool vsCode_child_process_anomaly(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\code.exe") != std::string::npos &&
        (path.find("Invoke-Expressions") != std::string::npos ||
         path.find("IEX") != std::string::npos ||
         path.find("Invoke-Command") != std::string::npos ||
         path.find("ICM") != std::string::npos ||
         path.find("DownloadString") != std::string::npos ||
         path.find("rundll32") != std::string::npos ||
         path.find("regsvr32") != std::string::npos ||
         path.find("wscript") != std::string::npos ||
         path.find("cscript") != std::string::npos ||
         path.find("C:\\Users\\Public\\") != std::string::npos ||
         path.find("C:\\Windows\\Temp\\") != std::string::npos ||
         path.find("C:\\Temp\\") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected uncommon or suspicious child processes spawning from a VsCode 'code.exe' process. **False Positive may occur when developers use task to compile or execute different types of code.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218 - Potential Binary Proxy Execution Via VSDiagnostics.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%VSDiagnostics.exe%' AND cmdline LIKE '%start%' AND (cmdline LIKE '%/launch:%' OR cmdline LIKE '%-launch:%');

bool potential_binary_proxy_execution_via_VSDiagnostics_EXE(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("VSDiagnostics.exe") != std::string::npos && cmdline.find("start") != std::string::npos && (cmdline.find("/launch:") != std::string::npos || cmdline.find("-launch:") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected execution of 'VSDiagnostics.exe' with the 'start' command in order to launch and proxy arbitrary binaries. **False Positive: Legitimate usage for tracing and diagnostics purposes";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1218 - Suspicious Vsls-Agent Command With AgentExtensionPath Load
// SELECT * FROM win_process_events WHERE path LIKE '%\\vsls-agent.exe%' AND cmdline LIKE '%--agentExtensionPath%' AND cmdline LIKE '%Microsoft.VisualStudio.LiveShare.Agent.%';

bool suspicious_vsls_agent_command_with_agentExtensionPath_load(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\vsls-agent.exe") != std::string::npos && cmdline.find("--agentExtensionPath") != std::string::npos && !(cmdline.find("Microsoft.VisualStudio.LiveShare.Agent.") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}
// T1202 - Potential Arbitrary DLL Load Using Winword
// select * from win_process_events where cmdline like '%/l%' and cmdline like '%.dll%';

bool potential_arbitrary_dll_load_using_winword(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\WINWORD.exe") != std::string::npos && cmdline.find("/l") != std::string::npos && cmdline.find(".dll") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential Arbitrary DLL Load Using Winword";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1140 - Ping Hex IP
// select * from win_process_events where cmdline like '%0x%';

bool ping_hex_ip(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\ping.exe") != std::string::npos && cmdline.find("0x") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Ping Hex IP";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Suspicious Powercfg Execution To Change Lock Screen Timeout
// select * from win_process_events where
// cmdline like '%/setacvalueindex%' and
// cmdline like '%SCHEME_CURRENT%' and
// cmdline like '%SUB_VIDEO%' and
// cmdline like '%VIDEOCONLOCK%' and
// cmdline like '%-change%' and
// cmdline like '%-standby-timeout-%';

bool suspicious_powercfg_execution_to_change_lock_screen_timeout(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powercfg.exe") != std::string::npos &&
        cmdline.find("/setacvalueindex") != std::string::npos &&
        cmdline.find("SCHEME_CURRENT") != std::string::npos &&
        cmdline.find("SUB_VIDEO") != std::string::npos &&
        cmdline.find("VIDEOCONLOCK") != std::string::npos &&
        cmdline.find("-change") != std::string::npos &&
        cmdline.find("-standby-timeout-") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Suspicious Powercfg Execution To Change Lock Screen Timeout";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Potential AMSI Bypass Via .NET Reflection
// select * from win_process_events where
//(cmdline like '%System.Management.Automation.AmsiUtils%' or
// cmdline like '%amsiInitFailed%') and
// cmdline like '%[Ref].Assembly.GetType%' and
// cmdline like '%SetValue($null,$true)%' and
// cmdline like '%NonPublic,Static%';

bool potential_amsi_bypass_via_net_reflection(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("System.Management.Automation.AmsiUtils") != std::string::npos ||
         cmdline.find("amsiInitFailed") != std::string::npos) &&
        cmdline.find("[Ref].Assembly.GetType") != std::string::npos &&
        cmdline.find("SetValue($null,$true)") != std::string::npos &&
        cmdline.find("NonPublic,Static") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential AMSI Bypass Via .NET Reflection";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Potential AMSI Bypass Using NULL Bits
// select * from win_process_events where
// cmdline like '%if(0){{{0}}}\'' -f $(0 -as [char]) +%' or
// cmdline like '%#<NULL>%';

bool potential_amsi_bypass_using_null_bits(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("if(0){{{0}}}' -f $(0 -as [char]) +") != std::string::npos ||
        cmdline.find("#<NULL>") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential AMSI Bypass Using NULL Bits";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1140 - PowerShell Base64 Encoded FromBase64String Cmdlet
// select * from win_process_events where cmdline like '%::FromBase64String%';

bool powershell_base64_encoded_frombase64string_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("::FromBase64String") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell Base64 Encoded FromBase64String Cmdlet";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Powershell Base64 Encoded MpPreference Cmdlet
// select * from win_process_events where
// cmdline like '%Add-MpPreference%' or
// cmdline like '%Set-MpPreference%' or
// cmdline like '%add-MpPreference%' or
// cmdline like '%set-MpPreference%';

bool powershell_base64_encoded_mppreference_cmdlet(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Add-MpPreference ") != std::string::npos ||
        cmdline.find("Set-MpPreference ") != std::string::npos ||
        cmdline.find("add-MpPreference ") != std::string::npos ||
        cmdline.find("set-MpPreference ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Powershell Base64 Encoded MpPreference Cmdlet";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - Potential Process Execution Proxy Via CL_Invocation.ps1
// select * from win_process_events where cmdline like '%SyncInvoke%';

bool potential_process_execution_proxy_via_cl_invocation_ps1(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("SyncInvoke") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential Process Execution Proxy Via CL_Invocation.ps1";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool fake_instance_of_hxtsr(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("hxtsr.exe") != std::string::npos && !(cmdline.find("C:\\program\\windowsapps\\microsoft.windowscommunicationsapps") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Fake instance of Hxtsr.exe detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool use_icacls_to_hide_file_to_everyone(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\icacls.exe") != std::string::npos) && cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("/deny") != std::string::npos && cmdline.find("*S-1-1-0:") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of icacls to deny access for everyone in Users folder detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool disable_windows_iis_http_logging(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\appcmd.exe") != std::string::npos) && cmdline.find("set") != std::string::npos && cmdline.find("config") != std::string::npos && cmdline.find("section:httplogging") != std::string::npos && cmdline.find("dontLog:true") != std::string::npos)
    {
        std::stringstream ss;
        ss << "HTTP logging on a Windows IIS web server detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_iis_url_globalrules_rewrite_via_appcmd(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\appcmd.exe") != std::string::npos) && cmdline.find("set") != std::string::npos && cmdline.find("config") != std::string::npos && cmdline.find("section:system.webServer/rewrite/globalRules") != std::string::npos && cmdline.find("commit:") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of 'appcmd' to create new global URL rewrite rules detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - Assembly Loading Via CL_LoadAssembly.ps1
// select * from win_process_events where
// cmdline like '%LoadAssemblyFromPath%' or
// cmdline like '%LoadAssemblyFromNS%';

bool assembly_loading_via_cl_loadassembly_ps1(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("LoadAssemblyFromPath ") != std::string::npos ||
        cmdline.find("LoadAssemblyFromNS ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Assembly Loading Via CL_LoadAssembly.ps1";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - Potential Script Proxy Execution Via CL_Mutexverifiers.ps1
// select * from win_process_events where
// cmdline like '% -nologo -windowstyle minimized -file %' and
//(cmdline like '%\\AppData\\Local\\Temp\\%' or
// cmdline like '%\\Windows\\Temp\\%');

bool potential_script_proxy_execution_via_cl_mutexverifiers_ps1(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        parent_path.find("\\powershell.exe") != std::string::npos &&
        parent_path.find("\\pwsh.exe") != std::string::npos &&
        cmdline.find(" -nologo -windowstyle minimized -file ") != std::string::npos &&
        (cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos ||
         cmdline.find("\\Windows\\Temp\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Script Proxy Execution Via CL_Mutexverifiers.ps1";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - ConvertTo-SecureString Cmdlet Usage Via CommandLine
// select * from win_process_events where cmdline like '%ConvertTo-SecureString%';

bool convertto_securestring_cmdlet_usage_via_commandline(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        cmdline.find("ConvertTo-SecureString") != std::string::npos)
    {
        std::stringstream ss;
        ss << "ConvertTo-SecureString Cmdlet Usage Via CommandLine";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Potential PowerShell Obfuscation Via Reversed Commands
// select * from win_process_events where
//(cmdline like '% -enc %' or cmdline like '% -EncodedCommand %') and
//(cmdline like '%hctac%' or
// cmdline like '%kaerb%' or
// cmdline like '%dnammoc%' or
// cmdline like '%ekovn%' or
// cmdline like '%eliFd%' or
// cmdline like '%rahc%' or
// cmdline like '%etirw%' or
// cmdline like '%golon%' or
// cmdline like '%tninon%' or
// cmdline like '%eddih%' or
// cmdline like '%tpircs%' or
// cmdline like '%ssecorp%' or
// cmdline like '%llehsrewop%' or
// cmdline like '%esnopser%' or
// cmdline like '%daolnwod%' or
// cmdline like '%tneilCbeW%' or
// cmdline like '%tneilc%' or
// cmdline like '%ptth%' or
// cmdline like '%elifotevas%' or
// cmdline like '%46esab%' or
// cmdline like '%htaPpmeTteG%' or
// cmdline like '%tcejbO%' or
// cmdline like '%maerts%' or
// cmdline like '%hcaerof%' or
// cmdline like '%retupmoc%');

bool potential_powershell_obfuscation_via_reversed_commands(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        (cmdline.find(" -enc ") != std::string::npos ||
         cmdline.find(" -EncodedCommand ") != std::string::npos) &&
        (cmdline.find("hctac") != std::string::npos ||
         cmdline.find("kaerb") != std::string::npos ||
         cmdline.find("dnammoc") != std::string::npos ||
         cmdline.find("ekovn") != std::string::npos ||
         cmdline.find("eliFd") != std::string::npos ||
         cmdline.find("rahc") != std::string::npos ||
         cmdline.find("etirw") != std::string::npos ||
         cmdline.find("golon") != std::string::npos ||
         cmdline.find("tninon") != std::string::npos ||
         cmdline.find("eddih") != std::string::npos ||
         cmdline.find("tpircs") != std::string::npos ||
         cmdline.find("ssecorp") != std::string::npos ||
         cmdline.find("llehsrewop") != std::string::npos ||
         cmdline.find("esnopser") != std::string::npos ||
         cmdline.find("daolnwod") != std::string::npos ||
         cmdline.find("tneilCbeW") != std::string::npos ||
         cmdline.find("tneilc") != std::string::npos ||
         cmdline.find("ptth") != std::string::npos ||
         cmdline.find("elifotevas") != std::string::npos ||
         cmdline.find("46esab") != std::string::npos ||
         cmdline.find("htaPpmeTteG") != std::string::npos ||
         cmdline.find("tcejbO") != std::string::npos ||
         cmdline.find("maerts") != std::string::npos ||
         cmdline.find("hcaerof") != std::string::npos ||
         cmdline.find("retupmoc") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential PowerShell Obfuscation Via Reversed Commands";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Powershell Defender Disable Scan Feature
// select * from win_process_events where
//((cmdline like '%Add-MpPreference%' or
// cmdline like '%Set-MpPreference%') and
//(cmdline like '%DisableRealtimeMonitoring%' or
// cmdline like '%DisableIOAVProtection%' or
// cmdline like '%DisableBehaviorMonitoring%' or
// cmdline like '%DisableBlockAtFirstSeen%') and
//(cmdline like '%$true%' or
// cmdline like '% 1 %') and
//(cmdline like '%DisableRealtimeMonitoring%' or
// cmdline like '%DisableIOAVProtection%' or
// cmdline like '%DisableBehaviorMonitoring%' or
// cmdline like '%DisableBlockAtFirstSeen%' or
// cmdline like '%disablerealtimemonitoring%' or
// cmdline like '%disableioavprotection%' or
// cmdline like '%disablebehaviormonitoring%' or
// cmdline like '%disableblockatfirstseen%'));

bool powershell_defender_disable_scan_feature(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("Add-MpPreference ") != std::string::npos ||
         cmdline.find("Set-MpPreference ") != std::string::npos) &&
        (cmdline.find("DisableRealtimeMonitoring ") != std::string::npos ||
         cmdline.find("DisableIOAVProtection ") != std::string::npos ||
         cmdline.find("DisableBehaviorMonitoring ") != std::string::npos ||
         cmdline.find("DisableBlockAtFirstSeen ") != std::string::npos) &&
        (cmdline.find("$true") != std::string::npos ||
         cmdline.find(" 1 ") != std::string::npos) &&
        (cmdline.find("DisableRealtimeMonitoring ") != std::string::npos ||
         cmdline.find("DisableIOAVProtection ") != std::string::npos ||
         cmdline.find("DisableBehaviorMonitoring ") != std::string::npos ||
         cmdline.find("DisableBlockAtFirstSeen ") != std::string::npos ||
         cmdline.find("disablerealtimemonitoring ") != std::string::npos ||
         cmdline.find("disableioavprotection ") != std::string::npos ||
         cmdline.find("disablebehaviormonitoring ") != std::string::npos ||
         cmdline.find("disableblockatfirstseen ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Powershell Defender Disable Scan Feature";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Powershell Defender Exclusion
// select * from win_process_events where
//((cmdline like '%Add-MpPreference%' or
// cmdline like '%Set-MpPreference%') and
//(cmdline like '% -ExclusionPath%' or
// cmdline like '% -ExclusionExtension%' or
// cmdline like '% -ExclusionProcess%' or
// cmdline like '% -ExclusionIpAddress%'));

bool powershell_defender_exclusion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("Add-MpPreference ") != std::string::npos ||
         cmdline.find("Set-MpPreference ") != std::string::npos) &&
        (cmdline.find(" -ExclusionPath ") != std::string::npos ||
         cmdline.find(" -ExclusionExtension ") != std::string::npos ||
         cmdline.find(" -ExclusionProcess ") != std::string::npos ||
         cmdline.find(" -ExclusionIpAddress ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Powershell Defender Exclusion";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.002 - Renamed Vmnat.EXE Execution
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%vmnat%') AND NOT (path LIKE '%\vmnat.exe%');

bool renamed_vmnatexe_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("vmnat") != std::string::npos) && !(path.find("\\vmnat.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected renamed vmnat.exe or portable version that can be used for DLL side-loading";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1562.001 - Disable Windows Defender AV Security Monitoring
// select * from win_process_events where
//((cmdline like '%-DisableBehaviorMonitoring $true%' or
// cmdline like '%-DisableRuntimeMonitoring $true%') and
//(cmdline like '%stop%' or
// cmdline like '%WinDefend%' or
// cmdline like '%delete%' or
// cmdline like '%config%' or
// cmdline like '%start=disabled%'));

bool disable_windows_defender_av_security_monitoring(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        (cmdline.find("-DisableBehaviorMonitoring $true") != std::string::npos ||
         cmdline.find("-DisableRuntimeMonitoring $true") != std::string::npos) &&
        (cmdline.find("stop") != std::string::npos &&
         cmdline.find("WinDefend") != std::string::npos &&
         cmdline.find("delete") != std::string::npos &&
         cmdline.find("config") != std::string::npos &&
         cmdline.find("start=disabled") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Disable Windows Defender AV Security Monitoring";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562 - Windows Firewall Disabled via PowerShell
// select * from win_process_events where
//((cmdline like '% -All%' or
// cmdline like '%Public%' or
// cmdline like '%Domain%' or
// cmdline like '%Private%') and
//(cmdline like '% -Enabled%' or
// cmdline like '% False%' or
// cmdline like '%Set-NetFirewallProfile%'));

bool windows_firewall_disabled_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        path.find("\\powershell_ise.exe") != std::string::npos &&
        (cmdline.find(" -All") != std::string::npos ||
         cmdline.find("Public") != std::string::npos ||
         cmdline.find("Domain") != std::string::npos ||
         cmdline.find("Private") != std::string::npos) &&
        (cmdline.find(" -Enabled") != std::string::npos &&
         cmdline.find(" False") != std::string::npos &&
         cmdline.find("Set-NetFirewallProfile ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Windows Firewall Disabled via PowerShell";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Disabled IE Security Features
// select * from win_process_events where
//((cmdline like '% -name IEHarden%' or
// cmdline like '% -value 0%' or
// cmdline like '% -name DEPOff%' or
// cmdline like '% -value 1%') and
//(cmdline like '% -name DisableFirstRunCustomize%' or
// cmdline like '% -value 2%'));

bool disabled_ie_security_features(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find(" -name IEHarden") != std::string::npos &&
         cmdline.find(" -value 0") != std::string::npos &&
         cmdline.find(" -name DEPOff") != std::string::npos &&
         cmdline.find(" -value 1") != std::string::npos) &&
        (cmdline.find(" -name DisableFirstRunCustomize") != std::string::npos &&
         cmdline.find(" -value 2") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Disabled IE Security Features";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Potential PowerShell Execution Via DLL
// select * from win_process_events where
//(cmdline like '%Default.GetString%' or
// cmdline like '%FromBase64String%' or
// cmdline like '%Invoke-Expression%' or
// cmdline like '%IEX %' or
// cmdline like '%Invoke-Command%' or
// cmdline like '%DownloadString%' or
// cmdline like '%ICM%');

bool potential_powershell_execution_via_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos &&
            path.find("\\regsvcs.exe") != std::string::npos &&
            path.find("\\InstallUtil.exe") != std::string::npos &&
            path.find("\\regasm.exe") != std::string::npos &&
            cmdline.find("Default.GetString") != std::string::npos ||
        cmdline.find("FromBase64String") != std::string::npos ||
        cmdline.find("Invoke-Expression") != std::string::npos ||
        cmdline.find("IEX ") != std::string::npos ||
        cmdline.find("Invoke-Command") != std::string::npos ||
        cmdline.find("DownloadString") != std::string::npos ||
        cmdline.find("ICM ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential PowerShell Execution Via DLL";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059.001 - Potential PowerShell Downgrade Attack
// select * from win_process_events where
//(cmdline like '% -version 2 %' or
// cmdline like '% -versio 2 %' or
// cmdline like '% -versi 2 %' or
// cmdline like '% -vers 2 %' or
// cmdline like '% -ver 2 %' or
// cmdline like '% -ve 2 %' or
// cmdline like '% -v 2 %');

bool potential_powershell_downgrade_attack(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
            cmdline.find(" -version 2 ") != std::string::npos ||
        cmdline.find(" -versio 2 ") != std::string::npos ||
        cmdline.find(" -versi 2 ") != std::string::npos ||
        cmdline.find(" -vers 2 ") != std::string::npos ||
        cmdline.find(" -ver 2 ") != std::string::npos ||
        cmdline.find(" -ve 2 ") != std::string::npos ||
        cmdline.find(" -v 2 ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential PowerShell Execution Via DLL";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562 - Potential Suspicious Windows Feature Enabled
// select * from win_process_events where
// cmdline like '%Enable-WindowsOptionalFeature%' and
// cmdline like '%-Online%' and
// cmdline like '%-FeatureName%' and
//(cmdline like '%TelnetServer%' or
// cmdline like '%Internet-Explorer-Optional-amd64%' or
// cmdline like '%TFTP%' or
// cmdline like '%SMB1Protocol%' or
// cmdline like '%Client-ProjFS%' or
// cmdline like '%Microsoft-Windows-Subsystem-Linux%');

bool potential_suspicious_windows_feature_enabled(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Enable-WindowsOptionalFeature") != std::string::npos &&
        cmdline.find("-Online") != std::string::npos &&
        cmdline.find("-FeatureName") != std::string::npos &&
        (cmdline.find("TelnetServer") != std::string::npos ||
         cmdline.find("Internet-Explorer-Optional-amd64") != std::string::npos ||
         cmdline.find("TFTP") != std::string::npos ||
         cmdline.find("SMB1Protocol") != std::string::npos ||
         cmdline.find("Client-ProjFS") != std::string::npos ||
         cmdline.find("Microsoft-Windows-Subsystem-Linux") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Suspicious Windows Feature Enabled";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Potential Encoded PowerShell Patterns In CommandLine
// select * from win_process_events where
//(cmdline like '%char%' and
// cmdline like '%join%' and
// cmdline like '%split%' and
//(cmdline like '%ToChar%' or
// cmdline like '%ToString%' or
// cmdline like '%String%') and
//(cmdline like '%ToInt%' or
// cmdline like '%ToDecimal%' or
// cmdline like '%ToByte%' or
// cmdline like '%ToUint%' or
// cmdline like '%ToSingle%' or
// cmdline like '%ToSByte%'));

bool potential_encoded_powershell_patterns_in_commandline(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        cmdline.find("char") != std::string::npos &&
        cmdline.find("join") != std::string::npos &&
        cmdline.find("split") != std::string::npos &&
        (cmdline.find("ToChar") != std::string::npos ||
         cmdline.find("ToString") != std::string::npos ||
         cmdline.find("String") != std::string::npos) &&
        (cmdline.find("ToInt") != std::string::npos ||
         cmdline.find("ToDecimal") != std::string::npos ||
         cmdline.find("ToByte") != std::string::npos ||
         cmdline.find("ToUint") != std::string::npos ||
         cmdline.find("ToSingle") != std::string::npos ||
         cmdline.find("ToSByte") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Encoded PowerShell Patterns In CommandLine";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Suspicious Advpack Call Via Rundll32.EXE
// select * from win_process_events where path like '%\rundll32.exe%' AND cmdline like '%advpack%' AND ((cmdline like '%#+%' AND cmdline like '%12%') OR cmdline like '%#-%');

bool suspicious_advpack_call_via_rundll32exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos && cmdline.find("advpack") != std::string::npos && ((cmdline.find("#+") != std::string::npos && cmdline.find("12") != std::string::npos) || cmdline.find("#-") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of 'rundll32' calling 'advpack.dll' with potential obfuscated ordinal calls";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Call by Ordinal
// select * from win_process_events where path like '%\rundll32.exe%' AND (cmdline like '%,#%' OR cmdline like '%, #%' OR cmdline like '%.dll #%' OR cmdline like '%.ocx #%') AND NOT((cmdline like '%EDGEHTML.dll%' AND cmdline like '%#141%') OR ((parent_path like '%\Msbuild\Current\Bin\%' OR parent_path like '%\VC\Tools\MSVC\%' OR parent_path like '%\Tracker.exe%') AND (cmdline like '%\FileTracker32.dll,#1%' OR cmdline like '%\FileTracker32.dll",#1%' OR cmdline like '%\FileTracker64.dll,#1%' OR cmdline like '%\FileTracker64.dll",#1%')));

bool suspicious_call_by_ordinal(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\rundll32.exe") != std::string::npos && (cmdline.find(",#") != std::string::npos || cmdline.find(", #") != std::string::npos || cmdline.find(".dll #") != std::string::npos || cmdline.find(".ocx #") != std::string::npos) && !((cmdline.find("EDGEHTML.dll") != std::string::npos && cmdline.find("#141") != std::string::npos) || ((parent_path.find("\\Msbuild\\Current\\Bin\\") != std::string::npos || parent_path.find("\\VC\\Tools\\MSVC\\") != std::string::npos || parent_path.find("\\Tracker.exe") != std::string::npos) && (cmdline.find("\\FileTracker32.dll,#1") != std::string::npos || cmdline.find("\\FileTracker32.dll\",#1") != std::string::npos || cmdline.find("\\FileTracker64.dll,#1") != std::string::npos || cmdline.find("\\FileTracker64.dll\",#1") != std::string::npos))))
    {
        std::stringstream ss;
        ss << "Detected suspicious calls of DLLs in rundll32.dll exports by ordinal";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Suspicious Rundll32 Invoking Inline VBScript
// select * from win_process_events where cmdline like '%rundll32.exe%' AND cmdline like '%Execute%' AND cmdline like '%RegRead%' AND cmdline like '%window.close%';

bool suspicious_rundll32_invoking_inline_vbScript(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("rundll32.exe") != std::string::npos && cmdline.find("Execute") != std::string::npos && cmdline.find("RegRead") != std::string::npos && cmdline.find("window.close") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected suspicious process related to rundll32 based on command line that invokes inline VBScript";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Rundll32 InstallScreenSaver Execution
// select * from win_process_events where path like '%rundll32.exe%' AND cmdline like '%InstallScreenSaver%';

bool rundll32_installscreensaver_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("rundll32.exe") != std::string::npos && cmdline.find("InstallScreenSaver") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected an attacker attempting to execute an application as a SCR File using rundll32.exe InstallScreenSaver.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Rundll32 JS RunHTMLApplication Pattern
// select * from win_process_events where (cmdline like '%rundll32%' AND cmdline like '%javascript%' AND cmdline like '%..\..\mshtml,RunHTMLApplication%') OR cmdline like '%;document.write();GetObject("script%';

bool rundll32_js_runhtmlapplication_pattern(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("rundll32") != std::string::npos && cmdline.find("javascript") != std::string::npos && cmdline.find("..\\..\\mshtml,RunHTMLApplication") != std::string::npos) || cmdline.find(";document.write();GetObject(\"script") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected suspicious command line patterns used when rundll32 is used to run JavaScript code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool imagingdevices_unusual_parentchild_processes(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("\\WmiPrvSE.exe") != std::string::npos || cmdline.find("\\svchost.exe") != std::string::npos || cmdline.find("\\dllhost.exe") != std::string::npos || cmdline.find("\\ImagingDevices.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool infdefaultinstallexe_inf_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("InfDefaultInstall.exe") != std::string::npos && cmdline.find(".inf") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of SCT script using scrobj.dll detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_execution_of_installutil_without_log(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("Microsoft.NET\\Framework") != std::string::npos && path.find("\\InstallUtil.exe") != std::string::npos) && cmdline.find("/logfile=") != std::string::npos && cmdline.find("/LogToConsole=false") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use the .NET InstallUtil.exe application in order to execute image without log detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool windows_kernel_debugger_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    if (path.find("\\kd.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of the Windows Kernel Debugger (kd.exe) detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_windows_trace_etw_session_tamper_via_logmanexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\logman.exe") != std::string::npos) && (cmdline.find("stop") != std::string::npos || cmdline.find("delete") != std::string::npos || cmdline.find("Circular Kernel Context Logger") != std::string::npos || cmdline.find("EventLog-") != std::string::npos || cmdline.find("SYSMON TRACE") != std::string::npos || cmdline.find("SysmonDnsEtwSession") != std::string::npos))
    {
        std::stringstream ss;
        ss << "The execution of 'logman' utility in order to disable or delete Windows trace sessions detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool using_appvlp_to_circumvent_asr_file_path_rule(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    std::string cmdline = process_event.entry.cmdline;
    if ((parent_path.find("\\appvlp.exe") != std::string::npos) && path.find("\\msoasb.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "AppVLP detected to circumvent ASR File Path Rule";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool custom_class_execution_via_xwizard(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    // std::regex pattern("\\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\\}");
    // if (std::regex_search(cmdline, pattern)) {
    //     std::stringstream ss;
    //     ss << "The execution of Xwizard tool with specific arguments which utilized to run custom class properties detected .";
    //     rule_event.metadata = ss.str();
    //     return true;
    // }
    // Need to check this part once

    if (path.find("\\xwizard.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "The execution of Xwizard tool with specific arguments which utilized to run custom class properties detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Base64 Encoded PowerShell Command Detected
// select * from win_process_events where cmdline like '%::FromBase64String(%';

bool base64_encoded_powershell_command_detected(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("::FromBase64String(") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Base64 Encoded PowerShell Command Detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_customshellhost_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string cmdline = process_event.entry.cmdline;
    if (parent_path.find("\\CustomShellHost.exe") != std::string::npos && !(cmdline.find("C:\\Windows\\explorer.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "The execution of CustomShellHost binary where the child isn't located in 'C:\\Windows\\explorer.exe' detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool zoho_dctask64_process_injection(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\dctask64.exe") != std::string::npos) && !(cmdline.find("DesktopCentral_Agent\\agent") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Suspicious process injection detected using ZOHO's dctask64.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool lolbin_defaultpackexe_use_as_proxy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("\\defaultpack.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of the 'defaultpack.exe' binary as a proxy to launch other programs detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool devicecredentialdeployment_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    if (path.find("\\DeviceCredentialDeployment.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "The execution of DeviceCredentialDeployment to hide a process from view detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool devtoollauncherexe_executes_specified_binary(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (cmdline.find("LaunchForDeploy") != std::string::npos && path.find("\\devtoolslauncher.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "DevToolLauncher.exe malfunctioning .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool xwizard_dll_sideloading(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    if (path.find("\\xwizard.exe") != std::string::npos && !(path.find("C:\\Windows\\System32\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Execution of Xwizard tool from the non-default directory detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool application_whitelisting_bypass_via_dnxexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    if (path.find("\\dnx.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execute C# code located in the consoleapp folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool process_memory_dump_via_dotnet_dump(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (cmdline.find("collect") != std::string::npos && path.find("\\dotnet-dump.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of 'dotnet-dump' with the 'collect' flag detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_extexport_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (cmdline.find("Extexport.exe") != std::string::npos && path.find("\\Extexport.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Suspicious Extexport execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool abusing_findstr_for_defence_evasion(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\findstr.exe") != std::string::npos) && (cmdline.find("findstr") != std::string::npos) && ((cmdline.find("/v") != std::string::npos || cmdline.find("-v") != std::string::npos) && (cmdline.find("/l") != std::string::npos || cmdline.find("-l") != std::string::npos)) || ((cmdline.find("/s") != std::string::npos || cmdline.find("-s") != std::string::npos) && (cmdline.find("/i") != std::string::npos || cmdline.find("-i") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Abuse of findstr detected ! (For defense evasion)";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool formatcom_filesystem_lolbin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("/fs:") != std::string::npos || cmdline.find("/fs:FAT") != std::string::npos || cmdline.find("/fs:exFAT") != std::string::npos || cmdline.find("/fs:NTFS") != std::string::npos || cmdline.find("/fs:UDF") != std::string::npos || cmdline.find("/fs:ReFS") != std::string::npos)
    {
        std::stringstream ss;
        ss << "The execution of format.com with a suspicious filesystem selection detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Gpscript Execution
// select * from win_process_events where
//     cmdline like '%gpscript%' or
//     cmdline like '%/logon%' or
//     cmdline like '%/startup%' or
//     cmdline like '%C:\\windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc%';

bool gpscript_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("gpscript") != std::string::npos || cmdline.find("/logon") != std::string::npos || cmdline.find("/startup") != std::string::npos || cmdline.find("C:\\windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of the LOLBIN gpscript, which executes logon or startup scripts configured in Group Policy detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Ilasm Lolbin Use Compile C-Sharp
// select * from win_process_events where
//     cmdline like '%ilasm%';

bool ilasm_lolbin_use_compile_c_sharp(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("ilasm") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of Ilasm.exe to compile c# code into dll or exe detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Suspicious Execution of InstallUtil To Download
// select * from win_process_events where
//     cmdline like '%InstallUtil%' or
//     cmdline like '%http://%'
//     or cmdline like '%https://%'
//     or cmdline like '%ftp://%';

bool suspicious_execution_of_installutil_to_download(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("InstallUtil") != std::string::npos || cmdline.find("http://") != std::string::npos || cmdline.find("https://") != std::string::npos || cmdline.find("ftp://") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of .NET InstallUtil.exe application in order to download arbitrary files detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - JSC Convert Javascript To Executable
// select * from win_process_events where
//     cmdline like '%.js%';

bool jsc_convert_javascript_to_executable(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find(".js") != std::string::npos)
    {
        std::stringstream ss;
        ss << "execution of the LOLBIN jsc.exe used by .NET to compile javascript code to .exe or .dll format detected.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Kavremover Dropped Binary LOLBIN Usage
// select * from win_process_events where
//     cmdline like '%run run-cmd%';

bool kavremover_dropped_binary_lolbin_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;
    if (cmdline.find("run run-cmd") != std::string::npos && !(parent_path.find("\\kavremover.exe") != std::string::npos || parent_path.find("\\cleanapi.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) detected.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216.001 - Launch-VsDevShell.PS1 Proxy Execution
// select * from win_process_events where
//     cmdline like '%Launch-VsDevShell.ps1%' or
//     cmdline like '%VsWherePath%'
//     or cmdline like '%VsInstallationPath%';

bool launch_vsdevshellps1_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Launch-VsDevShell.ps1") != std::string::npos || cmdline.find("VsWherePath") != std::string::npos || cmdline.find("VsInstallationPath") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of the 'Launch-VsDevShell.ps1' detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - Potential Manage-bde.wsf Abuse To Proxy Execution
// select * from win_process_events where
//     cmdline like '%manage-bde.wsf%';

bool potential_manage_bdewsf_abuse_to_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("manage-bde.wsf") != std::string::npos || cmdline.find("manage-bde.wsf") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Ppotential abuse of the 'manage-bde.wsf' script as a LOLBIN to proxy execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055.001 - Mavinject Inject DLL Into Running Process
// select * from win_process_events where
//     cmdline like '%/INJECTRUNNING%';

bool mavinject_inject_dll_into_running_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (cmdline.find("/INJECTRUNNING") != std::string::npos && !(parent_path.find("C:\\Windows\\System32\\AppVClient.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Ppotential abuse of the 'manage-bde.wsf' script as a LOLBIN to proxy execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Execute MSDT Via Answer File
// select * from win_process_events where
//     cmdline like '%/af%' or
//     cmdline like '%-af%' or
//     cmdline like '%\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml%';

bool execute_msdt_via_answer_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("/af") != std::string::npos || cmdline.find("-af") != std::string::npos || cmdline.find("\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Ppotential abuse of the 'manage-bde.wsf' script as a LOLBIN to proxy execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Download Arbitrary Files Via MSOHTMED.EXE
// select * from win_process_events where
//     cmdline like '%http://%' or
//     cmdline like '%https://%' or
//     cmdline like '%ftp://%';

bool downlaod_arbitrary_files_via_msohtmedexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("http://") != std::string::npos || cmdline.find("https://") != std::string::npos || cmdline.find("ftp://") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Ppotential abuse of the 'manage-bde.wsf' script as a LOLBIN to proxy execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Arbitrary File Download Via MSPUB.EXE
// select * from win_process_events where
//     cmdline like '%http://%' or
//     cmdline like '%https://%' or
//     cmdline like '%ftp://%';

bool abitrary_file_download_viamspuexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("http://") != std::string::npos || cmdline.find("https://") != std::string::npos || cmdline.find("ftp://") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Ppotential abuse of the 'manage-bde.wsf' script as a LOLBIN to proxy execution detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Ie4uinit Lolbin Use From Invalid Path
// select * from win_process_events where
//     cmdline like '%ie4uinit%';

bool ie4uinit_lolbin_use_from_invalid_path(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("ie4uinit") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories detected.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - OpenWith.exe Executes Specified Binary
// select * from win_process_events where
//     cmdline like '%ie4uinit%';

bool openwitexe_executes_specified_binary(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("ie4uinit") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories detected.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Execute Pcwrun.EXE To Leverage Follina
// select * from win_process_events where
//     cmdline like '%../%';

bool execute_pcwrunexe_to_leverage_follina(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("../") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Indirect command execution via Program Compatibility Assistant 'pcwrun.exe' leveraging the follina (CVE-2022-30190) vulnerability detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Indirect Command Execution By Program Compatibility Wizard
// select * from win_process_events where
//     cmdline like '%pcwrun.exe%';

bool indirect_command_execution_by_program_compatibility_wizard(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("pcwrun.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Indirect command execution via Program Compatibility Assistant 'pcwrun.exe' detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.001 - Code Execution via Pcwutl.dll
// select * from win_process_events where
//     cmdline like '%pcwutl%' and
//     cmdline like '%LaunchApplication%';

bool code_execution_via_pcwutldll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("pcwutl") != std::string::npos && cmdline.find("LaunchApplication") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Launch of executable by calling the LaunchApplication function from pcwutl.dll library detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Download Arbitrary Files Via PresentationHost.exe
// select * from win_process_events where
//     cmdline like '%http://%' or
//     cmdline like '%https://%' or
//     cmdline like '%ftp://%';

bool downlaod_arbitrary_files_via_presentationhostexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("http://") != std::string::npos || cmdline.find("https://") != std::string::npos || cmdline.find("ftp://") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected usage of 'PresentationHost' which is a utility that runs '.xbap' (Browser Applications) files to download arbitrary files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Application Whitelisting Bypass via PresentationHost.exe
// select * from win_process_events where
//     cmdline like '%.xbap%' or
//     cmdline like '%C:\\Windows\\%' or
//     cmdline like '%C:\\Program Files%';

bool application_whitelisting_bypass_via_presentationhostexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find(".xbap") != std::string::npos && (cmdline.find("C:\\Windows\\") != std::string::npos || cmdline.find("C:\\Program Files") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Usage of 'PresentationHost' which is a utility that runs '.xbap' detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - File Download Using ProtocolHandler.exe
// select * from win_process_events where
//     (cmdline like '%"ms-word%' and
//      cmdline like '%.docx"%') or
//     cmdline like '%http%';

bool file_download_using_protocol_handle(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("\"ms-word") != std::string::npos && cmdline.find(".docx\"") != std::string::npos) || cmdline.find("http") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of 'ProtocolHandler' to download files detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216.001 - Pubprn.vbs Proxy Execution
// select * from win_process_events where
//     cmdline like '%\\pubprn.vbs%' and
//     cmdline like '%script:%';

bool pubprnvbs_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("\\pubprn.vbs") != std::string::npos && cmdline.find("script:") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of the 'Pubprn.vbs' Microsoft signed script to execute commands detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 -DLL Execution via Rasautou.exe
// select * from win_process_events where
//     cmdline like '%-d%' and
//     cmdline like '%-p%';

bool dll_execution_via_rasautouexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("-d") != std::string::npos && cmdline.find("-p") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executing the export specified in -p";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - REGISTER_APP.VBS Proxy Execution
// select * from win_process_events where
//     cmdline like '%\\register_app.vbs%' and
//     cmdline like '%-register%';

bool registerappvbs_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("\register_app.vbs") != std::string::npos && cmdline.find("-register") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of a Microsoft signed script 'REGISTER_APP.VBS' to register a VSS/VDS Provider as a COM+ application detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Use of Remote.exe
// select * from win_process_events where
//     cmdline like '%remote%';

bool use_of_remoteexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("remote") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of Remote.exe detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Lolbin Runexehelper Use As Proxy
// select * from win_process_events where
//     cmdline like '%runexehelper%';

bool lolbin_runexehelper_use_as_proxy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("runexehelper") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of the 'runexehelper.exe' as proxy to launch other programs detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1059 - Suspicious runscripthelper.exe
// select * from win_process_events where
//     cmdline like '%surfacecheck%';

bool suspicious_runscripthelperexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("surfacecheck") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of powershell scripts via Runscripthelper.exe detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Use of Scriptrunner.exe
// select * from win_process_events where
//     cmdline like '%-appvscript%';

bool use_of_scriptrunnerexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("-appvscript") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of powershell scripts via Runscripthelper.exe detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.008 - Using SettingSyncHost.exe as LOLBin
// select * from win_process_events where
//     cmdline like '%cmd.exe /c%' and
//     cmdline like '%RoamDiag.cmd%' and
//     cmdline like '%-outputpath%';

bool using_settingsynchostexe_as_lolbin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("cmd.exe /c") != std::string::npos && cmdline.find("RoamDiag.cmd") != std::string::npos && cmdline.find("-outputpath") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects using SettingSyncHost.exe to run hijacked binary";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Use Of The SFTP.EXE Binary As A LOLBIN
// select * from win_process_events where
//     cmdline like '%-D ..%' or
//     cmdline like '%-D C:\\%';

bool use_of_sftpexe_binary_as_lolbin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("-D ..") != std::string::npos || cmdline.find("-D C:\\") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of the 'sftp.exe' binary as a LOLBIN by abusing the '-D' flag detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Sideloading Link.EXE
// select * from win_process_events where
//     cmdline like '%LINK /%';

bool sideloading_linkexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (cmdline.find("LINK /") != std::string::npos && !(path.find("C:\\Program Files\\Microsoft Visual Studio\\") != std::string::npos || path.find("C:\\Program Files (x86)\\Microsoft Visual Studio\\") != std::string::npos ||
                                                         path.find("\"\\VC\\Tools\\MSVC\\\"") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Sideloading detected ! (execution utitilies often found in Visual Studio tools that hardcode the call to the binary 'link.exe'. They can be abused to sideload any binary with the same name)";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - Use of Squirrel.exe

bool use_of_squirrelexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("\\AppData\\Local\\Discord\\Update.exe") != std::string::npos && cmdline.find("--processStart") != std::string::npos && cmdline.find("Discord.exe") != std::string::npos && cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("\\AppData\\Local\\GitHubDesktop\\Update.exe") != std::string::npos && cmdline.find("GitHubDesktop.exe") != std::string::npos && cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("\\AppData\\Local\\Microsoft\\Teams\\Update.exe") != std::string::npos && cmdline.find("Teams.exe") != std::string::npos && cmdline.find("C:\\Users\\") != std::string::npos && cmdline.find("\\AppData\\Local\\yammerdesktop\\Update.exe") != std::string::npos && cmdline.find("Yammer.exe") != std::string::npos) && (cmdline.find("--download") != std::string::npos || cmdline.find("--update") != std::string::npos || cmdline.find("--updateRollback=") != std::string::npos || cmdline.find("http") != std::string::npos || cmdline.find("--processStart") != std::string::npos || cmdline.find("--processStartAndWait") != std::string::npos || cmdline.find("--createShortcut") != std::string::npos || cmdline.find("--createShortcut") != std::string::npos || cmdline.find("--processStartAndWait") != std::string::npos || cmdline.find("--processStart") != std::string::npos || cmdline.find("--createShortcut") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Usage of the 'Squirrel.exe' binary as a LOLBIN detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Lolbin Ssh.exe Use As Proxy
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%PermitLocalCommand%' AND cmdline LIKE '%LocalCommand%') OR cmdline LIKE '%ProxyCommand=%');

bool lolbin_sshexe_use_as_proxy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("C:\\Windows\\System32\\OpenSSH\\sshd.exe") != std::string::npos && path.find("ssh.exe") != std::string::npos && ((cmdline.find("PermitLocalCommand") != std::string::npos && cmdline.find("LocalCommand") != std::string::npos) || cmdline.find("ProxyCommand=") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Usage of the 'ssh.exe' binary as a proxy to launch other programs detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Suspicious Atbroker Execution

bool suspicious_atbroker_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("start") != std::string::npos || cmdline.find("animations") != std::string::npos || cmdline.find("audiodescription") != std::string::npos || cmdline.find("caretbrowsing") != std::string::npos || cmdline.find("caretwidth") != std::string::npos || cmdline.find("colorfiltering") != std::string::npos || cmdline.find("cursorscheme") != std::string::npos || cmdline.find("filterkeys") != std::string::npos || cmdline.find("focusborderheight") != std::string::npos || cmdline.find("focusborderwidth") != std::string::npos || cmdline.find("highcontrast") != std::string::npos || cmdline.find("keyboardcues") != std::string::npos || cmdline.find("keyboardpref") != std::string::npos || cmdline.find("magnifierpane") != std::string::npos || cmdline.find("messageduration") != std::string::npos || cmdline.find("minimumhitradius") != std::string::npos || cmdline.find("mousekeys") != std::string::npos || cmdline.find("Narrator") != std::string::npos || cmdline.find("osk") != std::string::npos || cmdline.find("overlappedcontent") != std::string::npos || cmdline.find("showsounds") != std::string::npos || cmdline.find("soundsentry") != std::string::npos || cmdline.find("stickykeys") != std::string::npos || cmdline.find("togglekeys") != std::string::npos || cmdline.find("windowarranging") != std::string::npos || cmdline.find("windowtracking") != std::string::npos || cmdline.find("windowtrackingtimeout") != std::string::npos || cmdline.find("windowtrackingzorder") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of the 'ssh.exe' binary as a proxy to launch other programs detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Application Whitelisting Bypass via Dxcap.exe
bool application_whitelisting_bypass_via_dxcapexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("\\DXCap.exe") != std::string::npos && cmdline.find("-c") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of Dxcap.exe detected .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_extrac32_alternate_data_stream_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("extrac32.exe") != std::string::npos && cmdline.find(".cab") != std::string::npos)
    // CommandLine|re: ':[^\\]'
    {
        std::stringstream ss;
        ss << "Alert ! Extraction of data from cab file and hide it in an alternate data stream processing";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_diantz_alternate_data_stream_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("diantz.exe") != std::string::npos && cmdline.find(".cab") != std::string::npos)
    // CommandLine|re: ':[^\\]'   - Regular expression also present
    {
        std::stringstream ss;
        ss << "DevToolLauncher.exe malfunctioning .";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.004 - Root Certificate Installed From Susp Locations
// select * from win_process_events where
//(cmdline like '%\\AppData\\Local\\Temp\\%' or
// cmdline like '%:\\Windows\\TEMP\\%' or
// cmdline like '%\\Desktop\\%' or
// cmdline like '%\\Downloads\\%' or
// cmdline like '%\\Perflogs\\%' or
// cmdline like '%:\\Users\\Public\\%') and
// cmdline like '%Import-Certificate%' and
// cmdline like '% -FilePath %' and
// cmdline like '%Cert:\\LocalMachine\\Root%';

bool root_certificate_installed_from_susp_locations(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos ||
         cmdline.find(":\\Windows\\TEMP\\") != std::string::npos ||
         cmdline.find("\\Desktop\\") != std::string::npos ||
         cmdline.find("\\Downloads\\") != std::string::npos ||
         cmdline.find("\\Perflogs\\") != std::string::npos ||
         cmdline.find(":\\Users\\Public\\") != std::string::npos) &&
        cmdline.find("Import-Certificate") != std::string::npos &&
        cmdline.find(" -FilePath ") != std::string::npos &&
        cmdline.find("Cert:\\LocalMachine\\Root") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Root Certificate Installed From Susp Locations";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553 - Suspicious PowerShell Invocations
// SELECT * FROM your_process_events_table
// WHERE (cmdline LIKE '%(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1%'' OR cmdline LIKE '%Write-ChocolateyWarning%')
// AND cmdline LIKE '%-npop%'
// AND cmdline LIKE '% -w%'
// AND cmdline LIKE '%hidden%'
// AND cmdline LIKE '% -c%'
// AND cmdline LIKE '%[Convert]::FromBase64String%'
// AND cmdline LIKE '%-noni%'
// AND cmdline LIKE '%iex%'
// AND cmdline LIKE '%New-Object%'
// AND cmdline LIKE '%-ep%'
// AND cmdline LIKE '%bypass%'
// AND cmdline LIKE '%-Enc%'
// AND cmdline LIKE '%powershell%'
// AND cmdline LIKE '%-nonprofile%'
// AND cmdline LIKE '%-windowstyle%'
// AND cmdline LIKE '%reg%'
// AND cmdline LIKE '%add%'
// AND cmdline LIKE '%\\software\\%'
// AND cmdline LIKE '%new-object%'
// AND cmdline LIKE '%.download%'
// AND cmdline LIKE '%.Download%'
// AND cmdline LIKE '%system.net.webclient%'
// AND cmdline LIKE '%Net.WebClient%';

bool suspicious_powershell_invocations(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1") != std::string::npos ||
         cmdline.find("Write-ChocolateyWarning") != std::string::npos) &&
        cmdline.find("-npop") != std::string::npos &&
        cmdline.find(" -w") != std::string::npos &&
        cmdline.find("hidden") != std::string::npos &&
        cmdline.find(" -c") != std::string::npos &&
        cmdline.find("[Convert]::FromBase64String") != std::string::npos &&
        cmdline.find("-noni") != std::string::npos &&
        cmdline.find("iex") != std::string::npos &&
        cmdline.find("New-Object") != std::string::npos &&
        cmdline.find("-ep") != std::string::npos &&
        cmdline.find("bypass") != std::string::npos &&
        cmdline.find("-Enc") != std::string::npos &&
        cmdline.find("powershell") != std::string::npos &&
        cmdline.find("-nonprofile") != std::string::npos &&
        cmdline.find("-windowstyle") != std::string::npos &&
        cmdline.find("reg") != std::string::npos &&
        cmdline.find("add") != std::string::npos &&
        cmdline.find("\\software\\") != std::string::npos &&
        cmdline.find("new-object") != std::string::npos &&
        cmdline.find(".download") != std::string::npos &&
        cmdline.find(".Download") != std::string::npos &&
        cmdline.find("system.net.webclient") != std::string::npos &&
        cmdline.find("Net.WebClient") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Suspicious PowerShell Invocations";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses
// SELECT * FROM win_process_events WHERE cmdline LIKE '%Invoke-ATHRemoteFXvGPUDisablementCommand%' OR cmdline LIKE '%Invoke-ATHRemoteFXvGPUDisableme%';

bool remotefxvgpudisablement_abuse_via_atomictestharnesses(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Invoke-ATHRemoteFXvGPUDisablementCommand") != std::string::npos && cmdline.find("Invoke-ATHRemoteFXvGPUDisableme") != std::string::npos)
    {
        std::stringstream ss;
        ss << "RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.004 - Run PowerShell Script from ADS
// SELECT * FROM win_process_events WHERE cmdline LIKE '%Get-Content%' AND cmdline LIKE '%-Stream%';

bool run_powershell_script_from_ads(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        parent_path.find("\\powershell.exe") != std::string::npos &&
        parent_path.find("\\pwsh.exe") != std::string::npos &&
        cmdline.find("Get-Content") != std::string::npos && cmdline.find("-Stream") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Run PowerShell Script from ADS";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.004 - Mshtml DLL RunHTMLApplication Abuse
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\..\%' AND cmdline LIKE '%mshtml%' AND cmdline LIKE '%RunHTMLApplication%';

bool mshtml_dll_runhtmlapplication_abuse(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\..\\") != std::string::npos && cmdline.find("mshtml") != std::string::npos && cmdline.find("RunHTMLApplication") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected suspicious command line using the 'mshtml.dll' RunHTMLApplication export to run arbitrary code via different protocol handlers";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Rundll32 Execution Without CommandLine Parameters
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%\rundll32.exe%' OR cmdline LIKE '%\rundll32.exe"%' OR cmdline LIKE '%\rundll32%') AND NOT (parent_path LIKE '%\AppData\Local\%' OR parent_path LIKE '%\Microsoft\Edge\%');

bool rundll32_execution_without_commandline_parameters(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if ((cmdline.find("\\rundll32.exe") != std::string::npos || cmdline.find("\\rundll32.exe\"") != std::string::npos || cmdline.find("\\rundll32") != std::string::npos) && !(parent_path.find("\\AppData\\Local\\") != std::string::npos || parent_path.find("\\Microsoft\\Edge\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious start of rundll32.exe without any parameters";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Potential Obfuscated Ordinal Call Via Rundll32
// SELECT * FROM win_process_events WHERE path LIKE '%\rundll32.exe%' AND (cmdline LIKE '%#+%' OR cmdline LIKE '%#-%');

bool potential_obfuscated_ordinal_call_via_rundll32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos && (cmdline.find("#+") != std::string::npos || cmdline.find("#-") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of 'rundll32' with potential obfuscated ordinal calls";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Rundll32 Spawned Via Explorer.EXE
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\explorer.exe%' AND path LIKE '%\rundll32.exe%' AND NOT (cmdline LIKE '% C:\Windows\System32\%' AND cmdline LIKE '% -localserver 22d8c27b-47a1-48d1-ad08-7da7abd79617%');

bool rundll32_spawned_via_explorerexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\explorer.exe") != std::string::npos && path.find("\\rundll32.exe") != std::string::npos && !(cmdline.find(" C:\\Windows\\System32\\") != std::string::npos && cmdline.find(" -localserver 22d8c27b-47a1-48d1-ad08-7da7abd79617") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of 'rundll32' with a parent process of Explorer.exe.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Process Memory Dump Via Comsvcs.DLL
// SELECT * FROM win_process_events WHERE (path LIKE '%\rundll32.exe%' AND ((cmdline LIKE '%comsvcs%' AND cmdline LIKE '%full%') AND (cmdline LIKE '%#-%' OR cmdline LIKE '%#+%' OR cmdline LIKE '%#24%' OR cmdline LIKE '%24 %' OR cmdline LIKE '%MiniDump%'))) OR ((cmdline LIKE '%24%' AND cmdline LIKE '%comsvcs%' AND cmdline LIKE '%full%') AND (cmdline LIKE '% #%' OR cmdline LIKE '%,#%' OR cmdline LIKE '%, #%'));

bool process_memory_dump_via_comsvcsdll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\rundll32.exe") != std::string::npos && ((cmdline.find("comsvcs") != std::string::npos && cmdline.find("full") != std::string::npos) && (cmdline.find("#-") != std::string::npos || cmdline.find("#+") != std::string::npos || cmdline.find("#24") != std::string::npos || cmdline.find("24 ") != std::string::npos || cmdline.find("MiniDump") != std::string::npos))) || ((cmdline.find("24") != std::string::npos && cmdline.find("comsvcs") != std::string::npos && cmdline.find("full") != std::string::npos) && (cmdline.find(" #") != std::string::npos || cmdline.find(",#") != std::string::npos || cmdline.find(", #") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected a process memory dump via 'comsvcs.dll' using rundll32";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Potential ReflectDebugger Content Execution Via WerFault.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%WerFault%' AND cmdline LIKE '%-pr%';

bool potential_reflectDebugger_content_execution_via_werFault_EXE(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("WerFault") != std::string::npos && cmdline.find("-pr") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of WerFault.exe with '-pr' commandline flag which could be used to store the path to the malware in order to masquerade the execution flow.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Potential ReflectDebugger Content Execution Via WerFault.EXE
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%\\wermgr.exe%' AND (path LIKE '%\\cmd.exe%' OR path LIKE '%\\cscript.exe%' OR path LIKE '%\\ipconfig.exe%' OR path LIKE '%\\mshta.exe%' OR path LIKE '%\\net.exe%' OR path LIKE '%\\net1.exe%' OR path LIKE '%\\netstat.exe%' OR path LIKE '%\\nslookup.exe%' OR path LIKE '%\\powershell_ise.exe%' OR path LIKE '%\\powershell.exe%' OR path LIKE '%\\pwsh.exe%' OR path LIKE '%\\regsvr32.exe%' OR path LIKE '%\\rundll32.exe%' OR path LIKE '%\\systeminfo.exe%' OR path LIKE '%\\whoami.exe%' OR path LIKE '%\\wscript.exe%'));

bool suspicious_child_process_of_wermgr_EXE(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;

    if (parent_path.find("\\wermgr.exe") != std::string::npos &&
        (path.find("\\cmd.exe") != std::string::npos ||
         path.find("\\cscript.exe") != std::string::npos ||
         path.find("\\ipconfig.exe") != std::string::npos ||
         path.find("\\mshta.exe") != std::string::npos ||
         path.find("\\net.exe") != std::string::npos ||
         path.find("\\net1.exe") != std::string::npos ||
         path.find("\\netstat.exe") != std::string::npos ||
         path.find("\\nslookup.exe") != std::string::npos ||
         path.find("\\powershell_ise.exe") != std::string::npos ||
         path.find("\\powershell.exe") != std::string::npos ||
         path.find("\\pwsh.exe") != std::string::npos ||
         path.find("\\regsvr32.exe") != std::string::npos ||
         path.find("\\rundll32.exe") != std::string::npos ||
         path.find("\\systeminfo.exe") != std::string::npos ||
         path.find("\\whoami.exe") != std::string::npos ||
         path.find("\\wscript.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious Windows Error Reporting manager (wermgr.exe) child process.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - PowerShell Set-Acl On Windows Folder
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%Set-Acl%' AND
// cmdline LIKE '%-AclObject%' AND
//(cmdline LIKE '%-Path "C:\\Windows%' OR
// cmdline LIKE '%-Path ''C:\\\\Windows%' OR
// cmdline LIKE '%-Path %windir%' OR
// cmdline LIKE '%-Path $env:windir%') AND
//(cmdline LIKE '%FullControl%' OR
// cmdline LIKE '%Allow%');

bool powershell_set_acl_on_windows_folder(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        cmdline.find("Set-Acl") != std::string::npos &&
        cmdline.find("-AclObject") != std::string::npos &&
        (cmdline.find("-Path \"C:\\Windows") != std::string::npos ||
         cmdline.find("-Path 'C:\\\\Windows") != std::string::npos ||
         cmdline.find("-Path %windir%") != std::string::npos ||
         cmdline.find("-Path $env:windir") != std::string::npos) &&
        (cmdline.find("FullControl") != std::string::npos ||
         cmdline.find("Allow") != std::string::npos))
    {
        std::stringstream ss;
        ss << "PowerShell Set-Acl On Windows Folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - PowerShell Script Change Permission Via Set-Acl
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%Set-Acl%' AND
// cmdline LIKE '%-AclObject%' AND
// cmdline LIKE '%-Path%';

bool powershell_script_change_permission_via_set_acl(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        path.find("\\pwsh.exe") != std::string::npos &&
        cmdline.find("Set-Acl") != std::string::npos &&
        cmdline.find("-AclObject") != std::string::npos &&
        cmdline.find("-Path") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell Script Change Permission Via Set-Acl";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Service StartupType Change Via PowerShell Set-Service
// SELECT * FROM win_process_events WHERE
// cmdline LIKE '%Set-Service%' AND
// cmdline LIKE '%-StartupType%' AND
//(cmdline LIKE '%Disabled%' OR
// cmdline LIKE '%Manual%');

bool service_startuptype_change_via_powershell_set_service(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\powershell.exe") != std::string::npos &&
        cmdline.find("Set-Service") != std::string::npos &&
        cmdline.find("-StartupType") != std::string::npos &&
        (cmdline.find("Disabled") != std::string::npos ||
         cmdline.find("Manual") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Service StartupType Change Via PowerShell Set-Service";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Tamper Windows Defender Remove-MpPreference
// select * from win_process_events where
//(cmdline like '%-ControlledFolderAccessProtectedFolders%' or
// cmdline like '%-AttackSurfaceReductionRules_Ids%' or
// cmdline like '%-AttackSurfaceReductionRules_Actions%' or
// cmdline like '%-CheckForSignaturesBeforeRunningScan%') and
// cmdline like '%Remove-MpPreference%';

bool tamper_windows_defender_remove_mppreference(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("-ControlledFolderAccessProtectedFolders ") != std::string::npos ||
         cmdline.find("-AttackSurfaceReductionRules_Ids ") != std::string::npos ||
         cmdline.find("-AttackSurfaceReductionRules_Actions ") != std::string::npos ||
         cmdline.find("-CheckForSignaturesBeforeRunningScan ") != std::string::npos) &&
        cmdline.find("Remove-MpPreference") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Tamper Windows Defender Remove-MpPreference";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Suspicious Process Start Locations
// select * from win_process_events where (path like '%:\RECYCLER\%' OR path like '%:\SystemVolumeInformation\%') AND (path like '%C:\Windows\Tasks\%' OR path like '%C:\Windows\debug\%' OR path like '%C:\Windows\fonts\%' OR path like '%C:\Windows\help\%' OR path like '%C:\Windows\drivers\%' OR path like '%C:\Windows\addins\%' OR path like '%C:\Windows\cursors\%' OR path like '%C:\Windows\system32\tasks\%');

bool suspicious_process_start_locations(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if ((path.find(":\\RECYCLER\\") != std::string::npos || path.find(":\\SystemVolumeInformation\\") != std::string::npos) && (path.find("C:\\Windows\\Tasks\\") != std::string::npos || path.find("C:\\Windows\\debug\\") != std::string::npos || path.find("C:\\Windows\\fonts\\") != std::string::npos || path.find("C:\\Windows\\help\\") != std::string::npos || path.find("C:\\Windows\\drivers\\") != std::string::npos || path.find("C:\\Windows\\addins\\") != std::string::npos || path.find("C:\\Windows\\cursors\\") != std::string::npos || path.find("C:\\Windows\\system32\\tasks\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious process run from unusual locations";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Rundll32 Script in CommandLine
// select * from win_process_events where cmdline like '%rundll32%' AND (cmdline like '%mshtml,RunHTMLApplication%' OR cmdline like '%mshtml,#135%') AND (cmdline like '%javascript:%' OR cmdline like '%vbscript:%');

bool suspicious_rundll32_script_in_commandline(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("rundll32") != std::string::npos && (cmdline.find("mshtml,RunHTMLApplication") != std::string::npos || cmdline.find("mshtml,#135") != std::string::npos) && (cmdline.find("javascript:") != std::string::npos || cmdline.find("vbscript:") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious process related to rundll32 based on arguments";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Rundll32 Setupapi.dll Activity
// select * from win_process_events where path like '%\runonce.exe%' AND parent_path like '%\rundll32.exe%' AND (cmdline like '%setupapi.dll%' AND cmdline like '%InstallHinfSection%');

bool suspicious_rundll32_setupapidll_activity(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\runonce.exe") != std::string::npos && parent_path.find("\\rundll32.exe") != std::string::npos && (cmdline.find("setupapi.dll") != std::string::npos && cmdline.find("InstallHinfSection") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected use of InstallHinfSection function to obtain persistence via modifying one of Run or RunOnce registry keys, run process or use other DLLs chain calls";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Shell32 DLL Execution in Suspicious Directory
// select * from win_process_events where path like '%\rundll32.exe%' AND (cmdline like '%shell32.dll%' AND cmdline like '%Control_RunDLL%') AND (cmdline like '%\%AppData\%%' OR cmdline like '%\%LocalAppData\%%' OR cmdline like '%\%Temp\%%' OR cmdline like '%\%tmp\%%' OR cmdline like '%\AppData\%' OR cmdline like '%\Temp\%' OR cmdline like '%\Users\Public\%');

bool shell32_dll_execution_in_suspicious_directory(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos && (cmdline.find("shell32.dll") != std::string::npos && cmdline.find("Control_RunDLL") != std::string::npos) && (cmdline.find("%%AppData%") != std::string::npos || cmdline.find("%%LocalAppData%") != std::string::npos || cmdline.find("%Temp%") != std::string::npos || cmdline.find("%tmp%") != std::string::npos || cmdline.find("\\AppData\\") != std::string::npos || cmdline.find("\\Temp\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected shell32.dll executing a DLL in a suspicious directory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - RunDLL32 Spawning Explorer
// select * from win_process_events where parent_path like '%\rundll32.exe%' AND path like '%\explorer.exe%' AND NOT (cmdline like '%\shell32.dll,Control_RunDLL%');

bool rundll32_spawning_explorer(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\rundll32.exe") != std::string::npos && path.find("\\explorer.exe") != std::string::npos && !(cmdline.find("\\shell32.dll,Control_RunDLL") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected RunDLL32.exe spawning explorer.exe as child";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Control Panel DLL Load
// select * from win_process_events where parent_path like '%\System32\control.exe%' AND path like '%\rundll32.exe%' AND NOT (cmdline like '%Shell32.dll%');

bool suspicious_control_panel_dll_load(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\System32\\control.exe") != std::string::npos && path.find("\\rundll32.exe") != std::string::npos && !(cmdline.find("Shell32.dll") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious Rundll32 execution from control.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Rundll32 Execution With Image Extension
// select * from win_process_events where path like '%\rundll32.exe%' AND (cmdline like '%.bmp%' OR cmdline like '%.cr2%' OR cmdline like '%.eps%' OR cmdline like '%.gif%' OR cmdline like '%.ico%' OR cmdline like '%.jpeg%' OR cmdline like '%.jpg%' OR cmdline like '%.nef%' OR cmdline like '%.orf%' OR cmdline like '%.png%' OR cmdline like '%.raw%' OR cmdline like '%.sr2%' OR cmdline like '%.tif%' OR cmdline like '%.tiff%');

bool suspicious_rundll32_execution_with_image_extension(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos && (cmdline.find(".bmp") != std::string::npos || cmdline.find(".cr2") != std::string::npos || cmdline.find(".eps") != std::string::npos || cmdline.find(".gif") != std::string::npos || cmdline.find(".ico") != std::string::npos || cmdline.find(".jpeg") != std::string::npos || cmdline.find(".jpg") != std::string::npos || cmdline.find(".nef") != std::string::npos || cmdline.find(".orf") != std::string::npos || cmdline.find(".png") != std::string::npos || cmdline.find(".raw") != std::string::npos || cmdline.find(".sr2") != std::string::npos || cmdline.find(".tif") != std::string::npos || cmdline.find(".tiff") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the execution of Rundll32.exe with DLL files masquerading as image files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Usage Of ShellExec_RunDLL
// select * from win_process_events where cmdline like '%ShellExec_RunDLL%' AND (cmdline like '%regsvr32%' OR cmdline like '%msiexec%' OR cmdline like '%\Users\Public\%' OR cmdline like '%odbcconf%' OR cmdline like '%\Desktop\%' OR cmdline like '%\Temp\%' OR cmdline like '%Invoke-%' OR cmdline like '%iex%' OR cmdline like '%comspec%');

bool suspicious_usage_of_shellexec_rundll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("ShellExec_RunDLL") != std::string::npos && (cmdline.find("regsvr32") != std::string::npos || cmdline.find("msiexec") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("odbcconf") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("\\Temp\\") != std::string::npos || cmdline.find("Invoke-") != std::string::npos || cmdline.find("iex") != std::string::npos || cmdline.find("comspec") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious usage of the ShellExec_RunDLL function to launch other commands";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - ShimCache Flush
// select * from win_process_events where ((cmdline like '%rundll32%' AND cmdline like '%apphelp.dll%') AND (cmdline like '%ShimFlushCache%' OR cmdline like '%#250%')) OR ((cmdline like '%rundll32%' AND cmdline like '%kernel32.dll%') AND (cmdline like '%BaseFlushAppcompatCache%' OR cmdline like '%#46%'));

bool shimcache_flush(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (((cmdline.find("rundll32") != std::string::npos && cmdline.find("apphelp.dll") != std::string::npos) && (cmdline.find("ShimFlushCache") != std::string::npos || cmdline.find("#250") != std::string::npos)) || ((cmdline.find("rundll32") != std::string::npos && cmdline.find("kernel32.dll") != std::string::npos) && (cmdline.find("BaseFlushAppcompatCache") != std::string::npos || cmdline.find("#46") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected actions that clear the local ShimCache and remove forensic evidence";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious Rundll32 Activity Invoking Sys File
// select * from win_process_events where cmdline like '%rundll32%' AND (cmdline like '%.sys,%' OR cmdline like '%.sys %');

bool suspicious_rundll32_activity_invoking_sys_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("rundll32") != std::string::npos && (cmdline.find(".sys,") != std::string::npos || cmdline.find(".sys ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1021.002 - Rundll32 UNC Path Execution
// select * from win_process_events where path like '%\rundll32.exe%' AND cmdline like '%rundll32%' AND cmdline like '% \\\\%';

bool rundll32_unc_path_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos && cmdline.find("rundll32") != std::string::npos && cmdline.find(" \\\\\\\\") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected rundll32 execution where the DLL is located on a remote location";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1021.002 - Suspicious Workstation Locking via Rundll32
// select * from win_process_events where path like '%\rundll32.exe%' AND parent_path like '%\cmd.exe%' AND cmdline like '%user32.dll,%' AND cmdline like '%LockWorkStation%';

bool suspicious_workstation_locking_via_rundll32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\rundll32.exe") != std::string::npos && parent_path.find("\\cmd.exe") != std::string::npos && cmdline.find("user32.dll,") != std::string::npos && cmdline.find("LockWorkStation") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected a suspicious call to the user32.dll function that locked the user workstation";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1112 - Run Once Task Execution as Configured in Registry
// select * from win_process_events where path like '%\runonce.exe%' AND cmdline like '%/AlternateShellStartup%' AND cmdline like '%/r%';

bool run_once_task_execution_as_configured_in_registry(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\runonce.exe") != std::string::npos && cmdline.find("/AlternateShellStartup") != std::string::npos && cmdline.find("/r") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the execution of Run Once task as configured in the registry";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%format:pretty%' OR cmdline LIKE '%format:"pretty"%' OR cmdline LIKE '%format:"text"%' OR cmdline LIKE '%format:text%') AND (path LIKE '%C:\\Windows\\System32\\%' OR path LIKE '%C:\\Windows\\SysWOW64\\%') AND cmdline LIKE '%winrm%';

bool awl_bypass_with_winrm_vbs_and_malicious_wsmPty_xsl_wsmTxt_xsl(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("format:pretty") != std::string::npos || cmdline.find("format:\"pretty\"") != std::string::npos || cmdline.find("format:\"text\"") != std::string::npos || cmdline.find("format:text") != std::string::npos) && (path.find("C:\\Windows\\System32\\") != std::string::npos || path.find("C:\\Windows\\SysWOW64\\") != std::string::npos) && cmdline.find("winrm") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\cscript.exe%' OR path LIKE '%cscript.exe%') AND (cmdline LIKE '%winrm%' AND cmdline LIKE '%invoke Create wmicimv2/Win32_%' AND cmdline LIKE '%-r:http%');

bool remote_code_execute_via_winrm_vbs(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\cscript.exe") != std::string::npos || path.find("cscript.exe") != std::string::npos) && (cmdline.find("winrm") != std::string::npos && cmdline.find("invoke Create wmicimv2/Win32_") != std::string::npos && cmdline.find("-r:http") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected an attempt to execute code or create service on remote host via winrm.vbs.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1216 - AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
// SELECT * FROM win_process_events WHERE cmdline LIKE '%sc%' AND cmdline LIKE '%stop%' AND cmdline LIKE '%WinDefend%' AND cmdline LIKE '%start=disabled%';

bool tamper_with_windows_defender_using_command_prompt(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("sc") != std::string::npos && cmdline.find("stop") != std::string::npos && cmdline.find("WinDefend") != std::string::npos && cmdline.find("start=disabled") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected an attempt to disable scheduled scanning and other parts of windows defender atp.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Abusing Print Executable
// select * from win_process_events where
// cmdline like '%print%' and
// cmdline like '%print.exe%' and
//(cmdline like '%/D%' or
// cmdline like '%.exe%');

bool abusing_print_executable(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (cmdline.find("print") != std::string::npos && cmdline.find("/D") != std::string::npos && cmdline.find(".exe") != std::string::npos && !(cmdline.find("print.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Abusing Print Executable";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Potential Provlaunch.EXE Binary Proxy Execution Abuse
// select * from win_process_events where
// cmdline like '%:\\PerfLogs\\%' or
// cmdline like '%:\\Temp\\%' or
// cmdline like '%:\\Users\\Public\\%' or
// cmdline like '%\\AppData\\Temp\\%' or
// cmdline like '%\\Windows\\System32\\Tasks\\%' or
// cmdline like '%\\Windows\\Tasks\\%' or
// cmdline like '%\\Windows\\Temp\\%';

bool potential_provlaunch_exe_binary_proxy_execution_abuse(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\provlaunch.exe") != std::string::npos && !(cmdline.find(":\\PerfLogs\\") != std::string::npos ||
                                                                       cmdline.find(":\\Temp\\") != std::string::npos ||
                                                                       cmdline.find(":\\Users\\Public\\") != std::string::npos ||
                                                                       cmdline.find("\\AppData\\Temp\\") != std::string::npos ||
                                                                       cmdline.find("\\Windows\\System32\\Tasks\\") != std::string::npos ||
                                                                       cmdline.find("\\Windows\\Tasks\\") != std::string::npos ||
                                                                       cmdline.find("\\Windows\\Temp\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Provlaunch.EXE Binary Proxy Execution Abuse";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - PUA - CleanWipe Execution
// select * from win_process_events where
// cmdline like '%--uninstall%' and
// cmdline like '%-r%' and
// cmdline like '%/uninstall%' and
// cmdline like '%/enterprise%';

bool pua_cleanwipe_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\SepRemovalToolNative_x64.exe") != std::string::npos &&
        path.find("\\CATClean.exe") != std::string::npos &&
        path.find("\\NetInstaller.exe") != std::string::npos &&
        path.find("\\WFPUnins.exe") != std::string::npos &&
        cmdline.find("--uninstall") != std::string::npos &&
        cmdline.find("-r") != std::string::npos &&
        cmdline.find("/uninstall") != std::string::npos &&
        cmdline.find("/enterprise") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PUA - CleanWipe Execution";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036.003 - PUA - Potential PE Metadata Tamper Using Rcedit
// select * from win_process_events where
// cmdline like '%--set-%' and
//(cmdline like '%OriginalFileName%' or
// cmdline like '%CompanyName%' or
// cmdline like '%FileDescription%' or
// cmdline like '%ProductName%' or
// cmdline like '%ProductVersion%' or
// cmdline like '%LegalCopyright%');

bool pua_potential_pe_metadata_tamper_using_rcedit(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rcedit-x64.exe") != std::string::npos &&
        path.find("\\rcedit-x86.exe") != std::string::npos &&
        cmdline.find("--set-") != std::string::npos &&
        (cmdline.find("OriginalFileName") != std::string::npos ||
         cmdline.find("CompanyName") != std::string::npos ||
         cmdline.find("FileDescription") != std::string::npos ||
         cmdline.find("ProductName") != std::string::npos ||
         cmdline.find("ProductVersion") != std::string::npos ||
         cmdline.find("LegalCopyright") != std::string::npos))
    {
        std::stringstream ss;
        ss << "PUA - Potential PE Metadata Tamper Using Rcedit";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036.005 - Suspicious Scheduled Task Creation via Masqueraded XML File
// SELECT * FROM win_process_events WHERE path LIKE '%\schtasks.exe%' AND (cmdline LIKE '%/create%' OR cmdline LIKE '%-create%') AND (cmdline LIKE '%/xml%' OR cmdline LIKE '%-xml%') AND NOT (cmdline LIKE '%.xml%' OR cmdline LIKE '%System%' OR parent_path LIKE '%\rundll32.exe%' OR (cmdline LIKE '%:\\WINDOWS\\Installer\\MSI%' AND cmdline LIKE '%.tmp,zzzzInvokeManagedCustomActionOutOfProc%')) AND NOT (parent_path LIKE '%:\\ProgramData\\OEM\\UpgradeTool\\CareCenter_*\\BUnzip\\Setup_msi.exe%' OR parent_path LIKE '%:\\Program Files\\Axis Communications\\AXIS Camera Station\\SetupActions.exe%' OR parent_path LIKE '%:\\Program Files\\Axis Communications\\AXIS Device Manager\\AdmSetupActions.exe%' OR parent_path LIKE '%:\\Program Files (x86)\\Zemana\\AntiMalware\\AntiMalware.exe%' OR parent_path LIKE '%:\\Program Files\\Dell\\SupportAssist\pcdrcui.exe%');

bool suspicious_scheduled_task_creation_via_masqueraded_xml_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\schtasks.exe") != std::string::npos && (cmdline.find("/create") != std::string::npos || cmdline.find("-create") != std::string::npos) && (cmdline.find("/xml") != std::string::npos || cmdline.find("-xml") != std::string::npos) && !(cmdline.find(".xml") != std::string::npos || cmdline.find("System") != std::string::npos || parent_path.find("\\rundll32.exe") != std::string::npos || (cmdline.find(":\\WINDOWS\\Installer\\MSI") != std::string::npos && cmdline.find(".tmp,zzzzInvokeManagedCustomActionOutOfProc") != std::string::npos)) && !(parent_path.find(":\\ProgramData\\OEM\\UpgradeTool\\CareCenter_*\\BUnzip\\Setup_msi.exe") != std::string::npos || parent_path.find(":\\Program Files\\Axis Communications\\AXIS Camera Station\\SetupActions.exe") != std::string::npos || parent_path.find(":\\Program Files\\Axis Communications\\AXIS Device Manager\\AdmSetupActions.exe") != std::string::npos || parent_path.find(":\\Program Files (x86)\\Zemana\\AntiMalware\\AntiMalware.exe") != std::string::npos || parent_path.find(":\\Program Files\\Dell\\SupportAssist\\pcdrcui.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the creation of a scheduled task using the '-XML' flag with a file without the '.xml' extension.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Sdiagnhost Calling Suspicious Child Process
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\sdiagnhost.exe%' AND (path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%' OR path LIKE '%\cmd.exe%' OR path LIKE '%\mshta.exe%' OR path LIKE '%\cscript.exe%' OR path LIKE '%\wscript.exe%' OR path LIKE '%\taskkill.exe%' OR path LIKE '%\regsvr32.exe%' OR path LIKE '%\rundll32.exe%' OR path LIKE '%\calc.exe%');

bool sdiagnhost_calling_suspicious_child_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;

    if (parent_path.find("\\sdiagnhost.exe") != std::string::npos && (path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\cmd.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos || path.find("\\taskkill.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\calc.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected sdiagnhost.exe calling a suspicious child process.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Suspicious Splwow64 Without Params
// SELECT * FROM win_process_events WHERE path LIKE '%\splwow64.exe%' AND cmdline LIKE '%splwow64.exe%';

bool suspicious_splwow64_without_params(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\splwow64.exe") != std::string::npos && cmdline.find("splwow64.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected suspicious Splwow64.exe process without any command line parameters.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Execution via stordiag.exe
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\stordiag.exe%' AND (path LIKE '%\schtasks.exe%' OR path LIKE '%\systeminfo.exe%' OR path LIKE '%\fltmc.exe%') AND NOT (parent_path LIKE '%c:\windows\system32\%' OR parent_path LIKE '%c:\windows\syswow64\%');

bool execution_via_stordiagexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;

    if (parent_path.find("\\stordiag.exe") != std::string::npos && (path.find("\\schtasks.exe") != std::string::npos || path.find("\\systeminfo.exe") != std::string::npos || path.find("\\fltmc.exe") != std::string::npos) && !(parent_path.find("c:\\windows\\system32\\") != std::string::npos || parent_path.find("c:\\windows\\syswow64\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the use of stordiag.exe to execute schtasks.exe, systeminfo.exe and fltmc.exe.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Start of NT Virtual DOS Machine
// SELECT * FROM win_process_events WHERE path LIKE '%\ntvdm.exe%' OR path LIKE '%\csrstub.exe%';

bool start_of_nt_virtual_dos_machine(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("\\ntvdm.exe") != std::string::npos || path.find("\\csrstub.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the use of Ntvdm.exe which allows the execution of 16-bit Windows applications on 32-bit Windows operating systems.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Potential Tampering With Security Products Via WMIC
// SELECT * FROM win_process_events WHERE (((cmdline LIKE '%wmic%' AND cmdline LIKE '%product where%' AND cmdline LIKE '%call%' AND cmdline LIKE '%uninstall%' AND cmdline LIKE '%/nointeractive%') OR (cmdline LIKE '%wmic%' AND cmdline LIKE '%caption like%' AND (cmdline LIKE '%call delete%' OR cmdline LIKE '%call terminate%')) OR (cmdline LIKE '%process%' AND cmdline LIKE '%where%' AND cmdline LIKE '%delete%')) AND (cmdline LIKE '%\%carbon\%%' OR cmdline LIKE '%\%cylance\%%' OR cmdline LIKE '%\%endpoint\%%' OR cmdline LIKE '%\%eset\%%' OR cmdline LIKE '%\%malware\%%' OR cmdline LIKE '%\%Sophos\%%' OR cmdline LIKE '%\%symantec\%%' OR cmdline LIKE 'Antivirus%' OR cmdline LIKE 'AVG%' OR cmdline LIKE 'Carbon Black' OR cmdline LIKE 'CarbonBlack%' OR cmdline LIKE 'Cb Defense Sensor 64-bit' OR cmdline LIKE 'Crowdstrike Sensor' OR cmdline LIKE 'Cylance%' OR cmdline LIKE 'Dell Threat Defense' OR cmdline LIKE 'DLP Endpoint' OR cmdline LIKE 'Endpoint Detection' OR cmdline LIKE 'Endpoint Protection' OR cmdline LIKE 'Endpoint Security' OR cmdline LIKE 'Endpoint Sensor' OR cmdline LIKE 'ESET File Security' OR cmdline LIKE 'LogRhythm System Monitor Service' OR cmdline LIKE 'Malwarebytes' OR cmdline LIKE 'McAfee Agent' OR cmdline LIKE 'Microsoft Security Client' OR cmdline LIKE 'Sophos Anti-Virus' OR cmdline LIKE 'Sophos AutoUpdate' OR cmdline LIKE 'Sophos Credential Store' OR cmdline LIKE 'Sophos Management Console' OR cmdline LIKE 'Sophos Management Database' OR cmdline LIKE 'Sophos Management Server' OR cmdline LIKE 'Sophos Remote Management System' OR cmdline LIKE 'Sophos Update Manager' OR cmdline LIKE 'Threat Protection' OR cmdline LIKE 'VirusScan' OR cmdline LIKE 'Webroot SecureAnywhere' OR cmdline LIKE 'Windows Defender'));

bool potential_tampering_with_security_products_via_wmic(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (((cmdline.find("wmic") != std::string::npos && cmdline.find("product where ") != std::string::npos && cmdline.find("call") != std::string::npos && cmdline.find("uninstall") != std::string::npos && cmdline.find("/nointeractive") != std::string::npos) || ((cmdline.find("wmic") != std::string::npos && cmdline.find("caption like ") != std::string::npos) && (cmdline.find("call delete") != std::string::npos || cmdline.find("call terminate") != std::string::npos)) || (cmdline.find("process ") != std::string::npos && cmdline.find("where ") != std::string::npos && cmdline.find("delete ") != std::string::npos)) && (cmdline.find("%%carbon%") != std::string::npos || cmdline.find("%%cylance%") != std::string::npos || cmdline.find("%%endpoint%") != std::string::npos || cmdline.find("%%eset%") != std::string::npos || cmdline.find("%%malware%") != std::string::npos || cmdline.find("%%Sophos%") != std::string::npos || cmdline.find("%%symantec%") != std::string::npos || cmdline.find("Antivirus") != std::string::npos || cmdline.find("AVG ") != std::string::npos || cmdline.find("Carbon Black") != std::string::npos || cmdline.find("CarbonBlack") != std::string::npos || cmdline.find("Cb Defense Sensor 64-bit") != std::string::npos || cmdline.find("Crowdstrike Sensor") != std::string::npos || cmdline.find("Cylance ") != std::string::npos || cmdline.find("Dell Threat Defense") != std::string::npos || cmdline.find("DLP Endpoint") != std::string::npos || cmdline.find("Endpoint Detection") != std::string::npos || cmdline.find("Endpoint Protection") != std::string::npos || cmdline.find("Endpoint Security") != std::string::npos || cmdline.find("Endpoint Sensor") != std::string::npos || cmdline.find("ESET File Security") != std::string::npos || cmdline.find("LogRhythm System Monitor Service") != std::string::npos || cmdline.find("Malwarebytes") != std::string::npos || cmdline.find("McAfee Agent") != std::string::npos || cmdline.find("Microsoft Security Client") != std::string::npos || cmdline.find("Sophos Anti-Virus") != std::string::npos || cmdline.find("Sophos AutoUpdate") != std::string::npos || cmdline.find("Sophos Credential Store") != std::string::npos || cmdline.find("Sophos Management Console") != std::string::npos || cmdline.find("Sophos Management Database") != std::string::npos || cmdline.find("Sophos Management Server") != std::string::npos || cmdline.find("Sophos Remote Management System") != std::string::npos || cmdline.find("Sophos Update Manager") != std::string::npos || cmdline.find("Threat Protection") != std::string::npos || cmdline.find("VirusScan") != std::string::npos || cmdline.find("Webroot SecureAnywhere") != std::string::npos || cmdline.find("Windows Defender") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected uninstallation or termination of security products using the WMIC utility.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1220 - XSL Script Processing
// SELECT * FROM win_process_events WHERE (path LIKE '%\wmic.exe%' AND (cmdline LIKE '%/format%' OR cmdline LIKE '%-format%') AND NOT (cmdline LIKE '%Format:List%' OR cmdline LIKE '%Format:htable%' OR cmdline LIKE '%Format:hform%' OR cmdline LIKE '%Format:table%' OR cmdline LIKE '%Format:mof%' OR cmdline LIKE '%Format:value%' OR cmdline LIKE '%Format:rawxml%' OR cmdline LIKE '%Format:xml%' OR cmdline LIKE '%Format:csv%') OR (path LIKE '%\msxsl.exe%'));

bool xsl_script_processing(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\wmic.exe") != std::string::npos && (cmdline.find("/format") != std::string::npos || cmdline.find("-format") != std::string::npos) && !(cmdline.find("Format:List") != std::string::npos || cmdline.find("Format:htable") != std::string::npos || cmdline.find("Format:hform") != std::string::npos || cmdline.find("Format:table") != std::string::npos || cmdline.find("Format:mof") != std::string::npos || cmdline.find("Format:value") != std::string::npos || cmdline.find("Format:rawxml") != std::string::npos || cmdline.find("Format:xml") != std::string::npos || cmdline.find("Format:csv") != std::string::npos)) || (path.find("\\msxsl.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected adversaries abuse the functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 - Suspicious Windows Defender Registry Key Tampering Via Reg.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\reg.exe%' AND (cmdline LIKE '%SOFTWARE\Microsoft\Windows Defender\%' OR cmdline LIKE '%SOFTWARE\Policies\Microsoft\Windows Defender Security Center%' OR cmdline LIKE '%SOFTWARE\Policies\Microsoft\Windows Defender\%')) AND (((cmdline LIKE '% add %' AND cmdline LIKE '%d 0%') AND (cmdline LIKE '%DisallowExploitProtectionOverride%' OR cmdline LIKE '%EnableControlledFolderAccess%' OR cmdline LIKE '%MpEnablePus%' OR cmdline LIKE '%PUAProtection%' OR cmdline LIKE '%SpynetReporting%' OR cmdline LIKE '%SubmitSamplesConsent%' OR cmdline LIKE '%TamperProtection%')) OR ((cmdline LIKE '% add %' AND cmdline LIKE '%d 1%') AND (cmdline LIKE '%DisableAntiSpyware%' OR cmdline LIKE '%DisableAntiSpywareRealtimeProtection%' OR cmdline LIKE '%DisableAntiVirus%' OR cmdline LIKE '%DisableArchiveScanning%' OR cmdline LIKE '%DisableBehaviorMonitoring%' OR cmdline LIKE '%DisableBlockAtFirstSeen%' OR cmdline LIKE '%DisableConfig%' OR cmdline LIKE '%DisableEnhancedNotifications%' OR cmdline LIKE '%DisableIntrusionPreventionSystem%' OR cmdline LIKE '%DisableIOAVProtection%' OR cmdline LIKE '%DisableOnAccessProtection%' OR cmdline LIKE '%DisablePrivacyMode%' OR cmdline LIKE '%DisableRealtimeMonitoring%' OR cmdline LIKE '%DisableRoutinelyTakingAction%' OR cmdline LIKE '%DisableScanOnRealtimeEnable%' OR cmdline LIKE '%DisableScriptScanning%' OR cmdline LIKE '%Notification_Suppress%' OR cmdline LIKE '%SignatureDisableUpdateOnStartupWithoutEngine%')));

bool suspicious_windows_defender_registry_key_tampering_via_regexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\reg.exe") != std::string::npos && (cmdline.find("SOFTWARE\\Microsoft\\Windows Defender\\") != std::string::npos || cmdline.find("SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center") != std::string::npos || cmdline.find("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\") != std::string::npos) && (((cmdline.find(" add ") != std::string::npos && cmdline.find("d 0") != std::string::npos) && (cmdline.find("DisallowExploitProtectionOverride") != std::string::npos || cmdline.find("EnableControlledFolderAccess") != std::string::npos || cmdline.find("MpEnablePus") != std::string::npos || cmdline.find("PUAProtection") != std::string::npos || cmdline.find("SpynetReporting") != std::string::npos || cmdline.find("SubmitSamplesConsent") != std::string::npos || cmdline.find("TamperProtection") != std::string::npos)) || ((cmdline.find(" add ") != std::string::npos && cmdline.find("d 1") != std::string::npos) && (cmdline.find("DisableAntiSpyware") != std::string::npos || cmdline.find("SignatureDisableUpdateOnStartupWithoutEngine") != std::string::npos || cmdline.find("DisableAntiSpywareRealtimeProtection") != std::string::npos || cmdline.find("DisableAntiVirus") != std::string::npos || cmdline.find("DisableArchiveScanning") != std::string::npos || cmdline.find("DisableBehaviorMonitoring") != std::string::npos || cmdline.find("DisableBlockAtFirstSeen") != std::string::npos || cmdline.find("DisableConfig") != std::string::npos || cmdline.find("DisableEnhancedNotifications") != std::string::npos || cmdline.find("DisableIntrusionPreventionSystem") != std::string::npos || cmdline.find("DisableIOAVProtection") != std::string::npos || cmdline.find("DisableOnAccessProtection") != std::string::npos || cmdline.find("DisablePrivacyMode") != std::string::npos || cmdline.find("DisableRealtimeMonitoring") != std::string::npos || cmdline.find("DisableRoutinelyTakingAction") != std::string::npos || cmdline.find("DisableScanOnRealtimeEnable") != std::string::npos || cmdline.find("DisableScriptScanning") != std::string::npos || cmdline.find("Notification_Suppress") != std::string::npos))))
    {
        std::stringstream ss;
        ss << "Detected the usage of 'reg.exe' to tamper with different Windows Defender registry keys.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.009 - Regasm/Regsvcs Suspicious Execution
// SELECT * FROM win_process_events WHERE (((path LIKE '%\Regsvcs.exe%' OR path LIKE '%\Regasm.exe%') AND (cmdline LIKE '%\Users\Public\%' OR cmdline LIKE '%\AppData\Local\Temp\%' OR cmdline LIKE '%\Desktop\%' OR cmdline LIKE '%\Downloads\%' OR cmdline LIKE '%\PerfLogs\%' OR cmdline LIKE '%\Windows\Temp\%' OR cmdline LIKE '%\Microsoft\Windows\Start Menu\Programs\Startup\%')) OR ((path LIKE '%\Regasm.exe%' OR path LIKE '%\Regsvcs.exe%') AND NOT (cmdline LIKE '%.dll%' AND (cmdline LIKE '%\Regasm.exe"%' OR cmdline LIKE '%\Regasm.exe%' OR cmdline LIKE '%\Regsvcs.exe"%' OR cmdline LIKE '%\Regsvcs.exe%'))));

bool regasm_regsvcs_suspicious_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (((path.find("\\Regsvcs.exe") != std::string::npos || path.find("\\Regasm.exe") != std::string::npos) && (cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\PerfLogs\\") != std::string::npos || cmdline.find("\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") != std::string::npos)) || ((path.find("\\Regasm.exe") != std::string::npos || path.find("\\Regsvcs.exe") != std::string::npos) && !(cmdline.find(".dll") != std::string::npos && (cmdline.find("\\Regasm.exe\"") != std::string::npos || cmdline.find("\\Regasm.exe") != std::string::npos || cmdline.find("\\Regsvcs.exe\"") != std::string::npos || cmdline.find("\\Regsvcs.exe") != std::string::npos))))
    {
        std::stringstream ss;
        ss << "Detected suspicious execution of Regasm/Regsvcs utilities.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// To be checked
// T1218 - Windows Defender Download Activity
bool windows_defender_download_activity(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("url") != std::string::npos && cmdline.find("DownloadFile") != std::string::npos && cmdline.find("MpCmdRun.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detect the use of Windows Defender to download payloads";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool syncappvpublishingserver_execute_arbitrary_powershell_code(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\SyncAppvPublishingServer.exe") != std::string::npos && cmdline.find("\"n; ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects process dump via legitimate sqldumper.exe binary";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool syncappvpublishingserver_vbs_execute_arbitrary_powershell_code(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\SyncAppvPublishingServer.vbs") != std::string::npos && cmdline.find(";") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool potential_dll_injection_or_execution_using_trackerexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;
    if (path.find("\\tracker.exe") != std::string::npos && (cmdline.find("/d") != std::string::npos || cmdline.find("/c") != std::string::npos || cmdline.find("/ERRORREPORT:PROMPT") != std::string::npos) && (parent_path.find("\\Msbuild\\Current\\Bin\\MSBuild.exe") != std::string::npos || parent_path.find("\\Msbuild\\Current\\Bin\\amd64\\MSBuild.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detects potential DLL injection and execution using 'Tracker.exe'";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool use_of_ttdinjectexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    if (path.find("ttdinject.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects the executiob of TTDInject.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool time_travel_debugging_utility_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("\\tttracer.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects usage of Time Travel Debugging Utility.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool lolbin_unregmp2exe_use_as_proxy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\unregmp2.exe") != std::string::npos && cmdline.find(" /HideWMP") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detect usage of the 'unregmp2.exe' binary as a proxy to launch a custom version of 'wmpnscfg.exe'";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool utilityfunctionsps1_proxy_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    // std::string path = process_event.entry.path;
    if (cmdline.find("UtilityFunctions.ps1") != std::string::npos || cmdline.find("RegSnapin ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool visual_basic_command_line_compiler_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    if (parent_path.find("\\vbc.exe") != std::string::npos && path.find("\\cvtres.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detects successful code compilation via Visual Basic Command Line Compiler";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574 - Potential Mpclient.DLL Sideloading Via Defender Binaries
// SELECT * FROM win_process_events WHERE path LIKE '%\\NisSrv.exe%' OR path LIKE '%\\MpCmdRun.exe%';

bool potential_mpclientdll_sideloading_via_defender_binaries(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\NisSrv.exe") != std::string::npos || path.find("\\MpCmdRun.exe") != std::string::npos) && !(path.find("C:\\Program Files (x86)\\Windows Defender\\") != std::string::npos || path.find("C:\\Program Files\\Microsoft Security Client\\") != std::string::npos || path.find("C:\\Program Files\\Windows Defender\\") != std::string::npos ||
                                                                                                                  path.find("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\") != std::string::npos ||
                                                                                                                  path.find("C:\\Windows\\WinSxS\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Mpclient.DLL Sideloading Via Defender Binaries";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Potential Mftrace.EXE Abuse
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\\mftrace.exe%';

bool potential_mftraceexe_abuse(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;

    if (parent_path.find("\\mftrace.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Potential Mftrace.EXE Abuse";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Potential Register_App.Vbs LOLScript Abuse
// SELECT * FROM process_events WHERE (path LIKE '%\\cscript.exe%' OR path LIKE '%\\wscript.exe%') AND cmdline LIKE '%.vbs -register%';

bool potential_register_appvbs_lolscript_abuse(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\cscript.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos) && (cmdline.find(".vbs -register ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Potential Register_App.Vbs LOLScript Abuse";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Proxy Execution via Wuauclt
// SELECT * FROM process_events WHERE path LIKE '%\\wuauclt.exe%' AND (cmdline LIKE '%UpdateDeploymentProvider%' AND cmdline LIKE '%.dll%' AND cmdline LIKE '%RunHandlerComServer%' AND (cmdline LIKE '%/UpdateDeploymentProvider UpdateDeploymentProvider.dll%' OR cmdline LIKE '% wuaueng.dll %'));

bool proxy_execution_via_wuauclt(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\wuauclt.exe") != std::string::npos && (cmdline.find("UpdateDeploymentProvider") != std::string::npos && cmdline.find(".dll") != std::string::npos && cmdline.find("RunHandlerComServer") != std::string::npos && !(cmdline.find("UpdateDeploymentProvider UpdateDeploymentProvider.dll") != std::string::npos || cmdline.find(" wuaueng.dll ") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Proxy Execution via Wuauclt";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Microsoft Workflow Compiler Execution
// SELECT * FROM process_events WHERE path LIKE '%\\Microsoft.Workflow.Compiler.exe%';

bool microsoft_workflow_compiler_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\Microsoft.Workflow.Compiler.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Microsoft Workflow Compiler Execution";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Wlrmdr Lolbin Use as Launcher
// SELECT * FROM process_events WHERE path LIKE '%\\wfc.exe%' AND cmdline LIKE '%-s %' AND cmdline LIKE '%-f %' AND cmdline LIKE '%-t %' AND cmdline LIKE '%-m %' AND cmdline LIKE '%-a %' AND cmdline LIKE '%-u %' AND parent_path LIKE '%\\wlrmdr.exe%';

bool wlrmdr_lolbin_use_as_launcher(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("\\wfc.exe") != std::string::npos && (cmdline.find("-s ") != std::string::npos && cmdline.find("-f ") != std::string::npos && cmdline.find("-t ") != std::string::npos && cmdline.find("-m ") != std::string::npos && cmdline.find("-a ") != std::string::npos && cmdline.find("-u ") != std::string::npos) && (parent_path.find("\\wlrmdr.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Wlrmdr Lolbin Use as Launcher";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Use of Wfc.exe
// SELECT * FROM process_events WHERE path LIKE '%\\wfc.exe%';

bool use_of_wfcexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\wfc.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of Wfc.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Use of VSIISExeLauncher.exe
// SELECT * FROM process_events WHERE path LIKE '%\\VSIISExeLauncher.exe%' AND (cmdline LIKE '% -p %' OR cmdline LIKE '% -a %');

bool use_of_vsiisexelauncherexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\VSIISExeLauncher.exe") != std::string::npos && (cmdline.find(" -p ") != std::string::npos || cmdline.find(" -a ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Use of VSIISExeLauncher.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Use of VisualUiaVerifyNative.exe
// SELECT * FROM process_events WHERE path LIKE '%\\VisualUiaVerifyNative.exe%';

bool use_of_visualuiaverifynativeexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\VisualUiaVerifyNative.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of VisualUiaVerifyNative.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Suspicious AddinUtil.EXE CommandLine Execution
// select * from win_process_events where (cmdline like '%addinutil.exe%' or cmdline like '%AddInUtil.exe%') and (cmdline like '%-AddInRoot:%' and cmdline like '%-PipelineRoot:%') and ((cmdline like '%\\AppData\\Local\\Temp\\%' and cmdline like '%\\Desktop\\%' and cmdline like '%\\Downloads\\%' and cmdline like '%\\Users\\Public\\%' and cmdline like '%\\Windows\\Temp\\%') or (cmdline like '%-AddInRoot:.%' and cmdline like '%-AddInRoot:"."%' and cmdline like '%-PipelineRoot:.%' and cmdline like '%-PipelineRoot:"."%' and cmdline like '%\\AppData\\Local\\Temp\\%' and cmdline like '%\\Desktop\\%' and cmdline like '%\\Downloads\\%' and cmdline like '%\\Users\\Public\\%' and cmdline like '%\\Windows\\Temp\\%'));

bool addinutil_commandline_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if ((path.find("addinutil.exe") != std::string::npos) &&
            (cmdline.find("-AddInRoot:") != std::string::npos || cmdline.find("-PipelineRoot:") != std::string::npos) &&
            (cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos ||
             cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos ||
             cmdline.find("\\Windows\\Temp\\") != std::string::npos) ||
        ((cmdline.find("-AddInRoot:.") != std::string::npos || cmdline.find("-AddInRoot:\".\"") != std::string::npos ||
          cmdline.find("-PipelineRoot:.") != std::string::npos || cmdline.find("-PipelineRoot:\".\"") != std::string::npos) &&
         (cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos ||
          cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos ||
          cmdline.find("\\Windows\\Temp\\") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected suspicious commandline execution by adversary using addinutil.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.001 - Potential Adplus.EXE Abuse
// select * from win_process_events where cmdline like '%adplus.exe%' and cmdline like '% -hang %' and cmdline like '% -pn %' and cmdline like '% -pmn %' and cmdline like '% -p %' and cmdline like '% -po %' and cmdline like '% -c %' and cmdline like '% -sc %';

bool potentital_adplus_abuse(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("adplus.exe") != std::string::npos &&
        cmdline.find(" -hang ") != std::string::npos && cmdline.find(" -pn ") != std::string::npos &&
        cmdline.find(" -pmn ") != std::string::npos && cmdline.find(" -p ") != std::string::npos &&
        cmdline.find(" -po ") != std::string::npos && cmdline.find(" -c ") != std::string::npos &&
        cmdline.find(" -sc ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected potential abuse of the Adplus client";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - AgentExecutor PowerShell Execution
// select * from win_process_events where path like '%AgentExecutor.exe%' and cmdline like '%powershell%' and cmdline like '%remediationScript%';

bool agentexecutor_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("AgentExecutor.exe") != std::string::npos && cmdline.find("powershell") != std::string::npos && cmdline.find("remediationScript") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected powershell execution using AgentExecutor for malicious purposes";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - AspNetCompiler Execution
//  select * from win_process_events where (cmdline like '%C:\\Windows\\Microsoft.NET\\Framework\\%' or cmdline like '%C:\\Windows\\Microsoft.NET\\Framework64\\%') and cmdline like '%aspnet_compiler.exe%';

bool aspnetcompiler_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("C:\\Windows\\Microsoft.NET\\Framework\\") != std::string::npos || cmdline.find("C:\\Windows\\Microsoft.NET\\Framework64\\") != std::string::npos) && cmdline.find("aspnet_compiler.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected aspnet compiler which can be abused to execute C# code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Suspicious Child Process of AspNetCompiler
// select * from win_process_events where path like '%aspnet_compiler.exe%' and (cmdline like '%\\calc.exe%' or cmdline like '%\\notepad.exe%') and (cmdline like '%\\Users\\Public\\%' or cmdline like '%\\AppData\\Local\\Temp\\%' or cmdline like '%\\AppData\\Local\\Roaming\\%' or cmdline like '%:\\Temp\\%' or cmdline like '%:\\Windows\\Temp\\%' or cmdline like '%:\\Windows\\System32\\Tasks\\%' or cmdline like '%:\\Windows\\Tasks\\%');

bool suspicious_child_process_aspnetcompiler(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("aspnet_compiler.exe") != std::string::npos && (cmdline.find("\\calc.exe") != std::string::npos || cmdline.find("\\notepad.exe") != std::string::npos) &&
        (cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos ||
         cmdline.find("\\AppData\\Local\\Roaming\\") != std::string::npos || cmdline.find("\\Temp\\") != std::string::npos ||
         cmdline.find("\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\Windows\\System32\\Tasks\\") != std::string::npos ||
         cmdline.find("\\Windows\\Tasks\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected potentially suspicious child processes of aspnet compiler";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1127 - Potentially Suspicious ASP.NET Compilation Via AspNetCompiler
// select * from win_process_events where (cmdline like '%C:\\Windows\\Microsoft.NET\\Framework\\%' or cmdline like '%C:\\Windows\\Microsoft.NET\\Framework64\\%') and cmdline like '%aspnet_compiler.exe%' and (cmdline like '%\\Users\\Public\\%' or cmdline like '%\\AppData\\Local\\Temp\\%' or cmdline like '%\\AppData\\Local\\Roaming\\%' or cmdline like '%\\Temp\\%' or cmdline like '%\\Windows\\Temp\\%' or cmdline like '%\\Windows\\System32\\Tasks\\%' or cmdline like '%\\Windows\\Tasks\\%');

bool potential_suspicious_compilation_aspnet(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("C:\\Windows\\Microsoft.NET\\Framework\\") != std::string::npos ||
         cmdline.find("C:\\Windows\\Microsoft.NET\\Framework64\\") != std::string::npos) &&
        cmdline.find("aspnet_compiler.exe") != std::string::npos &&
        (cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos ||
         cmdline.find("\\AppData\\Local\\Roaming\\") != std::string::npos || cmdline.find("\\Temp\\") != std::string::npos ||
         cmdline.find("\\Windows\\Temp\\") != std::string::npos || cmdline.find("\\Windows\\System32\\Tasks\\") != std::string::npos ||
         cmdline.find("\\Windows\\Tasks\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "aspnet compiler detected using suspicious paths for compilation";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.001 - Hiding Files with Attrib.exe
// select * from win_process_events where path like '%attrib.exe%' and cmdline like '%+h%';

bool hide_files_attrib(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("attrib.exe") != std::string::npos && cmdline.find("+h") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected usage of attrib.exe to hide files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.001 - Set Files as System Files Using Attrib.EXE
//  select * from win_process_events where path like '%attrib.exe%' and cmdline like '%+s%'

bool set_files_system_files_attrib(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("attrib.exe") != std::string::npos && cmdline.find("+s") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected usage of attrib.exe with s flag to mark files as system files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.001 - Set Suspicious Files as System Files Using Attrib.EXE
// select * from win_process_events where path like '%attrib.exe%' and cmdline like '% +s%' and (cmdline like '%\\Users\\Public\\%' or cmdline like '%\\AppData\\Local\\%' or cmdline like '%\\ProgramData\\%' or cmdline like '%\\Downloads\\%' or cmdline like '%\\Windows\\Temp\\%') and (cmdline like '%.bat%' or cmdline like '%.dll%' or cmdline like '%.exe%' or cmdline like '%.hta%' or cmdline like '%.ps1%' or cmdline like '%.vbe%' or cmdline like '%.vbs%');

bool suspicious_files_system_files_attrib(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("attrib.exe") != std::string::npos &&
        cmdline.find(" +s") != std::string::npos &&
        (cmdline.find("\\Users\\Public\\") != std::string::npos ||
         cmdline.find("\\AppData\\Local\\") != std::string::npos || cmdline.find("\\ProgramData\\") != std::string::npos ||
         cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Windows\\Temp\\") != std::string::npos) &&
        (cmdline.find(".bat") != std::string::npos || cmdline.find(".dll") != std::string::npos ||
         cmdline.find(".exe") != std::string::npos || cmdline.find(".hta") != std::string::npos ||
         cmdline.find(".ps1") != std::string::npos || cmdline.find(".vbe") != std::string::npos ||
         cmdline.find(".vbs") != std::string::npos))
    {
        std::stringstream ss;
        ;
        ss << "Detected usage of attrib.exe with s flag to mark suspicious files as system files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.002 - Audit Policy Tampering Via NT Resource Kit Auditpol
// select * from win_process_events where cmdline like '%/logon:none%' or cmdline like '%/system:none%' or cmdline like '%/sam:none%' or cmdline like '%/privilege:none%' or cmdline like '%/object:none%' or cmdline like '%/process:none%' or cmdline like '%/policy:none%';

bool audit_policy_tampering_via_NT_resource(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("/logon:none") != std::string::npos || cmdline.find("/system:none") != std::string::npos || cmdline.find("/sam:none") != std::string::npos || cmdline.find("/privilege:none") != std::string::npos || cmdline.find("/object:none") != std::string::npos || cmdline.find("/process:none") != std::string::npos || cmdline.find("/policy:none") != std::string::npos)
    {
        std::stringstream ss;
        ss << "NT resource kit might be used to change audit policy configuration to impair detection capability";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.002 - Audit Policy Tampering Via Auditpol
//  select * from win_process_events where cmdline like '%auditpol.exe%' and (cmdline like '%disable%' or cmdline like '%clear%' or cmdline like '%remove%' or cmdline like '%restore%');

bool audit_policy_tampering_auditpol(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("auditpol.exe") != std::string::npos && (cmdline.find("disable") != std::string::npos || cmdline.find("clear") != std::string::npos || cmdline.find("remove") != std::string::npos || cmdline.find("restore") != std::string::npos))
    {
        std::stringstream ss;
        ss << "auditpol binary used to change audit policy for impairing defence";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Indirect Inline Command Execution Via Bash.EXE
// select * from win_process_events where (path like '%\\Windows\\System32\\bash.exe%' or path like '%\\Windows\\SysWOW64\\bash.exe%') and cmdline like '% -c %';

bool indirect_inline_command_execution_bash(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\Windows\\System32\\bash.exe") != std::string::npos || path.find("\\Windows\\SysWOW64\\bash.exe") != std::string::npos) && cmdline.find(" -c ") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected bash launcher with a flag to execute binaries for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Indirect Command Execution From Script File Via Bash.EXE
// select * from win_process_events where (path like '%\\Windows\\System32\\bash.exe%' or path like '%\\Windows\\SysWOW64\\bash.exe%') and (cmdline like '%bash.exe -%' or cmdline like '%bash -%');

bool indirect_command_execution_script_bash(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\Windows\\System32\\bash.exe") != std::string::npos || path.find("\\Windows\\SysWOW64\\bash.exe") != std::string::npos) && (cmdline.find("bash.exe -") != std::string::npos && cmdline.find("bash -") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected bash launcher script to execute binaries for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070 - Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE
// select * from win_process_events where path like '%bcdedit.exe%' and (cmdline like '%delete%' or cmdline like '%deletevalue%' or cmdline like '%import%' or cmdline like '%safeboot%' or cmdline like '%network%');

bool potenital_ransomware_bcdedit(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("bcdedit.exe") != std::string::npos && (cmdline.find("delete") != std::string::npos || cmdline.find("deletevalue") != std::string::npos || cmdline.find("import") != std::string::npos || cmdline.find("safeboot") != std::string::npos || cmdline.find("network") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Unauthorized MBR tampering using bcdedit.exe detected for malicious purpose";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Suspicious Child Process Of BgInfo.EXE
// select * from win_process_events where (parent_path like '%\\bginfo.exe%' or parent_path like '%\\bginfo64.exe%') and ((path like '%\\calc.exe%' or path like '%\\cmd.exe%' or path like '%\\cscript.exe%' or path like '%\\mshta.exe%' or path like '%\\notepad.exe%' or path like '%\\powershell.exe%' or path like '%\\pwsh.exe%' or path like '%\\wscript.exe%') and (path like '%\\AppData\\Local\\%' or path like '%\\AppData\\Roaming\\%' or path like '%\\Users\\Public\\%' or path like '%\\Temp\\%' or path like '%\\Windows\\Temp\\%' or path like '%\\PerfLogs\\%'));

bool suspicious_child_bginfo(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    if ((parent_path.find("\\bginfo.exe") != std::string::npos || parent_path.find("\\bginfo64.exe") != std::string::npos) && ((path.find("\\calc.exe") != std::string::npos || path.find("\\cmd.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\notepad.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos) && (path.find("\\AppData\\Local\\") != std::string::npos || path.find("\\AppData\\Roaming\\") != std::string::npos || path.find("\\Users\\Public\\") != std::string::npos || path.find("\\Temp\\") != std::string::npos || path.find("\\Windows\\Temp\\") != std::string::npos || path.find("\\PerfLogs\\") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected suspicious child processes of BgInfo.exe, could be a potential abuse of the binary to proxy execution via external VBScript";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Uncommon Child Process Of BgInfo.EXE
// select * from win_process_events where parent_path like '%\\bginfo.exe%' or parent_path like '%\\bginfo64.exe%';

bool uncommon_child_bginfo(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("bginfo.exe") != std::string::npos || parent_path.find("bginfo64.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected uncommon child processes of BgInfo.exe, could be a potential abuse of the binary to proxy execution via external VBScript";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - File download via Bitsadmin
// SELECT * FROM win_process_events WHERE (path LIKE '%bitsadmin.exe%' AND (cmdline LIKE '%download%' OR cmdline LIKE '%transfer%' OR cmdline LIKE '%addfile%'));

bool file_download_bitsadmin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("bitsadmin.exe") != std::string::npos && (cmdline.find("addfile") != std::string::npos || cmdline.find("create") != std::string::npos || cmdline.find("transfer") != std::string::npos ) && cmdline.find("http") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of bitsadmin to download file for malicious purpose detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - Suspicious Download From Direct IP Via Bitsadmin
// select * from win_process_events where path like '%bitsadmin.exe%' and cmdline like '% /transfer %' and cmdline like '% /create %' and cmdline like '% /addfile %' and (cmdline like '%://1%' or cmdline like '%://2%' or cmdline like '%://3%' or cmdline like '%://4%' or cmdline like '%://5%' or cmdline like '%://6%' or cmdline like '%://7%' or cmdline like '%://8%' or cmdline like '%://9%');

bool suspicious_download_ip_bitsadmin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("bitsadmin.exe") != std::string::npos && cmdline.find(" /transfer ") != std::string::npos && cmdline.find(" /create ") != std::string::npos && cmdline.find(" /addfile ") != std::string::npos && cmdline.find("://1") != std::string::npos && cmdline.find("://2") != std::string::npos && cmdline.find("://3") != std::string::npos && cmdline.find("://4") != std::string::npos && cmdline.find("://5") != std::string::npos && cmdline.find("://6") != std::string::npos && cmdline.find("://7") != std::string::npos && cmdline.find("://8") != std::string::npos && cmdline.find("://9") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Usage of bitsadmin to download file using a URL that contains an IP for malicious purpose detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - Suspicious Download From File-Sharing Website Via Bitsadmin
// select * from win_process_events where path like '%bitsadmin.exe%' and cmdline like '% /transfer %' and cmdline like '% /create %' and cmdline like '% /addfile %' and (cmdline like '%.githubusercontent.com%' or cmdline like '%anonfiles.com%' or cmdline like '%cdn.discordapp.com%' or cmdline like '%cdn.discordapp.com/attachments/%' or cmdline like '%ddns.net%' or cmdline like '%dl.dropboxusercontent.com%' or cmdline like '%ghostbin.co%' or cmdline like '%gofile.io%' or cmdline like '%hastebin.com%' or cmdline like '%mediafire.com%' or cmdline like '%mega.nz%' or cmdline like '%paste.ee%' or cmdline like '%pastebin.com%' or cmdline like '%pastebin.pl%' or cmdline like '%pastetext.net%' or cmdline like '%privatlab.com%' or cmdline like '%privatlab.net%' or cmdline like '%send.exploit.in%' or cmdline like '%sendspace.com%' or cmdline like '%storage.googleapis.com%' or cmdline like '%storjshare.io%' or cmdline like '%temp.sh%' or cmdline like '%transfer.sh%' or cmdline like '%ufile.io%');

bool suspicious_download_file_sharing_bitsadmin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (path.find("bitsadmin.exe") != std::string::npos && cmdline.find(" /transfer ") != std::string::npos && cmdline.find(" /create ") != std::string::npos && cmdline.find(" /addfile ") != std::string::npos && (cmdline.find(".githubusercontent.com") != std::string::npos || cmdline.find("anonfiles.com") != std::string::npos || cmdline.find("cdn.discordapp.com") != std::string::npos || cmdline.find("cdn.discordapp.com/attachments/") != std::string::npos || cmdline.find("ddns.net") != std::string::npos || cmdline.find("dl.dropboxusercontent.com") != std::string::npos || cmdline.find("ghostbin.co") != std::string::npos || cmdline.find("gofile.io") != std::string::npos || cmdline.find("hastebin.com") != std::string::npos || cmdline.find("mediafire.com") != std::string::npos || cmdline.find("mega.nz") != std::string::npos || cmdline.find("paste.ee") != std::string::npos || cmdline.find("pastebin.com") != std::string::npos || cmdline.find("pastebin.pl") != std::string::npos || cmdline.find("pastetext.net") != std::string::npos || cmdline.find("privatlab.com") != std::string::npos || cmdline.find("privatlab.net") != std::string::npos || cmdline.find("send.exploit.in") != std::string::npos || cmdline.find("sendspace.com") != std::string::npos || cmdline.find("storage.googleapis.com") != std::string::npos || cmdline.find("storjshare.io") != std::string::npos || cmdline.find("temp.sh") != std::string::npos || cmdline.find("transfer.sh") != std::string::npos || cmdline.find("ufile.io") != std::string::npos))
    {
        std::stringstream ss;
        ss << "bitsadmin detected downloading files from suspicious domains";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - File With Suspicious Extension Downloaded Via Bitsadmin
// select * from win_process_events where path like '%bitsadmin.exe%' and cmdline like '% /transfer %' and cmdline like '% /create %' and cmdline like '% /addfile %' and (cmdline like '%.7z%' or cmdline like '%.asax%' or cmdline like '%.ashx%' or cmdline like '%.asmx%' or cmdline like '%.asp%' or cmdline like '%.aspx%' or cmdline like '%.bat%' or cmdline like '%.cfm%' or cmdline like '%.cgi%' or cmdline like '%.chm%' or cmdline like '%.cmd%' or cmdline like '%.dll%' or cmdline like '%.gif%' or cmdline like '%.jpeg%' or cmdline like '%.jpg%' or cmdline like '%.jsp%' or cmdline like '%.jspx%' or cmdline like '%.log%' or cmdline like '%.png%' or cmdline like '%.ps1%' or cmdline like '%.psm1%' or cmdline like '%.rar%' or cmdline like '%.scf%' or cmdline like '%.sct%' or cmdline like '%.txt%' or cmdline like '%.vbe%' or cmdline like '%.vbs%' or cmdline like '%.war%' or cmdline like '%.wsf%' or cmdline like '%.wsh%' or cmdline like '%.xll%' or cmdline like '%.zip%');

bool file_download_suspicious_extension_bitsadmin(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (path.find("bitsadmin.exe") != std::string::npos && cmdline.find(" /transfer ") != std::string::npos && cmdline.find(" /create ") != std::string::npos && cmdline.find(" /addfile ") != std::string::npos && (cmdline.find(".7z") != std::string::npos || cmdline.find(".asax") != std::string::npos || cmdline.find(".ashx") != std::string::npos || cmdline.find(".asmx") != std::string::npos || cmdline.find(".asp") != std::string::npos || cmdline.find(".aspx") != std::string::npos || cmdline.find(".bat") != std::string::npos || cmdline.find(".cfm") != std::string::npos || cmdline.find(".cgi") != std::string::npos || cmdline.find(".chm") != std::string::npos || cmdline.find(".cmd") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".gif") != std::string::npos || cmdline.find(".jpeg") != std::string::npos || cmdline.find(".jpg") != std::string::npos || cmdline.find(".jsp") != std::string::npos || cmdline.find(".jspx") != std::string::npos || cmdline.find(".log") != std::string::npos || cmdline.find(".png") != std::string::npos || cmdline.find(".ps1") != std::string::npos || cmdline.find(".psm1") != std::string::npos || cmdline.find(".rar") != std::string::npos || cmdline.find(".scf") != std::string::npos || cmdline.find(".sct") != std::string::npos || cmdline.find(".txt") != std::string::npos || cmdline.find(".vbe") != std::string::npos || cmdline.find(".vbs") != std::string::npos || cmdline.find(".war") != std::string::npos || cmdline.find(".wsf") != std::string::npos || cmdline.find(".wsh") != std::string::npos || cmdline.find(".xll") != std::string::npos || cmdline.find(".zip") != std::string::npos))
    {
        std::stringstream ss;
        ss << "bitsadmin detected downloading files from suspicious extensions";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - File Download Via Bitsadmin To A Suspicious Target Folder
// select * from win_process_events where path like '%bitsadmin.exe%' and cmdline like '% /transfer %' and cmdline like '% /create %' and cmdline like '% /addfile %' and (cmdline like '%:\\Perflogs%' or cmdline like '%:\\ProgramData\\%' or cmdline like '%:\\Temp\\%' or cmdline like '%:\\Users\\Public\\%' or cmdline like '%:\\Windows\\%' or cmdline like '%\\AppData\\Local\\Temp\\%' or cmdline like '%\\AppData\\Roaming\\%' or cmdline like '%\\Desktop\\%' or cmdline like '%ProgramData%' or cmdline like '%public%');

bool file_download_bitsadmin_suspicious_target_folder(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (path.find("bitsadmin.exe") != std::string::npos && cmdline.find(" /transfer ") != std::string::npos && cmdline.find(" /create ") != std::string::npos && cmdline.find(" /addfile ") != std::string::npos && (cmdline.find(":\\Perflogs") != std::string::npos || cmdline.find(":\\ProgramData\\") != std::string::npos || cmdline.find(":\\Temp\\") != std::string::npos || cmdline.find(":\\Users\\Public\\") != std::string::npos || cmdline.find(":\\Windows\\") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\AppData\\Roaming\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("%ProgramData%") != std::string::npos || cmdline.find("%public%") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of bitsadmin downloading a file to a suspicious target folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - File Download Via Bitsadmin To An Uncommon Target Folder
// select * from win_process_events where path like '%bitsadmin.exe%' and cmdline like '% /transfer %' and cmdline like '% /create %' and cmdline like '% /addfile %' and (cmdline like '%AppData%' or cmdline like '%temp%' or cmdline like '%tmp%' or cmdline like '%\\AppData\\Local\\%' or cmdline like '%C:\\Windows\\Temp\\%');

bool file_download_bitsadmin_uncommon_target_folder(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (path.find("bitsadmin.exe") != std::string::npos && cmdline.find(" /transfer ") != std::string::npos && cmdline.find(" /create ") != std::string::npos && cmdline.find(" /addfile ") != std::string::npos && (cmdline.find("AppData%") != std::string::npos || cmdline.find("temp") != std::string::npos || cmdline.find("%tmp%") != std::string::npos || cmdline.find("\\AppData\\Local\\") != std::string::npos || cmdline.find("C:\\Windows\\Temp\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of bitsadmin downloading a file to an uncommon target folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1197 - Monitoring For Persistence Via BITS
// select * from win_process_events where ((cmdline like '%bitsadmin%' and cmdline like '%/SetNotifyCmdLine%') and (cmdline like '%COMSPEC%' or cmdline like '%cmd.exe%' or cmdline like '%regsvr32.exe%')) or ((cmdline like '%bitsadmin%' and cmdline like '%/Addfile%') and (cmdline like '%http:%' or cmdline like '%https:%' or cmdline like '%ftp:%' or cmdline like '%ftps:%'));

bool monitoring_persistence_bits(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (((cmdline.find("bitsadmin") != std::string::npos && cmdline.find("/SetNotifyCmdLine") != std::string::npos) && (cmdline.find("COMSPEC") != std::string::npos || cmdline.find("cmd.exe") != std::string::npos || cmdline.find("regsvr32.exe") != std::string::npos)) || ((cmdline.find("bitsadmin") != std::string::npos && cmdline.find("/Addfile") != std::string::npos) && (cmdline.find("http:") != std::string::npos || cmdline.find("https:") != std::string::npos || cmdline.find("ftp:") != std::string::npos || cmdline.find("ftps:") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Bits abused to create persistence and used for malicious purposes";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1553.004 - New Root Certificate Installed Via CertMgr.EXE
//  select * from win_process_events where path like '%\\CertMgr.exe%' and cmdline like '%/add%' and cmdline like '%root%';

bool new_root_certificate_certmgr(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\CertMgr.exe") != std::string::npos && cmdline.find("/add") != std::string::npos && cmdline.find("root") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected certmgr with flag to install certificates on the system";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - DLL Loaded via CertOC.EXE
// select * from win_process_events where path like '%certoc.exe%' and (cmdline like '%-LoadDLL%' or cmdline like '%/LoadDLL%');

bool dll_loaded_certoc(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certoc.exe") != std::string::npos && (cmdline.find("-LoadDLL") != std::string::npos || cmdline.find("/LoadDLL") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected installation of certificates via certoc to load dll file";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Suspicious DLL Loaded via CertOC.EXE
//  select * from win_process_events where path like '%certoc.exe%' and (cmdline like '%-LoadDLL%' or cmdline like '%/LoadDLL%') and (cmdline like '%\\Appdata\\Local\\Temp\\%' or cmdline like '%\\Desktop\\%' or cmdline like '%\\Downloads\\%' or cmdline like '%\\Users\\Public\\%' or cmdline like '%C:\\Windows\\Tasks\\%' or cmdline like '%C:\\Windows\\Temp\\%');

bool suspicious_dll_loaded_certoc(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certoc.exe") != std::string::npos && (cmdline.find("-LoadDLL") != std::string::npos || cmdline.find("/LoadDLL") != std::string::npos) && (cmdline.find("\\Appdata\\Local\\Temp\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("C:\\Windows\\Tasks\\") != std::string::npos || cmdline.find("C:\\Windows\\Temp\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected installation of certificates via certoc to load suspicious dll file";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Suspicious Download Via Certutil.EXE
// select * from win_process_events where path like '%certutil.exe%' and ((cmdline like '%urlcache%' or cmdline like '%verifyctl%') and cmdline like '%http%');

bool suspicious_download_certutil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certutil.exe") != std::string::npos && (cmdline.find("urlcache ") != std::string::npos || cmdline.find("verifyctl ") != std::string::npos) && cmdline.find("http") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected certutil to run with flags enabling utility to download files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Suspicious File Downloaded From Direct IP Via Certutil.EXE
// select * from win_process_events where path like '%certutil.exe%' and ((cmdline like '%urlcache%' or cmdline like '%verifyctl%') and (cmdline like '%://1%' or cmdline like '%://2%' or cmdline like '%://3%' or cmdline like '%://4%' or cmdline like '%://5%' or cmdline like '%://6%' or cmdline like '%://7%' or cmdline like '%://8%' or cmdline like '%://9%'));

bool suspicious_download_certutil_ip(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certutil.exe") != std::string::npos && (cmdline.find("urlcache ") != std::string::npos || cmdline.find("verifyctl ") != std::string::npos) && ((cmdline.find("://1") != std::string::npos || cmdline.find("://2") != std::string::npos || cmdline.find("://3") != std::string::npos || cmdline.find("://4") != std::string::npos || cmdline.find("://5") != std::string::npos || cmdline.find("://6") != std::string::npos || cmdline.find("://7") != std::string::npos || cmdline.find("://8") != std::string::npos || cmdline.find("://9") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected certutil to run with flags enabling utility to download files from direct IPs";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE
// select * from win_process_events where path like '%certutil.exe%' and ((cmdline like '%urlcache%' or cmdline like '%verifyctl%') and (cmdline like '%.githubusercontent.com%' or cmdline like '%anonfiles.com%' or cmdline like '%cdn.discordapp.com%' or cmdline like '%cdn.discordapp.com/attachments/%' or cmdline like '%ddns.net%' or cmdline like '%dl.dropboxusercontent.com%' or cmdline like '%ghostbin.co%' or cmdline like '%gofile.io%' or cmdline like '%hastebin.com%' or cmdline like '%mediafire.com%' or cmdline like '%mega.nz%' or cmdline like '%paste.ee%' or cmdline like '%pastebin.com%' or cmdline like '%pastebin.pl%' or cmdline like '%pastetext.net%' or cmdline like '%privatlab.com%' or cmdline like '%privatlab.net%' or cmdline like '%send.exploit.in%' or cmdline like '%sendspace.com%' or cmdline like '%storage.googleapis.com%' or cmdline like '%storjshare.io%' or cmdline like '%temp.sh%' or cmdline like '%transfer.sh%' or cmdline like '%ufile.io%'));

bool suspicious_file_download_certutil_file_sharing(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certutil.exe") != std::string::npos && (cmdline.find("urlcache ") != std::string::npos || cmdline.find("verifyctl ") != std::string::npos) && (cmdline.find(".githubusercontent.com") != std::string::npos || cmdline.find("anonfiles.com") != std::string::npos || cmdline.find("cdn.discordapp.com") != std::string::npos || cmdline.find("cdn.discordapp.com/attachments/") != std::string::npos || cmdline.find("ddns.net") != std::string::npos || cmdline.find("dl.dropboxusercontent.com") != std::string::npos || cmdline.find("ghostbin.co") != std::string::npos || cmdline.find("gofile.io") != std::string::npos || cmdline.find("hastebin.com") != std::string::npos || cmdline.find("mediafire.com") != std::string::npos || cmdline.find("mega.nz") != std::string::npos || cmdline.find("paste.ee") != std::string::npos || cmdline.find("pastebin.com") != std::string::npos || cmdline.find("pastebin.pl") != std::string::npos || cmdline.find("pastetext.net") != std::string::npos || cmdline.find("privatlab.com") != std::string::npos || cmdline.find("privatlab.net") != std::string::npos || cmdline.find("send.exploit.in") != std::string::npos || cmdline.find("sendspace.com") != std::string::npos || cmdline.find("storage.googleapis.com") != std::string::npos || cmdline.find("storjshare.io") != std::string::npos || cmdline.find("temp.sh") != std::string::npos || cmdline.find("transfer.sh") != std::string::npos || cmdline.find("ufile.io") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected certutil to run with flags enabling utility to download files from file sharing websites";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Suspicious File Encoded To Base64 Via Certutil.EXE
//  select * from win_process_events where path like '%certutil.exe%' and ((cmdline like '%-encode%' or cmdline like '%/encode%') and (cmdline like '%.githubusercontent.com%' or cmdline like '%anonfiles.com%' or cmdline like '%cdn.discordapp.com%' or cmdline like '%cdn.discordapp.com/attachments/%' or cmdline like '%ddns.net%' or cmdline like '%dl.dropboxusercontent.com%' or cmdline like '%ghostbin.co%' or cmdline like '%gofile.io%' or cmdline like '%hastebin.com%' or cmdline like '%mediafire.com%' or cmdline like '%mega.nz%' or cmdline like '%paste.ee%' or cmdline like '%pastebin.com%' or cmdline like '%pastebin.pl%' or cmdline like '%pastetext.net%' or cmdline like '%privatlab.com%' or cmdline like '%privatlab.net%' or cmdline like '%send.exploit.in%' or cmdline like '%sendspace.com%' or cmdline like '%storage.googleapis.com%' or cmdline like '%storjshare.io%' or cmdline like '%temp.sh%' or cmdline like '%transfer.sh%' or cmdline like '%ufile.io%'));

bool suspicious_file_encoded_base64_certutil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certutil.exe") != std::string::npos && (cmdline.find("-encode") != std::string::npos || cmdline.find("/encode") != std::string::npos) && (cmdline.find(".githubusercontent.com") != std::string::npos || cmdline.find("anonfiles.com") != std::string::npos || cmdline.find("cdn.discordapp.com") != std::string::npos || cmdline.find("cdn.discordapp.com/attachments/") != std::string::npos || cmdline.find("ddns.net") != std::string::npos || cmdline.find("dl.dropboxusercontent.com") != std::string::npos || cmdline.find("ghostbin.co") != std::string::npos || cmdline.find("gofile.io") != std::string::npos || cmdline.find("hastebin.com") != std::string::npos || cmdline.find("mediafire.com") != std::string::npos || cmdline.find("mega.nz") != std::string::npos || cmdline.find("paste.ee") != std::string::npos || cmdline.find("pastebin.com") != std::string::npos || cmdline.find("pastebin.pl") != std::string::npos || cmdline.find("pastetext.net") != std::string::npos || cmdline.find("privatlab.com") != std::string::npos || cmdline.find("privatlab.net") != std::string::npos || cmdline.find("send.exploit.in") != std::string::npos || cmdline.find("sendspace.com") != std::string::npos || cmdline.find("storage.googleapis.com") != std::string::npos || cmdline.find("storjshare.io") != std::string::npos || cmdline.find("temp.sh") != std::string::npos || cmdline.find("transfer.sh") != std::string::npos || cmdline.find("ufile.io") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected certutil with encode flag to encode suspicious extension";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - File In Suspicious Location Encoded To Base64 Via Certutil.EXE
// select * from win_process_events where path like '%certutil.exe%' and ((cmdline like '%-encode%' or cmdline like '%/encode%') and (cmdline like '%\\AppData\\Roaming\\%' or cmdline like '%\\Desktop\\%' or cmdline like '%\\Local\\Temp\\%' or cmdline like '%\\PerfLogs\\%' or cmdline like '%\\Users\\Public\\%' or cmdline like '%\\Windows\\Temp\\%' or cmdline like '%$Recycle.Bin%'));

bool file_in_suspicious_location_cerutil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("certutil.exe") != std::string::npos && (cmdline.find("-encode") != std::string::npos || cmdline.find("/encode") != std::string::npos) && (cmdline.find("\\AppData\\Roaming\\") != std::string::npos || cmdline.find("\\Desktop\\") != std::string::npos || cmdline.find("\\Local\\Temp\\") != std::string::npos || cmdline.find("\\PerfLogs\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\Windows\\Temp\\") != std::string::npos || cmdline.find("$Recycle.Bin") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected certutil with encode flag to encode file in potentially suspicious location";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1027 - Certificate Exported Via Certutil.EXE
// select * from win_process_events where path like '%certutil.exe%' and (cmdline like '%-exportPFX%' or cmdline like '%/exportPFX%');

bool certificate_exported_certutil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\certutil.exe") != std::string::npos && (cmdline.find("-exportPFX ") != std::string::npos || cmdline.find("/exportPFX ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected certutil with export flag to enable utility to export certificates";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Potential NTLM Coercion Via Certutil.EXE
// select * from win_process_events where path like '%certutil.exe%' and (cmdline like '% -syncwithWU %' and cmdline like '% \\\\%');

bool potential_ntlm_coercion_certutil(const ProcessEvent &process_event, Event &rule_event)
{

    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\certutil.exe") != std::string::npos && cmdline.find(" -syncwithWU ") != std::string::npos && cmdline.find(" \\\\") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected possible NTLM coercion via certutil using the 'syncwithWU' flag";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 - Greedy File Deletion Using Del
//  SELECT * FROM win_process_events WHERE path LIKE '%cmd.exe%' AND (cmdline LIKE '%del %' OR cmdline LIKE '%erase %') AND (cmdline LIKE '%.au3%' OR cmdline LIKE '%.dll%' OR cmdline LIKE '%.exe%' OR cmdline LIKE '%.js%');

bool greedy_file_deletion_using_del(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("cmd.exe") != std::string::npos && (cmdline.find("del ") != std::string::npos || cmdline.find("erase ") != std::string::npos) && (cmdline.find(".au3") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".exe") != std::string::npos || cmdline.find(".js") != std::string::npos))
    {
        std::stringstream ss;
        ss << "File deletion using Del";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 -  Suspicious Ping/Copy Command Combination
//  SELECT * FROM win_process_events WHERE path LIKE '%\\cmd.exe%' AND ((cmdline LIKE '% -n %' OR cmdline LIKE '% /n %') AND (cmdline LIKE '%ping%' AND cmdline LIKE '%copy %' AND cmdline LIKE '% /y %'));

bool ping_copy_command_combination(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\cmd.exe") != std::string::npos && (cmdline.find(" -n ") != std::string::npos || cmdline.find(" /n ") != std::string::npos) && (cmdline.find("ping") != std::string::npos && cmdline.find("copy ") != std::string::npos && cmdline.find(" /y ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected ping and copy command executed at the same time";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 - Ping/Del Command Combination
//  SELECT * FROM win_process_events WHERE ((cmdline LIKE '% -n %' OR cmdline LIKE '% /n %') AND cmdline LIKE '%Nul%' AND (cmdline LIKE '% /f %' OR cmdline LIKE '% -f %' OR cmdline LIKE '% /q %' OR cmdline LIKE '% -q %') AND (cmdline LIKE '%ping%' AND cmdline LIKE '%del %'));

bool ping_del_command_combination(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find(" -n ") != std::string::npos || cmdline.find(" /n ") != std::string::npos) && cmdline.find("Nul") != std::string::npos && (cmdline.find(" /f ") != std::string::npos || cmdline.find(" -f ") != std::string::npos || cmdline.find(" /q ") != std::string::npos || cmdline.find(" -q ") != std::string::npos) && (cmdline.find("ping") != std::string::npos && cmdline.find("del ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected ping and del command executed at the same time";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 - Directory Removal Via Rmdir
// SELECT * FROM win_process_events WHERE (path LIKE '%cmd.exe%' AND cmdline LIKE '%rmdir%' AND (cmdline LIKE '%/s%' OR cmdline LIKE '%/q%'));

bool directory_removal_rmdir(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("cmd.exe") != std::string::npos && cmdline.find("rmdir") != std::string::npos && (cmdline.find("/s") != std::string::npos || cmdline.find("/q") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of rmdir command to delete a directory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Suspicious High IntegrityLevel Conhost Legacy Option
//
bool suspicious_high_integrity_level_conhost_legacy_option(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("conhost.exe") != std::string::npos && cmdline.find("0xffffffff") != std::string::npos && cmdline.find("-ForceV1") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected ForceV1 running along with conhost with elevated privileges";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - CreateDump Process Dump
//
bool createdump_process_dump(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\createdump.exe") != std::string::npos && (cmdline.find(" -u ") != std::string::npos || cmdline.find(" --full ") != std::string::npos || cmdline.find(" -f ") != std::string::npos || cmdline.find(" --name ") != std::string::npos || cmdline.find(".dmp ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected use of the createdump.exe LOLOBIN utility to dump process memory";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Suspicious Csi.exe Usage
//
bool suspicious_csi_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    if (path.find("csi.exe") != std::string::npos || path.find("rcsi.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected signed binary csi.exe used for executing C# code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.002 - Potential DLL Sideloading Via DeviceEnroller.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\deviceenroller.exe%' AND cmdline LIKE '%/PhoneDeepLink%');

bool potential_dll_sideloading_deviceenroller(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\deviceenroller.exe") != std::string::npos && cmdline.find("/PhoneDeepLink") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected signed binary csi.exe used for executing C# code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218 - Arbitrary MSI Download Via Devinit.EXE
// SELECT * FROM win_process_events WHERE (cmdline LIKE '% -t msi-install %' AND cmdline LIKE '% -i http%');

bool arbitrary_msi_download_devinit(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find(" -t msi-install ") != std::string::npos && cmdline.find(" -i http") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected signed binary csi.exe used for executing C# code";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1574.002 - DNS ServerLevelPluginDll Installed Via Dnscmd.EXE
// SELECT * FROM win_process_events WHERE (path LIKE '%\\dnscmd.exe%' AND cmdline LIKE '%/config%' AND cmdline LIKE '%/serverlevelplugindll%');

bool dns_serverlevelplugindll_dnscmd(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\dnscmd.exe") != std::string::npos && cmdline.find("/config") != std::string::npos && cmdline.find("/serverlevelplugindll") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1562.001 -  Dism Remove Online Package
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\DismHost.exe%' AND cmdline LIKE '%/Online%' AND cmdline LIKE '%/Disable-Feature%') OR (path LIKE '%\\Dism.exe%' AND cmdline LIKE '%/Online%' AND cmdline LIKE '%/Disable-Feature%'));

bool dism_remove_online_package(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\DismHost.exe") != std::string::npos && cmdline.find("/Online") != std::string::npos && cmdline.find("/Disable-Feature") != std::string::npos) || (path.find("\\Dism.exe") != std::string::npos && cmdline.find("/Online") != std::string::npos && cmdline.find("/Disable-Feature") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - DumpMinitool Execution
// SELECT * FROM win_process_events WHERE ((path LIKE '%\\DumpMinitool.exe%' OR path LIKE '%\\DumpMinitool.x86.exe%' OR path LIKE '%\\DumpMinitool.arm64.exe%') AND (cmdline LIKE '% Full%' OR cmdline LIKE '% Mini%' OR cmdline LIKE '% WithHeap%'));

bool dumpminitool_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\DumpMinitool.exe") != std::string::npos || path.find("\\DumpMinitool.x86.exe") != std::string::npos || path.find("\\DumpMinitool.arm64.exe") != std::string::npos) && (cmdline.find(" Full") != std::string::npos || cmdline.find(" Mini") != std::string::npos || cmdline.find(" WithHeap") != std::string::npos))
    {
        std::stringstream ss;
        ss << "";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Explorer Process Tree Break
// SELECT * FROM win_process_events WHERE cmdline LIKE '%/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}%' OR (cmdline LIKE '%explorer.exe%' AND cmdline LIKE '%/root,%');

bool explorer_process_tree_break(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}") != std::string::npos || (cmdline.find("explorer.exe") != std::string::npos && cmdline.find("/root,") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a command line process that uses explorer.exe to launch arbitrary commands or binaries";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1036 - Findstr Launching .lnk File
//
bool findstr_lnk_file(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("findstr.exe") != std::string::npos && cmdline.find(".lnk") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected usage of findstr to identify and execute a lnk file";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070 - Fsutil Suspicious Invocation
//
bool fsutil_sus_invocation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\fsutil.exe") != std::string::npos && (cmdline.find("deletejournal") != std::string::npos || cmdline.find("createjournal") != std::string::npos || cmdline.find("setZeroData") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious parameters of fsutil ";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.001 - Remote CHM File Download/Execution Via HH.EXE
//

bool remote_chm_file_download_hh_exe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\hh.exe") != std::string::npos && cmdline.find("http") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the usage of hh.exe to execute/download remotely hosted .chm files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.001 - HTML Help HH.EXE Suspicious Child Process
//

bool html_help_hh_exe_child_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    if (parent_path.find("hh.exe") != std::string::npos && (path.find("\\CertReq.exe") != std::string::npos || path.find("\\CertUtil.exe") != std::string::npos || path.find("\\cmd.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\installutil.exe") != std::string::npos || path.find("\\MSbuild.exe") != std::string::npos || path.find("\\MSHTA.EXE") != std::string::npos || path.find("\\msiexec.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\schtasks.exe") != std::string::npos || path.find("\\wmic.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a suspicious child process of a Microsoft HTML Help ";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.001 - Suspicious HH.EXE Execution
//
bool sus_hh_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\hh.exe") != std::string::npos && (cmdline.find(".application") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp\\") != std::string::npos || cmdline.find("\\Content.Outlook\\") != std::string::npos || cmdline.find("\\Downloads\\") != std::string::npos || cmdline.find("\\Users\\Public\\") != std::string::npos || cmdline.find("\\Windows\\Temp\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a suspicious execution of a Microsoft HTML Help ";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - HackTool - F-Secure C3 Load by Rundll32
//
bool hacktool_c3_load_rundll32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("rundll32.exe") != std::string::npos && cmdline.find(".dll") != std::string::npos && cmdline.find("StartNodeRelay") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected F-Secure C3 produces DLLs with a default exported StartNodeRelay function";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - CobaltStrike Load by Rundll32
//
bool cobaltstrike_load_rundll32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("rundll32") != std::string::npos && cmdline.find("dll") != std::string::npos && cmdline.find("StartW") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected Rundll32 use by Cobalt Strike with StartW function to load DLLs";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - HackTool - DInjector PowerShell Cradle Execution
//
bool hacktool_dinjector_powershell_cradle_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("am51") != std::string::npos && cmdline.find("password") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the use of the Dinject PowerShell cradle based on the specific flags";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Pikabot - Defense Evasion Pikabot fake DLL extension execution via rundll32
bool pikabot_fake_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (((parent_path.find("cmd.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos || parent_path.find("cmd.exe") != std::string::npos) && path.find("rundll32.exe") != std::string::npos && (cmdline.find("\\ProgramData") != std::string::npos || cmdline.find("\\Users\\Public") != std::string::npos || cmdline.find("\\Windows\\Installer") != std::string::npos || cmdline.find("\\AppData\\Local\\Temp") != std::string::npos || cmdline.find("\\AppData\\Roaming") != std::string::npos)) &&
        !(cmdline.find(".cpl") != std::string::npos || cmdline.find(".dll") != std::string::npos || cmdline.find(".inf") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected specific process tree behavior linked to rundll32 executions, wherein the associated DLL lacks a common .dll";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Pikabot - Defense Evasion, T1218, Execution, T1059.003 Potential Pikabot infection via suspicious cmd command combination
bool pikabot_infection_via_sus_cmd_combination(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("cmd") != std::string::npos || cmdline.find("/c") != std::string::npos) &&
        (cmdline.find("\\ &\\ ") != std::string::npos || cmdline.find("\\ ||\\ ") != std::string::npos) &&
        (cmdline.find("\\ curl") != std::string::npos || cmdline.find("\\ wget") != std::string::npos ||
         cmdline.find("\\ timeout") != std::string::npos || cmdline.find("\\ ping\\ ") != std::string::npos) &&
        (cmdline.find("\\ rundll32") != std::string::npos || cmdline.find("\\ mkdir\\ ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the execution of concatenated commands via cmd.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}
// Qakbot
bool qakbot_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if ((parent_path.find("cmd.exe") != std::string::npos && path.find("mshta.exe") != std::string::npos && cmdline.find("http://") != std::string::npos) || (path.find("wscript.exe") != std::string::npos && cmdline.find("appdata\\local\\temp\\*.js") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Qakbot Detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Qakbot - Process tree execution

bool qakbot_process_tree_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (parent_path.find("explorer.exe") != std::string::npos &&
        ((path.find("wscript.exe") != std::string::npos || path.find("cscript.exe") != std::string::npos) &&
         (cmdline.find(".js") != std::string::npos || cmdline.find(".vbs") != std::string::npos || cmdline.find(".wsf") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Qakbot Detected";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}
// MSI installation from the internet via msiexec
bool raspberry_robin_msi_installation(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;
    if (path.find("msiexec.exe") != std::string::npos &&
        cmdline.find("/q") != std::string::npos &&
        cmdline.find("http") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the installation of msi package from the internet";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1567.022 - Remote Access Tool - NetSupport Execution From Unusual Location
// SELECT * FROM win_process_events WHERE path LIKE '%\\client32.exe%' AND NOT (cmdline LIKE '%C:\\Program Files\\%' OR cmdline LIKE '%C:\\Program Files (x86)\\%');
bool netsupport_execution_from_unusual_location(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\client32.exe") != std::string::npos && !(cmdline.find("C:\\Program Files\\") != std::string::npos || cmdline.find("C:\\Program Files (x86)\\") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected execution of client32.exe (NetSupport RAT) from an unusual location";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1202 - Usage of winrs
// SELECT * FROM win_process_events WHERE path LIKE '%winrs.exe%';

bool usage_of_winrs(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("winrs.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the usage of winrs to bypass monitoring and restrictions on CLI";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.005 - MSHTA proxy execution
// SELECT * FROM win_process_events WHERE path LIKE '%mshta.exe%' AND (cmdline LIKE '%javascript%' OR cmdline LIKE '%vbscript%');

bool mshta_proxy_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("mshta.exe") != std::string::npos && (cmdline.find("javascript") != std::string::npos || cmdline.find("vbscript") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the usage of mshta to proxy the execution of javascript or vbscript files.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Rundll32 execution with DLLRegisterServer command line
// SELECT * FROM win_process_events WHERE path LIKE '%rundll32.exe%' AND cmdline LIKE '%dllregisterserver%';

bool rundll32_execution_with_dllregisterserver_command_line(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string cmdline = process_event.entry.cmdline;

    if (path.find("rundll32.exe") != std::string::npos && cmdline.find("dllregisterserver") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected execution of rundll32 with command line specifying DLLRegisterServer.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1218.011 - Suspicious parent process of rundll32
// SELECT * FROM win_process_events WHERE (parent_path LIKE '%winword.exe%' OR parent_path LIKE '%excel.exe%' OR parent_path LIKE '%msaccess.exe%' OR parent_path LIKE '%lsass.exe%' OR parent_path LIKE '%taskeng.exe%' OR parent_path LIKE '%winlogon.exe%' OR parent_path LIKE '%schtask.exe%' OR parent_path LIKE '%regsvr32.exe%' OR parent_path LIKE '%wmiprvse.exe%' OR parent_path LIKE '%wsmprovhost.exe%') AND path LIKE '%rundll32.exe%';

bool suspicious_parent_process_of_rundll32(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if ((parent_path.find("winword.exe") != std::string::npos || parent_path.find("excel.exe") != std::string::npos || parent_path.find("msaccess.exe") != std::string::npos || parent_path.find("lsass.exe") != std::string::npos || parent_path.find("taskeng.exe") != std::string::npos || parent_path.find("winlogon.exe") != std::string::npos || parent_path.find("schtask.exe") != std::string::npos || parent_path.find("regsvr32.exe") != std::string::npos || parent_path.find("wmiprvse.exe") != std::string::npos || parent_path.find("wsmprovhost.exe") != std::string::npos) && path.find("rundll32.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the execution of rundll32.exe via suspicious parent process.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1222.001 - File permissions modification
// SELECT * FROM win_process_events WHERE (path LIKE '%takeown.exe%' OR path LIKE '%icacls.exe%' OR path LIKE '%cacls.exe%' OR path LIKE '%attrib.exe%') AND NOT parent_path LIKE '%iwrap.exe%' AND NOT cmdline LIKE '%Adobe%';

bool file_permissions_modification(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if ((path.find("takeown.exe") != std::string::npos || path.find("icacls.exe") != std::string::npos || path.find("cacls.exe") != std::string::npos || path.find("attrib.exe") != std::string::npos) && !(parent_path.find("iwrap.exe") != std::string::npos) && !(cmdline.find("Adobe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of file permission modification utilities.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.002 - Hiding local user accounts
// SELECT * FROM win_process_events WHERE ((parent_path LIKE '%cmd.exe%' OR parent_path LIKE '%powershell.exe%') AND path LIKE '%reg.exe%' AND (cmdline LIKE '%HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist%' AND cmdline LIKE '%add%' AND cmdline LIKE '%/t%' AND cmdline LIKE '%REG_DWORD%' AND cmdline LIKE '%/v%' AND cmdline LIKE '%/d 0%'));

bool hiding_local_user_accounts(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if ((parent_path.find("cmd.exe") != std::string::npos || parent_path.find("powershell.exe") != std::string::npos) && path.find("reg.exe") != std::string::npos && (cmdline.find("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("/t") != std::string::npos && cmdline.find("REG_DWORD") != std::string::npos && cmdline.find("/v") != std::string::npos && cmdline.find("/d 0") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the use of reg.exe to hide users from listed in the logon screen.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1564.005 - Registry export via GUI or CLI utility
// SELECT * FROM win_process_events WHERE (path LIKE '%reg.exe%' AND cmdline LIKE '%export%') OR (path LIKE '%regedit.exe%' AND (cmdline LIKE '%-E%' OR cmdline LIKE '%/E%'));

bool registry_export_via_gui_or_cli_utility(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("reg.exe") != std::string::npos && cmdline.find("export") != std::string::npos) || (path.find("regedit.exe") != std::string::npos && (cmdline.find("-E") != std::string::npos || cmdline.find("/E") != std::string::npos)))
    {
        std::stringstream ss;
        ss << "Detected the export of a registry key.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1055 - Common injected process with empty command line
// SELECT * FROM win_process_events WHERE
// (
//     (path = 'backgroundtaskhost.exe' AND cmdline LIKE '%backgroundtaskhost.exe%') OR
//     (path = 'svchost.exe' AND cmdline LIKE '%svchost.exe%') OR
//     (path = 'dllhost.exe' AND cmdline LIKE '%dllhost.exe%') OR
//     (path = 'werfault.exe' AND cmdline LIKE '%werfault.exe%') OR
//     (path = 'searchprotocolhost.exe' AND cmdline LIKE '%searchprotocolhost.exe%') OR
//     (path = 'wuauclt.exe' AND cmdline LIKE '%wuauclt.exe%') OR
//     (path = 'spoolsv.exe' AND cmdline LIKE '%spoolsv.exe%') OR
//     (path = 'rundll32.exe' AND cmdline LIKE '%rundll32.exe%') OR
//     (path = 'regasm.exe' AND cmdline LIKE '%regasm.exe%') OR
//     (path = 'regsvr32.exe' AND cmdline LIKE '%regsvr32.exe%') OR
//     (path = 'regsvcs.exe' AND cmdline LIKE '%regsvcs.exe%')
// );

bool common_injected_process_with_empty_command_line(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path == "backgroundtaskhost.exe" && cmdline.find("backgroundtaskhost.exe") != std::string::npos) ||
        (path == "svchost.exe" && cmdline.find("svchost.exe") != std::string::npos) ||
        (path == "dllhost.exe" && cmdline.find("dllhost.exe") != std::string::npos) ||
        (path == "werfault.exe" && cmdline.find("werfault.exe") != std::string::npos) ||
        (path == "searchprotocolhost.exe" && cmdline.find("searchprotocolhost.exe") != std::string::npos) ||
        (path == "wuauclt.exe" && cmdline.find("wuauclt.exe") != std::string::npos) ||
        (path == "spoolsv.exe" && cmdline.find("spoolsv.exe") != std::string::npos) ||
        (path == "rundll32.exe" && cmdline.find("rundll32.exe") != std::string::npos) ||
        (path == "regasm.exe" && cmdline.find("regasm.exe") != std::string::npos) ||
        (path == "regsvr32.exe" && cmdline.find("regsvr32.exe") != std::string::npos) ||
        (path == "regsvcs.exe" && cmdline.find("regsvcs.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious execution of common processes without command line, which are not supposed to have empty command line.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.001 - Event log cleared via wevtutil
// SELECT * FROM win_process_events WHERE (path LIKE '%wevtutil.exe%' AND cmdline LIKE '%cl%');

bool event_log_cleared_via_wevtutil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("wevtutil.exe") != std::string::npos && cmdline.find("cl") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the clearing of logs via the Windows built-in wevtutil utility.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1070.004 - Anti-forensic deletion, tampering or size reduction of USN Journal
// SELECT * FROM win_process_events WHERE ((path LIKE '%fsutil.exe%' OR original_filename LIKE '%fsutil.exe%') AND (cmdline LIKE '%deletejournal%' OR cmdline LIKE '%createjournal%' OR cmdline LIKE '%setZeroData%'));

bool anti_forensic_deletion_tampering_or_size_reduction_of_USN_journal(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("fsutil.exe") != std::string::npos) &&
        (cmdline.find("deletejournal") != std::string::npos ||
         cmdline.find("createjournal") != std::string::npos ||
         cmdline.find("setZeroData") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the deletion, tampering or size reduction of the USN Journal with the utility fsutil.exe";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1132.001 Suspcious CertUtil execution
// SELECT * FROM win_process_events WHERE (path LIKE '%certutil.exe%' AND (cmdline LIKE '%encode%' OR cmdline LIKE '%decode%' OR cmdline LIKE '%-verify%' OR cmdline LIKE '%-decodehex%'));

bool suspcious_certUtil_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("certutil.exe") != std::string::npos && (cmdline.find("encode") != std::string::npos || cmdline.find("decode") != std::string::npos || cmdline.find("-verify") != std::string::npos || cmdline.find("-decodehex") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected suspicious command line of process certutil to detect decoding or encoding activities to either bypass defenses or for exfiltration purpose.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}


