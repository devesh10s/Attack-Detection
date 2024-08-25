#include "win_credential_access_rules.h"
#include <sstream>

// // Cached Credential Dump via Cmdkey

// bool cached_credential_dump_cmdkey(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

// 	if(cmdline.find("cmdkey /list") != std::string::npos)
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;
// 	}

// 	return false;
// }

// T1110.001 - Brute Force: Password Guessing
// select * from win_process_events where path like '%net.exe%' and cmdline like '%net%' and cmdline like '%/user:%' and cmdline like '%use%';

bool password_guessing(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("net.exe") != std::string::npos && cmdline.find("net") != std::string::npos && cmdline.find("/user:") != std::string::npos && cmdline.find("use") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Password guessing done for account access";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1539 - Steal Web Session Cookie
// select * from win_process_events where path like '%powershell.exe%' and ((cmdline like '%firefox%' and cmdline like '%CookieDBLocation%') or (cmdline like '%chrome%' and cmdline like '%Cookies%'));

bool steal_web_session_cookie(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("powershell.exe") != std::string::npos && ((cmdline.find("firefox") != std::string::npos && cmdline.find("CookieDBLocation") != std::string::npos) || (cmdline.find("chrome") != std::string::npos && cmdline.find("Cookies") != std::string::npos)))
    {
        std::stringstream ss;

        ss << "Web cookies stolen for accessing web applications or internet services";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.002: Registry dump of SAM, creds, and secrets
// SELECT * FROM win_process_events WHERE (path LIKE '%reg.exe%' AND (cmdline LIKE '%save*%' OR cmdline LIKE '%export*%') AND parent_path LIKE '%trolleyexpress.exe%');

bool registry_dump_of_sam_creds_secrets(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    std::string parent_path = process_event.entry.parent_path;

    if (path.find("reg.exe") != std::string::npos && (cmdline.find("save*") != std::string::npos || (cmdline.find("export*") != std::string::npos)) && parent_path.find("trolleyexpress.exe") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Credential material extracted from Security Account Manager(SAM)";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1040: Packet Capture Windows Command Prompt
// select * from win_process_events where (path like '%cmd.exe%' and cmdline like '%pktmon.exe%) OR (path like '%PktMon.exe%' and cmdline like '%pktmon.exe% );

bool packet_capture_windows_command_prompt(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("cmd.exe") != std::string::npos && cmdline.find("pktmon.exe") != std::string::npos) || (path.find("PktMon.exe") != std::string::npos && cmdline.find("pktmon.exe") != std::string::npos) || (cmdline.find("netsh") != std::string::npos && cmdline.find("trace") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Network Traffic sniffed for caputring information";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1040: Windows internal packet capture

// bool windows_internal_packet_capture(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

// 	if(cmdline.find("netsh") != std::string::npos && cmdline.find("trace") != std::string::npos)
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;
// 	}

// 	return false;
// }

// T1552.002 - Unsecured Credentials: Credentials in Registry
// select * from win_process_events where cmdline like '%reg%' and cmdline like '%query%' and cmdline '%PuTTY%';

// bool enumeration_for_credentials_in_registry(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

// 	if(cmdline.find("reg") != std::string::npos && cmdline.find("query") != std::string::npos && cmdline.find("password") != std::string::npos)
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;
// 	}

// 	return false;
// }

bool enumeration_for_credentials_in_registry(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("reg") != std::string::npos && cmdline.find("query") != std::string::npos && cmdline.find("PuTTY") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Compromised Registry searched for stored credentials";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.002 - Unsecured Credentials: Credentials in Registry
// Enumeration for PuTTY Credentials in Registry

// bool putty_credentials_in_registry(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;

// 	if(cmdline.find("reg") != std::string::npos && cmdline.find("query") != std::string::npos && cmdline.find("putty") != std::string::npos)
// 	{
// 		std::stringstream ss;

//         	ss << "[" << process_event.entry.file_path << " " << process_event.entry.name << ")] Possibly malicious";
//         	rule_event.metadata = ss.str();

//         	return true;
// 	}

// 	return false;
// }

// T1556.002 - Modify Authentication Process: Password Filter DLL
//  select * from win_process_events where cmdline like '%reg%' and cmdline like '%export%' and cmdline '%lsa%';

bool install_and_register_paassword_filter_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("reg") != std::string::npos && cmdline.find("export") != std::string::npos && cmdline.find("lsa") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Malicious password filters registered to DLLs for acquiring user credentials";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.006 - Unsecured Credentials: Group Policy Preferences
//  select * from win_process_events where cmdline like '%findstr%' and (cmdline like '%cpassword%' or cmdline '%sysvol%');

bool unsecured_credentials_gpp_passwords(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("findstr") != std::string::npos && (cmdline.find("cpassword") != std::string::npos || cmdline.find("sysvol") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Unsecured credentials found in Group Policy Preferences";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - OS Credential Dumping: LSASS Memory
//  select * from win_process_events where cmdline like '%lsass%' and cmdline like '%.dmp%';

bool lsass_memory_using_comsvcs_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("lsass") != std::string::npos && cmdline.find(".dmp") != std::string::npos)
    {
        std::stringstream ss;

        ss << "lsass.exe used for accessing credential material";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1110.003 - Brute Force: Password Spraying
//  select * from win_process_events where path like '%powershell.exe%' and cmdline like '%passwordspray%' and cmdline '%kerbrute%';

bool password_spraying_kurbute(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("powershell.exe") != std::string::npos && cmdline.find("passwordspray") != std::string::npos && process_event.entry.cmdline.find("kerbrute") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Password spraying done for account access";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1056.004 - Input Capture: Credential API Hooking
//  select * from win_process_events where cmdline like '%mavinject%' and cmdline like '%.dll%';

bool input_capture_credential_api_hooking(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("mavinject") != std::string::npos && cmdline.find(".dll") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Windows API used for credential access";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.006 - OS Credential Dumping: DCSync
//  select * from win_process_events where cmdline like '%mimikatz%' and cmdline like '%lsadump%';

bool os_credential_dumping_dcsync(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("mimikatz") != std::string::npos && cmdline.find("lsadump") != std::string::npos && cmdline.find("dcsync") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Attempt to access credentials using Windows Domain Controller's application";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1555.004 - Credentials from Password Stores: Windows Credential Manager
//  select * from win_process_events where path like '%VaultCmd.exe%' and cmdline like '%vaultcmd%';

bool password_stores_windows_credentail_manager(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("VaultCmd.exe") != std::string::npos && cmdline.find("vaultcmd") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Attempt to access credentials from the Windows Credential Manager";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003 - OS Credential Dumping
//  select * from win_process_events where (cmdline like '%rundll32.exe%' and cmdline like '%keymgr%' and cmdline like '%KRShowKeyMgr%') or (cmdline like '%Copy-Item%' and cmdline like '%NPPSPY.dll%');

bool os_credential_dumping(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("rundll32.exe") != std::string::npos && cmdline.find("keymgr") != std::string::npos && cmdline.find("KRShowKeyMgr") != std::string::npos) || (cmdline.find("Copy-Item") != std::string::npos && cmdline.find("NPPSPY.dll") != std::string::npos))

    {
        std::stringstream ss;

        ss << "Attempt to dump credentials for obtaining login credentials";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1187 - Forced Authentication
//  select * from win_process_events where (cmdline like '%PetiPotam.exe%' and cmdline like '%Write-Host%') or (cmdline like '%impersonate%' and cmdline like '%restore%');

bool forced_authentication(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("PetiPotam.exe") != std::string::npos && cmdline.find("Write-Host") != std::string::npos) || (cmdline.find("impersonate") != std::string::npos && cmdline.find("restore") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Credential material for authentication gathered by force";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
//  select * from win_process_events where cmdline like '%Invoke-Rubeus%' and cmdline like '%kerberoast%';

bool kerberoasting_steal_or_forge_Kerberos_tickets(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Invoke-Rubeus") != std::string::npos && cmdline.find("kerberoast") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Valid Kerberos ticket-granting ticket abused";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003 - OS Credential Dumping: Security Account Manager, esentutl.exe SAM copy

bool os_credential_dumping_esentutl(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (process_event.entry.path.find("esentutl.exe") != std::string::npos && cmdline.find("esentutl.exe") != std::string::npos && cmdline.find("SAM") != std::string::npos)

    {
        std::stringstream ss;

        ss << "SAM Hive copied using esentutl.exe utility";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// Credential Access Rules

// T1555.003 - Simulating access to Browser Login Data
// select * from win_process_events where cmdline like '%powershell.exe%' and (cmdline like '%\Opera Software\Opera Stable\Login Data%' or cmdline like '%\Mozilla\Firefox\Profiles%' or cmdline like '%\Microsoft\Edge\User Data\Default%' or cmdline like '%\Google\Chrome\User Data\Default\Login Data%' or cmdline like '%\Google\Chrome\User Data\Default\Login Data For Account%');

bool access_to_browser_login_data(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("\\Opera Software\\Opera Stable\\Login Data") != std::string::npos || cmdline.find("\\Mozilla\\Firefox\\Profiles") != std::string::npos || cmdline.find("\\Microsoft\\Edge\\User Data\\Default") != std::string::npos || cmdline.find("\\Google\\Chrome\\User Data\\Default\\Login Data") != std::string::npos || cmdline.find("\\Google\\Chrome\\User Data\\Default\\Login Data For Account") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Browser login data accessed";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1556.002 - Powershell Install a DLL in System Directory
// select * from win_process_events where cmdline like '%powershell.exe%' and (cmdline like '%Copy-Item%' and cmdline like '%-Destination%') and (cmdline like '%\Windows\System32%' or cmdline like '%\Windows\SysWOW64%'));

bool powershell_install_a_DLL_in_system_directory(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Copy-Item") != std::string::npos && cmdline.find("-Destination") != std::string::npos) && (cmdline.find("\\Windows\\System32") != std::string::npos || cmdline.find("\\Windows\\SysWOW64") != std::string::npos))
    {
        std::stringstream ss;

        ss << "DLL file installed in system directory";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.003 - Create Volume Shadow Copy with Powershell
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%win32_shadowcopy%' and cmdline like '%).Create(%' and cmdline like '%ClientAccessible%');

bool create_volume_shadow_copy_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("gwmi") != std::string::npos && cmdline.find("win32_shadowcopy") != std::string::npos && cmdline.find(").Create(") != std::string::npos && cmdline.find("ClientAccessible") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Volume shadow copy has been created";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1555 - Dump Credentials from Windows Credential Manager With PowerShell
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%GetCredmanCreds%' or cmdline like '%Get-PasswordVaultCredentials%'));

bool dump_credentials_from_windows_credential_manager_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("GetCredmanCreds") != std::string::npos || cmdline.find("Get-CredmanCreds") != std::string::npos || cmdline.find("Get-PasswordVaultCredentials") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Credentials have been extracted with powershell";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.004 - Certificate Exported Via PowerShell - ScriptBlock
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%Export-PfxCertificate%' or cmdline like '%Export-Certificate%'));

bool certificate_exported_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("Export-PfxCertificate") != std::string::npos || cmdline.find("Export-Certificate") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Certificates have been exported via PowerShell";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.006 - Suspicious Get-ADReplAccount
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%Get-ADReplAccount%' and cmdline like '%-All%' and cmdline like '%-Server%');

bool suspicious_get_ADReplAccount(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("Get-ADReplAccount") != std::string::npos && cmdline.find("-All") != std::string::npos && cmdline.find("-Server") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Domain and credentials have been compromised";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1558.003 - Request A Single Ticket via PowerShell
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%New-Object%' and cmdline like '%System.IdentityModel.Tokens.KerberosRequestorSecurityToken%');

bool request_a_single_ticket_via_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("New-Object") != std::string::npos && cmdline.find("System.IdentityModel.Tokens.KerberosRequestorSecurityToken") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Native PowerShell Identity modules utilized to query the domain to extract the Service Principal Names for a single computer";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - PowerShell Get-Process LSASS in ScriptBlock
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%-u%' and cmdline like '%-f%' and cmdline like '%Get-Process lsass%');

bool powershell_get_process_LSASS_in_scriptblock(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("-u") != std::string::npos && cmdline.find("-f") != std::string::npos && cmdline.find("Get-Process lsass") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Credential material stored in the process memory of LSASS might be exposed";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1110.001 - Suspicious Connection to Remote Account
// select * from win_process_events where (cmdline like '%powershell.exe%' and (cmdline like '%System.DirectoryServices.Protocols.LdapDirectoryIdentifier%' or cmdline like '%System.DirectoryServices.Protocols%' or cmdline like '%System.Net.NetworkCredential%' or cmdline like '%System.DirectoryServices.Protocols.LdapConnection%'));

bool suspicious_connection_to_remote_account(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && (cmdline.find("System.DirectoryServices.Protocols.LdapDirectoryIdentifier") != std::string::npos || cmdline.find("System.DirectoryServices.Protocols") != std::string::npos || cmdline.find("System.Net.NetworkCredential") != std::string::npos || cmdline.find("System.DirectoryServices.Protocols.LdapConnection") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Passwords might be guessed using an iterative manner";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - Credential Dumping by LaZagne
// select * from win_process_events where (cmdline like '%cmd.exe%' and cmdline like '%lsass.exe%' and cmdline like '%C:/Windows/System32/KERNELBASE.dll%' and cmdline like '%C:/Windows/SYSTEM32/ntdll.dll%');

bool credential_dumping_by_laZagne(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("cmd.exe") != std::string::npos && cmdline.find("lsass.exe") != std::string::npos && cmdline.find("C:/Windows/System32/KERNELBASE.dll") != std::string::npos && cmdline.find("C:/Windows/SYSTEM32/ntdll.dll") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Credential Dumping by LaZagne";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - Lsass Memory Dump via Comsvcs DLL
// select * from win_process_events where (cmdline like '%powershell.exe%' and cmdline like '%lsass.exe%' and cmdline like '%C:/Windows/System32/KERNELBASE.dll%' and cmdline like '%C:/Windows/SYSTEM32/ntdll.dll%');

bool lsass_memory_dump_via_comsvcs_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("powershell.exe") != std::string::npos && cmdline.find("lsass.exe") != std::string::npos && cmdline.find("rundll32.exe") != std::string::npos && cmdline.find("comsvcs.dll") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Lsass Memory Dump via Comsvcs DLL";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.003 - Suspicious Get-ADDBAccount Usage
// select * from win_process_events where (cmdline like '%Get-ADDBAccount%' and cmdline like '%BootKey%' and cmdline like '%DatabasePath%');

bool suspicious_get_ADDBAccount_usage(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Get-ADDBAccount") != std::string::npos && cmdline.find("BootKey") != std::string::npos && cmdline.find("DatabasePath") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Suspicious Get-ADDBAccount Usage"; // Review message!
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1555 - Enumerate Credentials from Windows Credential Manager With PowerShell
// select * from win_process_events where (cmdline like '%vaultcmd%' and cmdline like '%/listcreds:%') and (cmdline like '%Windows Credentials%' or cmdline like '%Web Credentials%'));

bool enumerate_credentials_from_windows_credential_manager_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("vaultcmd") != std::string::npos && cmdline.find("/listcreds:") != std::string::npos) && (cmdline.find("Windows Credentials") != std::string::npos || cmdline.find("Web Credentials") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Extraction of windows or web credentials present in the system";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003 - Live Memory Dump Using Powershell
// select * from win_process_events where cmdline like '%Get-StorageDiagnosticInfo%' and cmdline like '%-IncludeLiveDump%';

bool live_memory_dump_using_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Get-StorageDiagnosticInfo") != std::string::npos && cmdline.find("-IncludeLiveDump") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Live memory of machine is accessed";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003 - Potential Invoke-Mimikatz PowerShell Script
// select * from win_process_events where cmdline like '%Invoke-Mimikatz%' and (cmdline like '%-DumpCreds%' or cmdline like '%-DumpCerts%');

bool potential_invoke_mimikatz_powershell_script(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("Invoke-Mimikatz") != std::string::npos && (cmdline.find("-DumpCreds") != std::string::npos || cmdline.find("-DumpCerts") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Windows account logins and passwords extracted using Mimikatz";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.001 - Extracting Information with PowerShell
// select * from win_process_events where cmdline like '%ls%' and cmdline like '%-R%' or cmdline like '%select-string%' and cmdline like '%-Pattern%';

bool extracting_information_with_powershell(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("ls") != std::string::npos && cmdline.find("-R") != std::string::npos && cmdline.find("select-string") != std::string::npos && cmdline.find("-Pattern") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Information like credentials might be accessed through PowerShell.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.001 - HackTool - Inveigh Execution

bool hacktool_inveigh_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("-SpooferIP") != std::string::npos && (cmdline.find("-SpooferIP") != std::string::npos || cmdline.find("-ReplyToIPs") != std::string::npos || cmdline.find("-ReplyToDomains") != std::string::npos || cmdline.find("-ReplyToMACs") != std::string::npos || cmdline.find("-SnifferIP") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Inveigh execution detected. (a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool)";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - Process Memory Dump via RdrLeakDiag.EXE
// select * from win_process_events where (path like '%\rgrleakdiag.exe%' and (cmdline like '%fullmemdmp%' or cmdline like '%/memdmp%' or cmdline like '%-memdmp%')) or ((cmdline like '%fullmemdmp%' or cmdline like '%/memdmp%' or cmdline like '%-memdmp%') and (cmdline like '% -o %' or cmdline like '% /o %') and (cmdline like '% -p %' or cmdline like '% /p %'));

bool process_memory_dump_via_rdrleakdiag(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\rgrleakdiag.exe") != std::string::npos && (cmdline.find("fullmemdmp") != std::string::npos || cmdline.find("/memdmp") != std::string::npos || cmdline.find("-memdmp") != std::string::npos)) || ((cmdline.find("fullmemdmp") != std::string::npos || cmdline.find("/memdmp") != std::string::npos || cmdline.find("-memdmp") != std::string::npos) && (cmdline.find(" -o ") != std::string::npos || cmdline.find(" /o ") != std::string::npos) && (cmdline.find(" -p ") != std::string::npos || cmdline.find(" /p ") != std::string::npos)))
    {
        std::stringstream ss;

        ss << "Detected use of RdrLeakDiag to dump process memory";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1555.003 - Potential Browser Data Stealing
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%copy-item%' AND cmdline LIKE '%copy%' AND cmdline LIKE '%cpi%' AND cmdline LIKE '%move%' AND cmdline LIKE '%move-item%') AND (path LIKE '%\\xcopy.exe%' OR path LIKE '%\\robocopy.exe%');

bool potential_browser_data_stealing(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("copy-item") != std::string::npos && cmdline.find("copy") != std::string::npos && cmdline.find("cpi") != std::string::npos && cmdline.find("move") != std::string::npos && cmdline.find("move-item") != std::string::npos) && (path.find("\\xcopy.exe") != std::string::npos || path.find("\\robocopy.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Browser data might be accessed, including credentials and passwords!";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.001 - Extracting Information with PowerShell
// SELECT * FROM win_process_events WHERE cmdline LIKE '%lsass%' AND cmdline LIKE '%.dmp%' AND cmdline LIKE '%SQLDmpr%' AND cmdline LIKE '%.mdmp%' AND cmdline LIKE '%nanodump%';

bool lsass_dump_keyword_in_commandLine(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("lsass") != std::string::npos && cmdline.find(".dmp") != std::string::npos && cmdline.find("SQLDmpr") != std::string::npos && cmdline.find(".mdmp") != std::string::npos && cmdline.find("nanodump") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected a potential attempt to dump or create a dump of the lsass process";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1556.002 - Dropping Of Password Filter DLL
// SELECT * FROM win_process_events WHERE cmdline LIKE '%HKLM\SYSTEM\CurrentControlSet\Control\Lsa%' AND cmdline LIKE '%scecli\0*%' AND cmdline LIKE '%reg add%';

bool dropping_of_password_filter_dll(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa") != std::string::npos && cmdline.find("scecli\\0*") != std::string::npos && cmdline.find("reg add") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected dropping of dll files to retrieve user credentials";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1558.003 - Hacktool - KrbRelay Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%-spn%' AND cmdline LIKE '%-clsid%' AND cmdline LIKE '%-rbcd%' AND cmdline LIKE '%shadowcred%' AND cmdline LIKE '%spn%' AND cmdline LIKE '%session%';

bool hacktool_krbrelay_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\KrbRelay.exe") != std::string::npos) && (cmdline.find("-spn") != std::string::npos && cmdline.find("-clsid") != std::string::npos && cmdline.find("-rbcd") != std::string::npos && cmdline.find("shadowcred") != std::string::npos && cmdline.find("spn") != std::string::npos && cmdline.find("session") != std::string::npos))
    {
        std::stringstream ss;

        ss << "KrbRelay Detected !";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1558.003 - Hacktool - KrbRelayUp Execution
// SELECT * FROM win_process_events WHERE cmdline LIKE '%relay%' AND cmdline LIKE '%-Domain%' AND cmdline LIKE '%-ComputerName%' AND cmdline LIKE '%krbscm%' AND cmdline LIKE '%-sc%' AND cmdline LIKE '%spawn%' AND cmdline LIKE '%-d%' AND cmdline LIKE '%-cn%' AND cmdline LIKE '%-cp%';

bool hacktool_krbrelayup_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\KrbRelayUp.exe") != std::string::npos) && (cmdline.find("relay") != std::string::npos && cmdline.find("-Domain") != std::string::npos && cmdline.find("-ComputerName") != std::string::npos && cmdline.find("krbscm") != std::string::npos && cmdline.find("-sc") != std::string::npos && cmdline.find("spawn") != std::string::npos && cmdline.find("-d") != std::string::npos && cmdline.find("-cn") != std::string::npos && cmdline.find("-cp") != std::string::npos))
    {
        std::stringstream ss;

        ss << "KrbRelayUp Detected !";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - Hacktool - Mimikatz Execution

bool hacktool_mimikatz_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("DumpCreds") != std::string::npos || cmdline.find("mimikatz") != std::string::npos || cmdline.find("::aadcookie") != std::string::npos || cmdline.find("::detours") != std::string::npos || cmdline.find("::memssp") != std::string::npos || cmdline.find("::mflt") != std::string::npos || cmdline.find("::ncroutemon") != std::string::npos || cmdline.find("::ngcsign") != std::string::npos || cmdline.find("::printnightmare") != std::string::npos || cmdline.find("::skeleton") != std::string::npos || cmdline.find("::preshutdown") != std::string::npos || cmdline.find("::mstsc") != std::string::npos || cmdline.find("::multirdp") != std::string::npos || cmdline.find("rpc::") != std::string::npos || cmdline.find("token::") != std::string::npos || cmdline.find("crypto::") != std::string::npos || cmdline.find("dpapi::") != std::string::npos || cmdline.find("sekurlsa::") != std::string::npos || cmdline.find("kerberos::") != std::string::npos || cmdline.find("lsadump::") != std::string::npos || cmdline.find("privilege::") != std::string::npos || cmdline.find("process::") != std::string::npos || cmdline.find("vault::") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Mimikatz command line arguments detected !";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.001 - Hacktool - Mimikatz Execution

bool hacktool_pypykatz_credential_dumping_activity(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\python.exe") != std::string::npos || path.find("\\pypykatz.exe") != std::string::npos) && (cmdline.find("live") != std::string::npos && cmdline.find("registry") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Use of Pypykatz (to obtain stored credentials) detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.002 - Enumeration for Credentials in Registry
// SELECT * FROM win_process_events WHERE (path LIKE '%\reg.exe%' AND (cmdline LIKE '% query %' AND cmdline LIKE '%/t %' AND cmdline LIKE '%REG_SZ%' AND cmdline LIKE '%/s%')) AND ((cmdline LIKE '%/f %' AND (cmdline LIKE '%HKLM%' OR cmdline LIKE '%HKCU%')) OR cmdline LIKE '%HKCU\Software\SimonTatham\PuTTY\Sessions%');

bool enumeration_for_insecure_credentials_in_registry(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\reg.exe") != std::string::npos && (cmdline.find(" query ") != std::string::npos && cmdline.find("/t ") != std::string::npos && cmdline.find("REG_SZ") != std::string::npos && cmdline.find("/s") != std::string::npos)) && ((cmdline.find("/f ") != std::string::npos && (cmdline.find("HKLM") != std::string::npos || cmdline.find("HKCU") != std::string::npos)) || cmdline.find("HKCU\\Software\\SimonTatham\\PuTTY\\Sessions") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected querying of Registry by adversaries to look for insecurely stored credentials";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003 - Suspicious Reg Add Open Command
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%reg%' AND cmdline LIKE '%add%' AND cmdline LIKE '%hkcu\software\classes\ms-settings\shell\open\command%' AND cmdline LIKE '%/ve %' AND cmdline LIKE '%/d%') OR (cmdline LIKE '%reg%' AND cmdline LIKE '%add%' AND cmdline LIKE '%hkcu\software\classes\ms-settings\shell\open\command%' AND cmdline LIKE '%/v%' AND cmdline LIKE '%DelegateExecute%') OR (cmdline LIKE '%reg%' AND cmdline LIKE '%delete%' AND cmdline LIKE '%hkcu\software\classes\ms-settings%');

bool suspicious_reg_add_open_command(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("hkcu\\software\\classes\\ms-settings\\shell\\open\\command") != std::string::npos && cmdline.find("/ve ") != std::string::npos && cmdline.find("/d") != std::string::npos) || (cmdline.find("reg") != std::string::npos && cmdline.find("add") != std::string::npos && cmdline.find("hkcu\\software\\classes\\ms-settings\\shell\\open\\command") != std::string::npos && cmdline.find("/v") != std::string::npos && cmdline.find("DelegateExecute") != std::string::npos) || (cmdline.find("reg") != std::string::npos && cmdline.find("delete") != std::string::npos && cmdline.find("hkcu\\software\\classes\\ms-settings") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected dumping of SAM, SECURITY and SYSTEM registry hives";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.003 - Suspicious Process Patterns NTDS.DIT Exfil
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%\\NTDSDump.exe%' OR cmdline LIKE '%\\NTDSDumpEx.exe%') AND cmdline LIKE '%ntds.dit%' AND cmdline LIKE '%system.hiv%' AND cmdline LIKE '%NTDSgrab.ps1%');

bool suspicious_process_patterns_NTDS_DIT_exfil(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("\\NTDSDump.exe") != std::string::npos || cmdline.find("\\NTDSDumpEx.exe") != std::string::npos) && cmdline.find("ntds.dit") != std::string::npos && cmdline.find("system.hiv") != std::string::npos && cmdline.find("NTDSgrab.ps1") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Suspicious Process Patterns NTDS.DIT Exfil"; // To be reviewed
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.003 - Suspicious Process Patterns NTDS.DIT Exfil
// SELECT * FROM win_process_events WHERE ((cmdline LIKE '%\\NTDSDump.exe%' OR cmdline LIKE '%\\NTDSDumpEx.exe%') AND cmdline LIKE '%ntds.dit%' AND cmdline LIKE '%system.hiv%' AND cmdline LIKE '%NTDSgrab.ps1%');

bool suspicious_office_token_search_via_CLI(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("eyJ0eXAiOi") != std::string::npos || cmdline.find(" eyJ0eX") != std::string::npos || cmdline.find("'eyJ0eX'") != std::string::npos || cmdline.find("\"eyJ0eX\"") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detects possible search for office tokens via CLI by looking for the string 'eyJ0eX'";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.002 - HackTool - Quarks PwDump Execution

bool hacktool_quarks_pwdump_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\QuarksPwDump.exe") != std::string::npos) && (cmdline.find("-dhl") != std::string::npos || cmdline.find("--dump-hash-local") != std::string::npos || cmdline.find("-dhdc") != std::string::npos || cmdline.find("--dump-hash-domain-cached") != std::string::npos || cmdline.find("--dump-bitlocker") != std::string::npos || cmdline.find("-dhd") != std::string::npos || cmdline.find("--dump-hash-domain") != std::string::npos || cmdline.find("--ntds-file") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Quarks PwDump tool usage detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.006 - Suspicious SYSVOL Domain Group Policy Access
// SELECT * FROM win_process_events WHERE cmdline LIKE '%SYSVOL%' AND cmdline LIKE '%policies%';

bool suspicious_SYSVOL_domain_group_policy_access(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("SYSVOL") != std::string::npos && cmdline.find("policies") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected Access to Domain Group Policies stored in SYSVOL"; // To be reviewed
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1552.001 - Active Directory Database Snapshot Via ADExplorer
// SELECT * FROM win_process_events WHERE path LIKE '%\\ADExplorer.exe%' AND cmdline LIKE '%snapshot%';

bool active_directory_database_snapshot_via_ADExplorer(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\ADExplorer.exe") != std::string::npos && cmdline.find("snapshot") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the execution of Sysinternals ADExplorer with the '-snapshot' flag in order to save a local copy of the active directory database."; // To be reviewed
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003 - Hacktool - Rubeus Execution

bool hacktool_rubeus_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\Rubeus.exe") != std::string::npos) && cmdline.find("asreproast") != std::string::npos && cmdline.find("dump /service:krbtgt") != std::string::npos && cmdline.find("dump /luid:0x") != std::string::npos && cmdline.find("kerberoast") != std::string::npos && cmdline.find("createnetonly /program:") != std::string::npos && cmdline.find("ptt /ticket:") != std::string::npos && cmdline.find("/impersonateuser:") != std::string::npos && cmdline.find("renew /ticket:") != std::string::npos && cmdline.find("asktgt /user:") != std::string::npos && cmdline.find("harvest /interval:") != std::string::npos && cmdline.find("s4u /user:") != std::string::npos && cmdline.find("s4u /ticket:") != std::string::npos && cmdline.find("hash /password:") != std::string::npos && cmdline.find("golden /aes256:") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Execution of the hacktool Rubeus via PE information of command line parameters";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.002 - Enumeration for 3rd Party Creds From CLI
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\Software\SimonTatham\PuTTY\Sessions%' OR cmdline LIKE '%\Software\\SimonTatham\PuTTY\SshHostKeys\%' OR cmdline LIKE '%\Software\Mobatek\MobaXterm\%' OR cmdline LIKE '%\Software\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin%' OR cmdline LIKE '%\Software\Aerofox\FoxmailPreview%' OR cmdline LIKE '%\Software\Aerofox\Foxmail\V3.1%' OR cmdline LIKE '%\Software\IncrediMail\Identities%' OR cmdline LIKE '%\Software\Qualcomm\Eudora\CommandLine%' OR cmdline LIKE '%\Software\RimArts\B2\Settings%' OR cmdline LIKE '%\Software\OpenVPN-GUI\configs%' OR cmdline LIKE '%\Software\Martin Prikryl\WinSCP 2\Sessions%' OR cmdline LIKE '%\Software\FTPWare\COREFTP\Sites%' OR cmdline LIKE '%\Software\DownloadManager\Passwords%' OR cmdline LIKE '%\Software\OpenSSH\Agent\Keys%' OR cmdline LIKE '%\Software\TightVNC\Server%' OR cmdline LIKE '%\Software\ORL\WinVNC3\Password%' OR cmdline LIKE '%\Software\RealVNC\WinVNC4%';

bool enumeration_for_third_party_creds_from_cli(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\Software\\SimonTatham\\PuTTY\\Sessions") != std::string::npos || cmdline.find("\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\") != std::string::npos || cmdline.find("\\Software\\Mobatek\\MobaXterm\\") != std::string::npos || cmdline.find("\\Software\\WOW6432Node\\Radmin\v3.0\\Server\\Parameters\\Radmin") != std::string::npos || cmdline.find("\\Software\\Aerofox\\FoxmailPreview") != std::string::npos || cmdline.find("\\Software\\Aerofox\\Foxmail\\V3.1") != std::string::npos || cmdline.find("\\Software\\IncrediMail\\Identities") != std::string::npos || cmdline.find("\\Software\\Qualcomm\\Eudora\\CommandLine") != std::string::npos || cmdline.find("\\Software\\RimArts\\B2\\Settings") != std::string::npos || cmdline.find("\\Software\\OpenVPN-GUI\\configs") != std::string::npos || cmdline.find("\\Software\\Martin Prikryl\\WinSCP 2\\Sessions") != std::string::npos || cmdline.find("\\Software\\FTPWare\\COREFTP\\Sites") != std::string::npos || cmdline.find("\\Software\\DownloadManager\\Passwords") != std::string::npos || cmdline.find("\\Software\\OpenSSH\\Agent\\Keys") != std::string::npos || cmdline.find("\\Software\\TightVNC\\Server") != std::string::npos || cmdline.find("\\Software\\ORL\\WinVNC3\\Password") != std::string::npos || cmdline.find("\\Software\\RealVNC\\WinVNC4") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected processes that query known 3rd party registry keys"; // To be reviewed
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003 - Potential Credential Dumping Attempt Using New NetworkProvider - CLI
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\System\CurrentControlSet\Services\%' AND cmdline LIKE '%\NetworkProvider%';

bool potential_credential_dumping_attempt_using_new_networkprovider_cli(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if (cmdline.find("\\System\\CurrentControlSet\\Services\\") != std::string::npos && cmdline.find("\\NetworkProvider") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected an attacker trying to add a new network provider in order to dump clear text credentials"; // To be reviewed
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1528 - Suspicious Command With Teams Objects Paths
// SELECT * FROM win_process_events WHERE cmdline LIKE '%\\Teams%' AND (cmdline LIKE '%\\Cookies%' OR cmdline LIKE '%\\leveldb%' OR cmdline LIKE '%\\current%');

bool suspicious_command_with_teams_objects_paths(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((cmdline.find("\\Microsoft\\Teams\\Cookies") != std::string::npos || cmdline.find("\\Microsoft\\Teams\\Local Storage\\leveldb") != std::string::npos) && !(path.find("\\Microsoft\\Teams\\current\\Teams.exe") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Detected an access to authentication tokens and accounts of Microsoft Teams desktop application."; // To be reviewed
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1040 - Potential Network Sniffing Activity Using Network Tools
// SELECT * FROM win_process_events WHERE (path LIKE '%\\tshark.exe%' AND path LIKE '%\\windump.exe%' AND cmdline LIKE '%-i%');

bool potential_network_sniffing_activity_using_network_tools(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\tshark.exe") != std::string::npos && path.find("\\windump.exe") != std::string::npos && cmdline.find("-i") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Potential Network Sniffing Activity Using Network Tools";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1003.003 - Suspicious Usage Of Active Directory Diagnostic Tool
// SELECT * FROM win_process_events WHERE (path LIKE '%\\ntdsutil.exe%' AND cmdline LIKE '%snapshot%' AND (cmdline LIKE '%mount%' AND cmdline LIKE '%ac%' AND cmdline LIKE '% i%' AND cmdline LIKE '% ntds%'));

bool suspicious_usage_of_active_directory_diagnostic_tool(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\ntdsutil.exe") != std::string::npos && cmdline.find("snapshot") != std::string::npos && (cmdline.find("mount") != std::string::npos && cmdline.find("ac") != std::string::npos && cmdline.find(" i") != std::string::npos && cmdline.find(" ntds") != std::string::npos))
    {
        std::stringstream ss;

        ss << "Suspicious Usage Of Active Directory Diagnostic Tool";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

bool hacktool_windows_credential_editor_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;
    if (parent_path.find("\\services.exe") != std::string::npos && cmdline.find(".exe -S") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of Windows Credential Editor detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.003 - Invocation of Active Directory Diagnostic Tool
// SELECT * FROM win_process_events WHERE path LIKE '%\\ntdsutil.exe%';

bool invocation_of_active_directory_diagnostic_tool(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("\\ntdsutil.exe") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Invocation of Active Directory Diagnostic Tool";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1555.004 - Windows Credential Manager Access via VaultCmd
// SELECT * FROM win_process_events WHERE (cmdline LIKE '%VaultCmd.exe%' OR cmdline LIKE '%VAULTCMD.EXE%' OR cmdline LIKE '%vaultcmd%') AND cmdline LIKE '%/listcreds%');

bool windows_credential_manager_access_via_vaultCmd(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;

    if ((cmdline.find("VaultCmd.exe") != std::string::npos || cmdline.find("VAULTCMD.EXE") != std::string::npos || cmdline.find("vaultcmd") != std::string::npos) && cmdline.find("/listcreds") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Invocation of Active Directory Diagnostic Tool";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

bool microsoft_iis_service_account_password_dumped(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\appcmd.exe") != std::string::npos) && (cmdline.find("list") != std::string::npos || cmdline.find("/config") != std::string::npos || cmdline.find("/xml") != std::string::npos || cmdline.find("-xml") != std::string::npos || cmdline.find("/@t") != std::string::npos || cmdline.find("/text") != std::string::npos || cmdline.find("/show") != std::string::npos || cmdline.find("-@t") != std::string::npos || cmdline.find("-text") != std::string::npos || cmdline.find("-show") != std::string::npos || cmdline.find(":\\*") != std::string::npos || cmdline.find("password") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Internet Information Services (IIS) command-line tool AppCmd being used to list passwords detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003 - Capture Credentials with Rpcping.exe
// SELECT * FROM win_process_events WHERE path LIKE '%\rpcping.exe%' AND (cmdline LIKE '%-s%' OR cmdline LIKE '%/s%') AND ((cmdline LIKE '%-u%' AND cmdline LIKE '%NTLM%') OR (cmdline LIKE '%/u%' AND cmdline LIKE '%NTLM%') OR (cmdline LIKE '%-t%' AND cmdline LIKE '%ncacn_np%') OR (cmdline LIKE '%/t%' AND cmdline LIKE '%ncacn_np%'));

bool capture_credentials_with_rpcpingexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rpcping.exe") != std::string::npos && (cmdline.find("-s") != std::string::npos || cmdline.find("/s") != std::string::npos) && ((cmdline.find("-u") != std::string::npos && cmdline.find("NTLM") != std::string::npos) || (cmdline.find("/u") != std::string::npos && cmdline.find("NTLM") != std::string::npos) || (cmdline.find("-t") != std::string::npos && cmdline.find("ncacn_np") != std::string::npos) || (cmdline.find("/t") != std::string::npos && cmdline.find("ncacn_np") != std::string::npos)))
    {
        std::stringstream ss;

        ss << "Detected use of Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

// T1555.004 - Suspicious Key Manager Access
// SELECT * FROM win_process_events WHERE path LIKE '%\rundll32.exe%' AND cmdline LIKE '%keymgr%' AND cmdline LIKE '%KRShowKeyMgr%';

bool suspicious_key_manager_access(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\rundll32.exe") != std::string::npos && cmdline.find("keymgr") != std::string::npos && cmdline.find("KRShowKeyMgr") != std::string::npos)
    {
        std::stringstream ss;

        ss << "Detected the invocation of the Stored User Names and Passwords dialogue";
        rule_event.metadata = ss.str();

        return true;
    }

    return false;
}

bool microsoft_iis_connection_strings_decryption(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("\\aspnet_regiis.exe") != std::string::npos) && cmdline.find("connectionStrings") != std::string::npos && cmdline.find("-pdf") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Use of aspnet_regiis to decrypt Microsoft IIS connection strings detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

bool suspicious_dump64_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\dump64.exe") != std::string::npos && !(path.find("\\Installer\\Feedback\\dump64.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "User trying to bypass Defender by renaming a tool to dump64.exe and trying to place in a Visual Studio Folder";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.001 - Dumping Process Via Sqldumper.exe
// SELECT * FROM win_process_events WHERE
//     path LIKE '%\\sqldumper.exe%' AND
//     (cmdline LIKE '%0x0110%' OR cmdline LIKE '%0x01100:40%');
bool dumping_process_via_sqldumperexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\sqldumper.exe") != std::string::npos && (cmdline.find("0x0110") != std::string::npos || cmdline.find("0x01100:40") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Process dump via legitimate sqldumper.exe binary detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003 - Potential Credential Dumping Via LSASS Process Clone
// SELECT * FROM win_process_events WHERE
//     path LIKE '%\\Windows\\System32\\lsass.exe%' AND
//     parent_path LIKE '%\\Windows\\System32\\lsass.exe%';
bool potential_credential_dumping_via_lsass_process_clone(const ProcessEvent &process_event, Event &rule_event)
{
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;
    if (path.find("\\Windows\\System32\\lsass.exe") != std::string::npos && (parent_path.find("\\Windows\\System32\\lsass.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Suspicious LSASS process process clone detected !";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.004 - Certificate Exported Via PowerShell
// select * from win_process_events where
//(cmdline like '%Export-PfxCertificate%' or
// cmdline like '%Export-Certificate%');

// bool certificate_exported_via_powershell(const ProcessEvent &process_event, Event &rule_event)
// {
//     std::string cmdline = process_event.entry.cmdline;
//     if (cmdline.find("Export-PfxCertificate ") != std::string::npos ||
//     cmdline.find("Export-Certificate ") != std::string::npos)
//     {
//         std::stringstream ss;
//         ss << "Certificate Exported Via PowerShell";
//         rule_event.metadata = ss.str();
//         return true;
//     }
//     return false;
// }

// T1552.004 - PowerShell Get-Process LSASS
// select * from win_process_events where
// cmdline like '%Get-Process lsas%' or
// cmdline like '%ps lsas%' or
// cmdline like '%gps lsas%';

bool powershell_get_process_lsass(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Get-Process lsas") != std::string::npos ||
        cmdline.find("ps lsas") != std::string::npos ||
        cmdline.find("gps lsas") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell Get-Process LSASS";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.002 - PowerShell SAM Copy
// SELECT * FROM win_process_events WHERE
//(cmdline LIKE '%Copy-Item%' OR
// cmdline LIKE '%.File]::Copy(%' OR
// cmdline LIKE '%copy $_.%' OR
// cmdline LIKE '%cpi $_.%' OR
// cmdline LIKE '%cp $_.%') AND
// cmdline LIKE '%\\HarddiskVolumeShadowCopy%' AND
// cmdline LIKE '%System32\\config\\sam%';

bool powershell_sam_copy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("Copy-Item") != std::string::npos ||
         cmdline.find(".File]::Copy(") != std::string::npos ||
         cmdline.find("copy $_.") != std::string::npos ||
         cmdline.find("cpi $_.") != std::string::npos ||
         cmdline.find("cp $_.") != std::string::npos) &&
        cmdline.find("\\HarddiskVolumeShadowCopy") != std::string::npos &&
        cmdline.find("System32\\config\\sam") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PowerShell SAM Copy";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.001 - Potential Credential Dumping Via WER
// SELECT * FROM win_process_events WHERE path LIKE '%Werfault%' AND (cmdline LIKE '%AUTHORI%' OR cmdline LIKE '%AUTORI%') AND (cmdline LIKE '%-u -p%' AND cmdline LIKE '%-ip%' AND cmdline LIKE '%-s%');

bool potential_credential_dumping_via_WER(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("Werfault") != std::string::npos && (cmdline.find("AUTHORI") != std::string::npos || cmdline.find("AUTORI") != std::string::npos) && (cmdline.find("-u -p") != std::string::npos && cmdline.find("-ip") != std::string::npos && cmdline.find("-s") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected potential credential dumping via Windows Error Reporting LSASS Shtinkering technique.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.003 - PUA - DIT Snapshot Viewer
// select * from win_process_events where
// cmdline like '%ditsnap.exe%';

bool pua_dit_snapshot_viewer(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\ditsnap.exe") != std::string::npos && cmdline.find("ditsnap.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PUA - DIT Snapshot Viewer";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1056.002 - PUA - Mouse Lock Execution
// select * from win_process_events where
// cmdline like '%Mouse Lock_%';

bool pua_mouse_lock_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("Mouse Lock_") != std::string::npos)
    {
        std::stringstream ss;
        ss << "PUA - Mouse Lock Execution";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1555 - Suspicious Serv-U Process Pattern
// SELECT * FROM win_process_events WHERE parent_path LIKE '%\Serv-U.exe%' AND (path LIKE '%\cmd.exe%' OR path LIKE '%\powershell.exe%' OR path LIKE '%\pwsh.exe%' OR path LIKE '%\wscript.exe%' OR path LIKE '%\cscript.exe%' OR path LIKE '%\sh.exe%' OR path LIKE '%\bash.exe%' OR path LIKE '%\schtasks.exe%' OR path LIKE '%\regsvr32.exe%' OR path LIKE '%\wmic.exe%' OR path LIKE '%\mshta.exe%' OR path LIKE '%\rundll32.exe%' OR path LIKE '%\msiexec.exe%' OR path LIKE '%\forfiles.exe%' OR path LIKE '%\scriptrunner.exe%');

bool suspicious_serv_u_process_pattern(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string parent_path = process_event.entry.parent_path;
    std::string path = process_event.entry.path;

    if (parent_path.find("\\Serv-U.exe") != std::string::npos && (path.find("\\cmd.exe") != std::string::npos || path.find("\\powershell.exe") != std::string::npos || path.find("\\pwsh.exe") != std::string::npos || path.find("\\wscript.exe") != std::string::npos || path.find("\\cscript.exe") != std::string::npos || path.find("\\sh.exe") != std::string::npos || path.find("\\bash.exe") != std::string::npos || path.find("\\schtasks.exe") != std::string::npos || path.find("\\regsvr32.exe") != std::string::npos || path.find("\\wmic.exe") != std::string::npos || path.find("\\mshta.exe") != std::string::npos || path.find("\\rundll32.exe") != std::string::npos || path.find("\\msiexec.exe") != std::string::npos || path.find("\\forfiles.exe") != std::string::npos || path.find("\\scriptrunner.exe") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected a suspicious process pattern which could be a sign of an exploited Serv-U service";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1558.003 - Potential SPN Enumeration Via Setspn.EXE
// select * from win_process_events where path like '%\setspn.exe%' and (cmdline like '% -q %' or cmdline like '% /q %');

bool potential_spn_enumeration_via_setspnexe(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if (path.find("\\setspn.exe") != std::string::npos && (cmdline.find(" -q ") != std::string::npos || cmdline.find(" /q ") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected service principal name (SPN) enumeration used for Kerberoasting";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1539 - SQLite Chromium Profile Data DB Access
// select * from win_process_events where (path like '%\sqlite.exe%' or path like '%\sqlite3.exe%') and (cmdline like '%\User Data\%' or cmdline like '%\Opera Software\%' or cmdline like '%\ChromiumViewer\%') and (cmdline like '%Login Data%' or cmdline like '%Cookies%' or cmdline like '%Web Data%' or cmdline like '%History%' or cmdline like '%Bookmarks%');

bool sqlite_chromium_profile_data_db_access(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\sqlite.exe") != std::string::npos || path.find("\\sqlite3.exe") != std::string::npos) && (cmdline.find("\\User Data\\") != std::string::npos || cmdline.find("\\Opera Software\\") != std::string::npos || cmdline.find("\\ChromiumViewer\\") != std::string::npos) && (cmdline.find("Login Data") != std::string::npos || cmdline.find("Cookies") != std::string::npos || cmdline.find("Web Data") != std::string::npos || cmdline.find("History") != std::string::npos || cmdline.find("Bookmarks") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of the 'sqlite' binary to query databases in Chromium-based browsers for potential data stealing.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1539 - SQLite Firefox Profile Data DB Access
// select * from win_process_events where (path like '%\sqlite.exe%' or path like '%\sqlite3.exe%') and (cmdline like '%cookies.sqlite%' or cmdline like '%places.sqlite%');

bool sqlite_firefox_profile_data_db_access(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;

    if ((path.find("\\sqlite.exe") != std::string::npos || path.find("\\sqlite3.exe") != std::string::npos) && (cmdline.find("cookies.sqlite") != std::string::npos || cmdline.find("places.sqlite") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of the 'sqlite' binary to query databases in Firefox and other Gecko-based browsers for potential data stealing.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1555 - HackTool - SecurityXploded Execution
// select * from win_process_events where (path like '%PasswordDump.exe%');

bool hackTool_securityXploded_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string path = process_event.entry.path;

    if (path.find("PasswordDump.exe") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected the execution of SecurityXploded Tools.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1185 - Potential Data Stealing Via Chromium Headless Debugging
//  select * from win_process_events where cmdline like '%--remote-debugging-%' and cmdline like '%--user-data-dir%' and cmdline like '%--headless%';

bool potenital_data_stealing_chromium(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("--remote-debugging-") != std::string::npos && cmdline.find("--user-data-dir") != std::string::npos && cmdline.find("--headless") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Chromium based server started in headless or debugging mode and pointing to user profile";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1185 - Browser Started with Remote Debugging
// select * from win_process_events where cmdline like '% --remote-debugging-%' or (path like '%\\firefox.exe%' and cmdline like '% -start-debugger-server%');

bool browser_started_remote_debugging(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (cmdline.find(" --remote-debugging-") != std::string::npos || (path.find("\\firefox.exe") != std::string::npos && cmdline.find(" -start-debugger-server") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected browser started with remote debugging flags";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1003.005 - New Generic Credentials Added Via Cmdkey.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%cmdkey.exe%' AND cmdline LIKE '% /g%' AND cmdline LIKE '% /u%' AND cmdline LIKE '% /p%';

// T1003.005 - Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE
// SELECT * FROM win_process_events WHERE path LIKE '%cmdkey.exe%' AND (cmdline LIKE '%/l%' OR cmdline LIKE '%-l%');

bool credentials_cmdkey(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("cmdkey.exe") != std::string::npos && cmdline.find(" /g") != std::string::npos && cmdline.find(" /u") != std::string::npos && cmdline.find(" /p") != std::string::npos)
    {
        std::stringstream ss;
        ss << " Detected the usage of cmdkey to add generic credentials";
        rule_event.metadata = ss.str();
        return true;
    }

    if (path.find("cmdkey.exe") != std::string::npos && (cmdline.find("/l") != std::string::npos || cmdline.find("-l") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected the usage of cmdkey to look for cached credentials";
        rule_event.metadata = ss.str();
        return true;
    }

    return false;
}

// T1003.003 - Create Symlink to Volume Shadow Copy
// SELECT * FROM win_process_events WHERE cmdline LIKE '%mklink%' AND cmdline LIKE '%HarddiskVolumeShadowCopy%';

bool create_symlink_volume_shadow_copy(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find("mklink") != std::string::npos && cmdline.find("HarddiskVolumeShadowCopy") != std::string::npos)
    {
        std::stringstream ss;
        ss << "Detected shadow copies storage symbolic link using utilities";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.006 - LSASS Process Reconnaissance Via Findstr.EXE
//
bool findstr_lssass_process(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("findstr.exe") != std::string::npos && cmdline.find("lssass") != std::string::npos) && (cmdline.find(" /i lsass.exe") != std::string::npos || cmdline.find("findstr lsass") != std::string::npos || cmdline.find("findstr.exe lsass") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of findstr to identify and execute a lnk file";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.006 - Permission Misconfiguration Reconnaissance Via Findstr.EXE
//
bool permission_misconfiguration_findstr(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if ((path.find("findstr") != std::string::npos && (cmdline.find("Everyone") != std::string::npos || cmdline.find("BUILTIN") != std::string::npos)) || (cmdline.find("icacls") != std::string::npos && cmdline.find("findstr") != std::string::npos && cmdline.find("Everyone") != std::string::npos))
    {
        std::stringstream ss;
        ss << "Detected usage of findstr with the EVERYONE or BUILTIN keywords.";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1557.001 - HackTool - ADCSPwn Execution
//
bool hacktool_adcspwn_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if (cmdline.find(" --adcs ") != std::string::npos && cmdline.find(" --port ") != std::string::npos)
    {
        std::stringstream ss;
        ss << " Detected command line parameters used by ADCSPwn";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1649 - HackTool - Certify Execution
//
bool hacktool_certify_execution(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    std::string path = process_event.entry.path;
    if (path.find("\\Certify.exe") != std::string::npos ||
        (cmdline.find(".exe cas ") != std::string::npos || cmdline.find(".exe find ") != std::string::npos ||
         cmdline.find(".exe pkiobjects ") != std::string::npos || cmdline.find(".exe request ") != std::string::npos ||
         cmdline.find(".exe download ") != std::string::npos) ||
        (cmdline.find(" /vulnerable") != std::string::npos || cmdline.find(" /template:") != std::string::npos ||
         cmdline.find(" /altname:") != std::string::npos || cmdline.find(" /domain:") != std::string::npos ||
         cmdline.find(" /path:") != std::string::npos || cmdline.find(" /ca:") != std::string::npos))
    {
        std::stringstream ss;
        ss << " Detected Certify a tool for Active Directory certificate abuse based on PE metadata";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}

// T1552.001 - Searching for passwords in file with CLI and Powersploit
//
bool searching_for_passwords_in_file_with_CLI_and_powersploit(const ProcessEvent &process_event, Event &rule_event)
{
    std::string cmdline = process_event.entry.cmdline;
    if ((cmdline.find("findstr") != std::string::npos && cmdline.find("*pass*") != std::string::npos) ||
        (cmdline.find("type") != std::string::npos && cmdline.find("unattend.xml") != std::string::npos) ||
        (cmdline.find("select-string") != std::string::npos && cmdline.find("*password") != std::string::npos) ||
        (cmdline.find("get-content") != std::string::npos && cmdline.find("*unattend.xml*") != std::string::npos) ||
        cmdline.find("Get-UnattendedInstallFile") != std::string::npos ||
        cmdline.find("Get-Webconfig") != std::string::npos ||
        cmdline.find("Get-ApplicationHost") != std::string::npos ||
        cmdline.find("Get-SiteListPassword") != std::string::npos ||
        cmdline.find("Get-CachedGPPPassword") != std::string::npos ||
        cmdline.find("Get-RegistryAutoLogon") != std::string::npos)

    {
        std::stringstream ss;
        ss << "Detected activities related to searching for passwords and accessing configuration files";
        rule_event.metadata = ss.str();
        return true;
    }
    return false;
}
