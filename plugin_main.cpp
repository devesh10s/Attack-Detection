#include "../common/plugin_base.h"
#include "../common/EdrDataTypes.h"
#include "detection_rules.h"
#include "win_detection_rules.h"
#include "gtfobins_rules.h"
#include "collection_rules.h"
#include "command_control_rules.h"
#include "credential_access_rules.h"
#include "exfiltration_rules.h"
#include "win_impact_rules.h"
#include "win_execution_rules.h"
#include "win_defence_evasion_rules.h"
#include "win_privilege_escalation_rules.h"
#include "win_collection_rules.h"
#include "win_discovery_rules.h"
#include "win_command_control_rules.h"
#include "win_credential_access_rules.h"
#include "win_persistence_rules.h"
#include "win_initial_access_rules.h"
#include "win_exfilteration_rules.h"
#include "win_lateral_movement.h"
#include "win_resource_development_rules.h"
#include "defence_evasion_rules.h"
#include "discovery_rules.h"
#include "execution_rules.h"
#include "impact_rules.h"
#include "persistence_rules.h"
#include "privilege_escalation_rules.h"

class
    ProcessEventProcessor : public AbstractDetectionPlugin
{
private:
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, SeverityLevel, bool, std::function<bool(const ProcessEvent &, Event &)>>> event_rules;
    // std::vector<std::tuple<std::string, std::string, std::string, std::string, SeverityLevel, bool, std::function<bool(const WinProcessEvent &, Event &)>>> win_event_rules;
public:
    ProcessEventProcessor()
    {
        // Linux
        event_rules.emplace_back(
            std::make_tuple("WGET_DOWNLOAD_IN_TMP", "", "", "", "Linux", SeverityLevel::Medium, true, wget_download_tmp));
        event_rules.emplace_back(
            std::make_tuple("GET_DOWNLOAD_IN_TMP", "", "", "", "Linux", SeverityLevel::Medium, true, get_download_tmp));
        event_rules.emplace_back(
            std::make_tuple("CPULIMIT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, cpulimit_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("DMESG_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, dmesg_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("DOCKER_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, docker_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("DPKG_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, dpkg_spawn_shell));
        // event_rules.emplace_back(
        //     std::make_tuple("ENV_SPAWNS_SHELL","GTFOBINS","","","Linux", SeverityLevel::Medium, true, env_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("FIND_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, find_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("FLOCK_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, flock_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("APT_GET_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, apt_get_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("APT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, apt_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("ASH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ash_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("AWK_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, awk_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("BUNDLER_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, bundler_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("BUSCTL_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, busctl_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("BYEBUG_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, byebug_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("CPAN_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, cpan_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("IONICE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ionice_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("JOURNALCTL_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, journalctl_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("KSH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ksh_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("LESS_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, less_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("LOGSAVE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, logsave_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("LTRACE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ltrace_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("LUA_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, lua_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("MAN_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, man_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("MAWK_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, mawk_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("MYSQL_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, mysql_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NANO_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nano_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NICE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nice_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NMAP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nmap_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NOHUP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nohup_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NROFF_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nroff_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NSENTER_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nsenter_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("PERL_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, perl_spawn_shell));

        event_rules.emplace_back(
            std::make_tuple("FTP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ftp_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GIT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, git_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GAWK_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, gawk_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GCC_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, gcc_spawn_shell));
        // event_rules.emplace_back(
        //     std::make_tuple("GDB_SPAWNS_SHELL","GTFOBINS","","","Linux", SeverityLevel::Medium, true, gdb_spawn_shell));

        event_rules.emplace_back(
            std::make_tuple("TAR_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, tar_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("TASKSET_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, taskset_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("TIME_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, time_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("TIMEOUT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, timeout_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("TMUX_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, tmux_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("WATCH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, watch_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("VI_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, vi_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("VIM_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, vim_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("VIEW_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, view_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("XARGS_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, xargs_spawn_shell));

        event_rules.emplace_back(
            std::make_tuple("ZIP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, zip_spawn_shell));

        event_rules.emplace_back(
            std::make_tuple("STRACE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, strace_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("STDBUF_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, stdbuf_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("STARTSTOPDAEMON_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, startstopdaemon_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("SSH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ssh_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("SPLIT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, split_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("SQLITE3_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, sqlite3_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("SETARCH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, setarch_spawn_shell));
        event_rules.emplace_back(std::make_tuple("SED_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, sed_spawn_shell));
        event_rules.emplace_back(std::make_tuple("SLSH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, slsh_spawn_shell));
        event_rules.emplace_back(std::make_tuple("SOCAT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, socat_spawn_shell));
        event_rules.emplace_back(std::make_tuple("SCRIPT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, script_spawn_shell));
        event_rules.emplace_back(std::make_tuple("SCREEN_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, screen_spawn_shell));
        event_rules.emplace_back(std::make_tuple("PUPPET_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, puppet_spawn_shell));
        event_rules.emplace_back(std::make_tuple("RUNMAILCAP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, runmailcap_spawn_shell));
        event_rules.emplace_back(std::make_tuple("RAKE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, rake_spawn_shell));
        event_rules.emplace_back(std::make_tuple("RLWRAP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, rlwrap_spawn_shell));
        event_rules.emplace_back(std::make_tuple("RPM_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, rpm_spawn_shell));
        event_rules.emplace_back(std::make_tuple("PIC_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, pic_spawn_shell));
        event_rules.emplace_back(std::make_tuple("SCP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, scp_spawn_shell));
        event_rules.emplace_back(std::make_tuple("PHP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, php_spawn_shell));
        event_rules.emplace_back(std::make_tuple("UNSHARE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, unshare_spawn_shell));

        // Arjun
        event_rules.emplace_back(
            std::make_tuple("AT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, at_spawn_shell));
        // event_rules.emplace_back(
        //         std::make_tuple("BASH_SPAWNS_SHELL","GTFOBINS","","Linux", SeverityLevel::Medium, true, bash_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("CAPSH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, capsh_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("COWSAY_SPAWNS_SHELL", "GTFOBINS", "Cowsay", "https://gtfobins.github.io/gtfobins/cowsay/", "Linux", SeverityLevel::Medium, true, cowsay_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("CRASH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, crash_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("CSH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, csh_spawn_shell));
        // event_rules.emplace_back(
        //         std::make_tuple("DASH_SPAWNS_SHELL","GTFOBINS","","","Linux", SeverityLevel::Medium, true, dash_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("ED_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ed_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("EMAC_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, emacs_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("EX_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ex_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("EXPECT_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, expect_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("FACTER_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, facter_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GHC_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ghc_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GHCI_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, ghci_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("HPING_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, hping_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GTESTER_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, gtester_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("GIMP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, gimp_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("IRB_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, irb_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("JJS_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, jjs_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("MAIL_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, mail_spawn_shell));
        // event_rules.emplace_back(
        //     std::make_tuple("MAKE_SPAWNS_SHELL","GTFOBINS","","","Linux", SeverityLevel::Medium, true, make_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("MORE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, more_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NAWK_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, nawk_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("NODE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, node_spawn_shell));
        // event_rules.emplace_back(

        //     std::make_tuple("PICO_SPAWNS_SHELL","GTFOBINS","","","Linux", SeverityLevel::Medium, true, pico_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("ZYPPER_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, zypper_spawn_shell));
        // event_rules.emplace_back(
        //     std::make_tuple("ZSH_SPAWNS_SHELL","GTFOBINS","","","Linux", SeverityLevel::Medium, true, zsh_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("VALGRIND_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, valgrind_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("TOP_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, top_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("TCLSH_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, tclsh_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("SERVICE_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, service_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("RVIEW_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, rview_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("RUN-PARTS_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, run_parts_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("PYTHON_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, python_spawn_shell));
        event_rules.emplace_back(
            std::make_tuple("PSQL_SPAWNS_SHELL", "GTFOBINS", "", "", "Linux", SeverityLevel::Medium, true, psql_spawn_shell));

        // Sunil

        event_rules.emplace_back(
            std::make_tuple("KERNAL_MODULES_EXTENSIONS_MODPROBE", "PRIVILEGE ESCALATION, PERSISTENCE", "T1547.006", "https://attack.mitre.org/techniques/T1547/006", "Linux", SeverityLevel::Medium, true, kernel_modules_extensions_modprobe));

        event_rules.emplace_back(
            std::make_tuple("KERNAL_MODULES_EXTENSIONS_INSMOD", "PRIVILEGE ESCALATION, PERSISTENCE", "T1547.006", "https://attack.mitre.org/techniques/T1547/006", "Linux", SeverityLevel::Medium, true, kernel_modules_extensions_insmod));

        event_rules.emplace_back(
            std::make_tuple("KERNAL_MODULES_EXTENSIONS_LSMOD", "PRIVILEGE ESCALATION, PERSISTENCE", "T1547.006", "https://attack.mitre.org/techniques/T1547/006", "Linux", SeverityLevel::Medium, true, kernel_modules_extensions_lsmod));

        event_rules.emplace_back(
            std::make_tuple("KERNAL_MODULES_EXTENSIONS_RMMOD", "PRIVILEGE ESCALATION, PERSISTENCE", "T1547.006", "https://attack.mitre.org/techniques/T1547/006", "Linux", SeverityLevel::Medium, true, kernel_modules_extensions_rmmod));

        event_rules.emplace_back(
            std::make_tuple("CREATE_LOCAL_ACCOUNT_USERADD", "PERSISTENCE", "T1136.001", "https://attack.mitre.org/techniques/T1136/001", "Linux", SeverityLevel::Medium, true, create_local_account_useradd));

        event_rules.emplace_back(
            std::make_tuple("CREATE_LOCAL_ACCOUNT_ADDUSER", "PERSISTENCE", "T1136.001", "https://attack.mitre.org/techniques/T1136/001", "Linux", SeverityLevel::Medium, true, create_local_account_adduser));

        event_rules.emplace_back(
            std::make_tuple("CREATE_DOMAIN_ACCOUNT", "PERSISTENCE", "T1136.002", "https://attack.mitre.org/techniques/T1136/002", "Linux", SeverityLevel::Low, true, create_domain_account));

        event_rules.emplace_back(
            std::make_tuple("EVENT_TRIGGERED_EXECUTION_TRAP", "PRIVILEGE ESCALATION, PERSISTENCE", "T1546.005", "https://attack.mitre.org/techniques/T1546/005", "Linux", SeverityLevel::Medium, true, event_triggered_execution_trap));

        event_rules.emplace_back(
            std::make_tuple("DYNAMIC_LINKER_HIJACKING", "Defence Evasion, PRIVILEGE ESCALATION, PERSISTENCE", "T1574.006", "https://attack.mitre.org/techniques/T1574/006", "Linux", SeverityLevel::Medium, true, dynamic_linker_hijacking));

        event_rules.emplace_back(
            std::make_tuple("SCHEDULING_TASK_AT", "PRIVILEGE ESCALATION, PERSISTENCE, EXECUTION", "T1053.002", "https://attack.mitre.org/techniques/T1053/002", "Linux", SeverityLevel::Low, true, scheduled_task_at));

        event_rules.emplace_back(
            std::make_tuple("SCHEDULING_TASK_ATRM", "PRIVILEGE ESCALATION, PERSISTENCE, EXECUTION", "T1053.002", "https://attack.mitre.org/techniques/T1053/002", "Linux", SeverityLevel::Low, true, scheduled_task_atrm));

        // event_rules.CHEDULING_TASK_CRONTAB","PRIVILEGE ESCALATION, PERSISTENCE","T1053.003","https://attack.mitre.org/techniques/T1053/003","Linux", SeverityLevel::Medium, true, scheduled_task_cron));emplace_back(
        //     std::make_tuple("S

        event_rules.emplace_back(
            std::make_tuple("SCHEDULING_TASK_SYSTEMD_TIMERS", "PRIVILEGE ESCALATION, PERSISTENCE, EXECUTION", "T1053.006", "https://attack.mitre.org/techniques/T1053/006", "Linux", SeverityLevel::Information, true, scheduled_task_systemd_timers));

        // event_rules.emplace_back(
        //     std::make_tuple("SSH_AUTHORISED_KEYS","PERSISTENCE","T1098.004","https://attack.mitre.org/techniques/T1098/004","Linux", SeverityLevel::High, true, ssh_authorized_keys));

        // event_rules.emplace_back(
        //     std::make_tuple("ABUSE_ELEVATION_CONTROL_SETUID", "Defence Evasion, PRIVILEGE ESCALATION", "T1548.001", "https://attack.mitre.org/techniques/T1548/001", "Linux", SeverityLevel::High, true, abuse_elevation_control_setuid));

        event_rules.emplace_back(
            std::make_tuple("ABUSE_ELEVATION_CONTROL_SETUID1", "Defence Evasion, PRIVILEGE ESCALATION", "T1548.001", "https://attack.mitre.org/techniques/T1548/001", "Linux", SeverityLevel::Low, true, abuse_elevation_control_setuid1));

        event_rules.emplace_back(
            std::make_tuple("ABUSE_ELEVATION_CONTROL_SUDO_CACHING", "Defence Evasion, PRIVILEGE ESCALATION", "T1548.003", "https://attack.mitre.org/techniques/T1548/003", "Linux", SeverityLevel::Medium, true, abuse_elevation_control_sudo_caching));

        event_rules.emplace_back(
            std::make_tuple("CREATE_MODIFY_SYSTEMD_SERVICE", "PERSISTENCE", "T1543.002", "https://attack.mitre.org/techniques/T1543/002", "Linux", SeverityLevel::Medium, true, create_modify_system_systemd_service));

        event_rules.emplace_back(
            std::make_tuple("TERMINAL_DOWNLAODS_CURL", "", "", "", "Linux", SeverityLevel::Information, true, terminal_downloads_curl));

        event_rules.emplace_back(
            std::make_tuple("IMPAIR_COMMAND_HISTORY_LOGGING", "", "", "", "Linux", SeverityLevel::Medium, true, impair_command_history_logging));

        event_rules.emplace_back(
            std::make_tuple("TERMINAL_DOWNLAODS_PYTHON", "", "", "", "Linux", SeverityLevel::Low, true, terminal_downloads_python));

        event_rules.emplace_back(
            std::make_tuple("BASH_HISTORY_COMMANDLINE", "", "", "", "Linux", SeverityLevel::Medium, true, bash_history_commandLine));

        event_rules.emplace_back(
            std::make_tuple("PING_PRIVILEGED_COMMANDLINE", "", "", "", "Linux", SeverityLevel::Information, true, ping_privileged_commandLine));

        event_rules.emplace_back(
            std::make_tuple("MOUNT_PRIVILEGED_COMMANDLINE", "", "", "", "Linux", SeverityLevel::Information, true, mount_privileged_commandLine));

        event_rules.emplace_back(
            std::make_tuple("UMOUNT_PRIVILEGED_COMMANDLINE", "", "", "", "Linux", SeverityLevel::Information, true, umount_privileged_commandLine));

        event_rules.emplace_back(
            std::make_tuple("CHGRP_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, chgrp_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("PAM_TIMESTAMP_CHECK_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, pam_timestamp_check_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("UNIX_CHKPWD_CHECK_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, unix_chkpwd_check_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("PWCK_CHECK_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, pwck_check_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("USERHELPER_CHECK_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, userhelper_check_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("XORG_CHECK_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, Xorg_check_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("RLOGIN_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, rlogin_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("SUDOEDIT_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, sudoedit_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("RSH_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, rsh_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("GPASSWD_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, gpasswd_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("SUDO_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, sudo_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("STAPRUN_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, staprun_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("RCP_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, rcp_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("PASSWD_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, passwd_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("CHSH_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, chsh_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("CHFN_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, chfn_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("CHAGE_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, chage_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("SETFACL_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, setfacl_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("CHACL_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, chacl_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("CHCON_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, chcon_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("NEWGRP_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, newgrp_privileged_command));

        // event_rules.emplace_back(
        //         std::make_tuple("SLEEP_PRIVILEGED_COMMAND","","","","Linux", SeverityLevel::High, true, sleep_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("PGREP_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, pgrep_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("GREP_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, grep_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("LSPCI_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, lspci_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("UDEVADM_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, udevadm_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("FINDMNT_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, findmnt_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("NETSTAT_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, netstat_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("AWK_PRIVILEGED_COMMAND", "", "", "", "Linux", SeverityLevel::Information, true, awk_privileged_command));

        // event_rules.emplace_back(
        //         std::make_tuple("SED_PRIVILEGED_COMMAND","","","","Linux", SeverityLevel::High, true, sed_privileged_command));

        event_rules.emplace_back(
            std::make_tuple("SYSTED DETECT VIRTUAL ENV", "Defence Evasion, DISCOVERY", "T1497.001", "https://attack.mitre.org/techniques/T1497", "Linux", SeverityLevel::High, true, virtualization_evasion_system_checks_systemd_detect_virt));

        event_rules.emplace_back(
            std::make_tuple("SYSTED DETECT VIRTUAL ENV DMIDECODE", "Defence Evasion", "T1497.001", "https://attack.mitre.org/techniques/T1497/001", "Linux", SeverityLevel::High, true, virtualization_evasion_system_checks_dmidecode));

        event_rules.emplace_back(
            std::make_tuple("SET FILE ACCESS TIMESTAMP", "Defence Evasion", "T1070.006", "https://attack.mitre.org/techniques/T1070/006", "Linux", SeverityLevel::Medium, true, set_file_access_timestamp));

        // event_rules.emplace_back(
        //         std::make_tuple("SET FILE MODIFICATION TIMESTAMP","","","","Linux", SeverityLevel::High, true, set_file_modification_timestamp));

        event_rules.emplace_back(
            std::make_tuple("MODIFY FILE TIMESTAMP USING REFERENCE FILE", "Defence Evasion", "T1070.006", "https://attack.mitre.org/techniques/T1070/006", "Linux", SeverityLevel::Medium, true, modify_file_timestamp_using_reference_file));

        // event_rules.emplace_back(
        //     std::make_tuple("SUDO CACHING SUDO USAGE", "Defence Evasion", "T1070.006", "https://attack.mitre.org/techniques/T1070/006", "Linux", SeverityLevel::Medium, true, sudo_and_sudo_caching_sudo_usage));

        event_rules.emplace_back(
            std::make_tuple("SUDO CACHING UNLIMITED SUDO TIMEOUT", "Defence Evasion", "T1548.003", "https://attack.mitre.org/techniques/T1548/003", "Linux", SeverityLevel::Medium, true, sudo_and_sudo_caching_unlimited_sudo_timeout));
        //
        event_rules.emplace_back(
            std::make_tuple("SUDO CACHING UNLIMITED SUDO TIMEOUT", "Defence Evasion, PRIVILEGE ESCALATION", "T1548.003", "https://attack.mitre.org/techniques/T1548/003", "Linux", SeverityLevel::Medium, true, sudo_and_sudo_caching_disable_tty_tickets_sudo_caching));

        event_rules.emplace_back(
            std::make_tuple("IMPAIR COMMAND HISTORY LOGGING DISABLE HISTORY COLLECTION", "Defence Evasion", "T1562.003", "https://attack.mitre.org/techniques/T1562/003", "Linux", SeverityLevel::High, true, impair_cmd_history_logging_disable_history_collection));

        event_rules.emplace_back(
            std::make_tuple("IMPAIR COMMAND HISTORY LOGGING Mac HISTCONTROLL", "Defence Evasion", "T1562.003", "https://attack.mitre.org/techniques/T1562/003", "Linux", SeverityLevel::High, true, impair_cmd_history_logging_mac_hist_control));

        event_rules.emplace_back(
            std::make_tuple("FILE DELETION SINGLE FILE", "", "", "", "Linux", SeverityLevel::Information, true, file_deletion_single_file));

        event_rules.emplace_back(
            std::make_tuple("FILE DELETION ENTIRE FOLDER", "", "", "", "Linux", SeverityLevel::Information, true, file_deletion_entire_folder));

        event_rules.emplace_back(
            std::make_tuple("OVERWRITE AND DELETE FILE WITH SHRED", "", "", "", "Linux", SeverityLevel::Information, true, overwrite_and_delete_file_with_shred));

        event_rules.emplace_back(
            std::make_tuple("DELETE FILESYSTEM", "", "", "", "Linux", SeverityLevel::High, true, delete_filesystem_root));

        // event_rules.emplace_back(
        //     std::make_tuple("MODIFYING_CRON_FILE_REFERENCE", "", "", "", "Linux", SeverityLevel::High, true, modifying_cron_file_reference));

        event_rules.emplace_back(
            std::make_tuple("MODIFYING_CRON_DAILY_FILE", "", "", "", "Linux", SeverityLevel::Information, true, modifying_cron_daily_file));

        event_rules.emplace_back(
            std::make_tuple("MODIFYING_CRON_HOURLY_FILE", "", "", "", "Linux", SeverityLevel::Information, true, modifying_cron_hourly_file));

        event_rules.emplace_back(
            std::make_tuple("MODIFYING_CRON_MONTHLY_FILE", "", "", "", "Linux", SeverityLevel::Information, true, modifying_cron_monthly_file));

        event_rules.emplace_back(
            std::make_tuple("MODIFYING_CRON_WEEKLY_FILE", "", "", "", "Linux", SeverityLevel::Information, true, modifying_cron_weekly_file));

        event_rules.emplace_back(
            std::make_tuple("MODIFYING_CRON_VAR_FILE", "", "", "", "Linux", SeverityLevel::Low, true, modifying_cron_var_file));

        // event_rules.emplace_back(
        //     std::make_tuple("SHARED_LIBRARY_INJECTION", "", "", "", "Linux", SeverityLevel::High, true, shared_library_injection));

        // event_rules.emplace_back(
        //     std::make_tuple("SHARED_LIBRARY_INJECTION_LD_PRELOAD", "", "", "", "Linux", SeverityLevel::High, true, shared_library_injection_ld_preload));

        // event_rules.emplace_back(
        //     std::make_tuple("LOAD_KERNEL_MODULE_INSMOD", "", "", "", "Linux", SeverityLevel::High, true, load_kernel_module_insmod));

        event_rules.emplace_back(
            std::make_tuple("PAM_CONFIG_FILE_MODIFY", "Defence Evasion, PERSISTENCE, CREDENTIAL ACCESS", "T1556.003", "https://attack.mitre.org/techniques/T1556/003", "Linux", SeverityLevel::Medium, true, pam_config_file_modify));

        event_rules.emplace_back(
            std::make_tuple("RULE_ADD_PAM_CONFIG", "", "", "", "Linux", SeverityLevel::High, true, rule_add_pam_config));

        event_rules.emplace_back(
            std::make_tuple("RC_SCRIPT_COMMON_MIDIFY", "PRIVILEGE ESCALATION, PERSISTENCE", "T1037.004", "https://attack.mitre.org/techniques/T1037/004", "Linux", SeverityLevel::Medium, true, rc_script_common_midify));

        event_rules.emplace_back(
            std::make_tuple("RC_SCRIPT_LOCAL_MIDIFY", "PRIVILEGE ESCALATION", "T1037.004", "https://attack.mitre.org/techniques/T1037/004", "Linux", SeverityLevel::Medium, true, rc_script_local_midify));

        event_rules.emplace_back(
            std::make_tuple("SSH_AUTHORIZED_KEYS", "", "", "", "Linux", SeverityLevel::Critical, true, ssh_authorized_keys_midify));

        // event_rules.emplace_back(
        //     std::make_tuple("CREATE_SYSTEMD_SERVICE_PATH", "", "", "", "Linux", SeverityLevel::High, true, create_systemd_service_path));

        event_rules.emplace_back(
            std::make_tuple("CREATE_SYSTEMD_SERVICE_FILE", "PRIVILEGE ESCALATION", "T1543.002", "https://attack.mitre.org/techniques/T1543/002", "Linux", SeverityLevel::Medium, true, create_systemd_service_file));

        // event_rules.emplace_back(
        //     std::make_tuple("CREATE_SYSTEMD_SERVICE__TIMER_SERVICE", "", "", "", "Linux", SeverityLevel::Medium, true, create_systemd_service__timer_service));

        // event_rules.emplace_back(
        //     std::make_tuple("CREATE_SYSTEMD_SERVICE__TIMER_FILE", "", "", "", "Linux", SeverityLevel::Medium, true, create_systemd_service__timer_file));

        // event_rules.emplace_back(
        //     std::make_tuple("LATERAL_MOVEMENT_WITH_SECURE_SHELL","","","","Linux", SeverityLevel::High, true, lateral_movement_with_secure_shell));

        event_rules.emplace_back(
            std::make_tuple("LATERAL_MOVEMENT_WITH_SSH_RSA", "", "", "", "Linux", SeverityLevel::High, true, lateral_movement_with_ssh_rsa));

        // event_rules.emplace_back(
        //     std::make_tuple("LATERAL_TOOL_TRANSFER_FILES", "", "", "", "Linux", SeverityLevel::High, true, lateral_tool_transfer_files));

        event_rules.emplace_back(
            std::make_tuple("DYNAMIC_LINKER_HIJACKING_LD_SO_PRELOAD", "", "", "", "Linux", SeverityLevel::High, true, shared_library_injection_ld_so_preload));

        event_rules.emplace_back(
            std::make_tuple("DISABLE_SYSLOG", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Linux", SeverityLevel::Low, true, disable_syslog));

        event_rules.emplace_back(
            std::make_tuple("DISABLE_CB_RESPONSE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Linux", SeverityLevel::Medium, true, disable_cb_response));

        event_rules.emplace_back(
            std::make_tuple("STOP_CROWDSTRIKE_FALCON", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Linux", SeverityLevel::Medium, true, stop_crowdstrike_falcon));

        event_rules.emplace_back(
            std::make_tuple("STOP_START_UFW_FIREWALL", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, stop_start_ufw_firewall));

        event_rules.emplace_back(
            std::make_tuple("STOP_START_UFW_FIREWALL_SYSTEMCTL", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, stop_start_ufw_firewall_systemctl));

        event_rules.emplace_back(
            std::make_tuple("TURN_OFF_UFW_LOGGING", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, turn_off_ufw_logging));

        event_rules.emplace_back(
            std::make_tuple("ADD_DELETE_UFW_RULES", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, add_delete_ufw_rules));

        event_rules.emplace_back(
            std::make_tuple("EDIT_UFW_RULES_USER_DOT_RULES_FILE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, edit_ufw_user_rules_file));

        event_rules.emplace_back(
            std::make_tuple("EDIT_UFW_RULES_UFW_DOT_CONF_FILE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, edit_ufw_conf_file));

        event_rules.emplace_back(
            std::make_tuple("EDIT_UFW_RULES_SYSCTL_DOT_CONF_FILE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, edit_ufw_rules_sysctl_conf_file));

        event_rules.emplace_back(
            std::make_tuple("EDIT_UFW_FIREWALL_MAIN_CONFIG_FILE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, edit_ufw_firewall_main_config_file));

        event_rules.emplace_back(
            std::make_tuple("TAIL_UFW_FIREWALL_LOG_FILE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::High, true, tail_ufw_firewall_log_file));

        event_rules.emplace_back(
            std::make_tuple("BASE_64_DECODING_WITH_PYTHON", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Low, true, base64_decoding_python));

        event_rules.emplace_back(
            std::make_tuple("BASE_64_DECODING_WITH_PERL", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Low, true, base64_decoding_perl));

        event_rules.emplace_back(
            std::make_tuple("BASE_64_DECODING_WITH_SHELL_UTILITIES", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Low, true, base64_decoding_shell_utilities));

        event_rules.emplace_back(
            std::make_tuple("HEX_DECODING_WITH_SHELL_UTILITIES", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Low, true, hex_decoding_shell_utilities));

        event_rules.emplace_back(
            std::make_tuple("COMPILE_AFTER_DELIVERY_C_COMPILE", "Defence Evasion", "T1027.004", "https://attack.mitre.org/techniques/T1027/004", "Linux", SeverityLevel::Information, true, compile_after_delivery_c_compile));

        event_rules.emplace_back(
            std::make_tuple("COMPILE_AFTER_DELIVERY_GO_COMPILE", "Defence Evasion", "T1027.004", "https://attack.mitre.org/techniques/T1027/004", "Linux", SeverityLevel::Information, true, compile_after_delivery_go_compile));

        event_rules.emplace_back(
            std::make_tuple("CREATING_GCP_SERVICE_ACCOUNT_AND_KEY", "", "", "", "Linux", SeverityLevel::High, true, creating_gcp_service_account_and_key));

        event_rules.emplace_back(
            std::make_tuple("CLEAR_LINUX_LOGS", "Defence Evasion", "T1070.002", "https://attack.mitre.org/techniques/T1070/002", "Linux", SeverityLevel::High, true, clear_linux_logs_rm_rf));

        event_rules.emplace_back(
            std::make_tuple("OVERWRITE_LINUX_MAIL_SPOOL_AND_LOGS", "Defence Evasion", "T1070.002", "https://attack.mitre.org/techniques/T1070/002", "Linux", SeverityLevel::High, true, overwrite_linux_mail_spool_and_logs));

        // event_rules.emplace_back(
        //         std::make_tuple("SCHEDULE_A_JOB_LINUX_AT","","","","Linux", SeverityLevel::High, true, at_schedule_a_job));

        // event_rules.emplace_back(
        //         std::make_tuple("SYSTEM_OWNER_USER_DISCOVERY","DISCOVERY","T1033","https://attack.mitre.org/techniques/T1033","Linux", SeverityLevel::High, true, system_owner_user_discovery));

        event_rules.emplace_back(
            std::make_tuple("ENUMERATE_ALL_ACCOUNTS_LOCAL", "DISCOVERY", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Linux", SeverityLevel::High, true, enumerate_all_accounts_local));

        // event_rules.emplace_back(
        //     std::make_tuple("VIEW_SUDOERS_ACCESS", "DISCOVERY", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Linux", SeverityLevel::High, true, view_sudoers_file));

        event_rules.emplace_back(
            std::make_tuple("VIEW_ACCOUNTS_WITH_UID_0", "DISCOVERY", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Linux", SeverityLevel::High, true, view_accounts_with_uid_0));

        event_rules.emplace_back(
            std::make_tuple("LIST_OPENED_FILES_BY_USER", "DISCOVERY", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Linux", SeverityLevel::High, true, list_opened_files_by_user));

        event_rules.emplace_back(
            std::make_tuple("SHOW_IF_A_USER_ACCOUNT_HAS_EVER_LOGGED_IN_REMOTELY", "DISCOVERY", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Linux", SeverityLevel::High, true, show_if_a_user_account_has_ever_logged_in_remotely));

        // event_rules.emplace_back(
        //         std::make_tuple("ENUMERATE_USERS_AND_GROUPS","DISCOVERY","T1087.001","https://attack.mitre.org/techniques/T1087/001","Linux", SeverityLevel::High, true, enumerate_users_and_groups));

        event_rules.emplace_back(
            std::make_tuple("SYSTEM_SERVICE_DISCOVERY_SYSTEMCTL", "DISCOVERY", "T1007", "https://attack.mitre.org/techniques/T1007", "Linux", SeverityLevel::Information, true, system_service_discovery_systemctl));

        event_rules.emplace_back(
            std::make_tuple("PACKET_CAPTURE_LINUX", "DISCOVERY", "T1040", "https://attack.mitre.org/techniques/T1040", "Linux", SeverityLevel::Low, true, packet_capture_linux));

        event_rules.emplace_back(
            std::make_tuple("NETWORK_SHARE_DISCOVERY", "DISCOVERY", "T1135", "https://attack.mitre.org/techniques/T1135", "Linux", SeverityLevel::High, true, network_share_discovery));

        // event_rules.emplace_back(
        //         std::make_tuple("EXAMINE_PASSWORD_COMPLEXITY_POLICY","DISCOVERY","T1201","https://attack.mitre.org/techniques/T1201","Linux", SeverityLevel::High, true, examine_password_complexity_policy));

        event_rules.emplace_back(
            std::make_tuple("LIST_OS_INFORMATION", "DISCOVERY", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::Information, true, list_os_information));

        event_rules.emplace_back(
            std::make_tuple("LINUX_VM_CHECK_VIA_HARWARE", "DISCOVERY", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::High, true, linux_vm_check_via_hardware));

        // event_rules.emplace_back(
        //     std::make_tuple("LINUX_VM_CHECK_VIA_KERNEL_MODULES", "DISCOVERY", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::High, true, linux_vm_check_via_kernel_modules));

        // event_rules.emplace_back(
        //         std::make_tuple("HOSTNAME_DISCOVERY","DISCOVERY","T1082","https://attack.mitre.org/techniques/T1082","Linux", SeverityLevel::High, true, hostname_discovery));

        // event_rules.emplace_back(
        //         std::make_tuple("ENVIRONMENT_VARIABLES_DISCOVERY","DISCOVERY","T1082","https://attack.mitre.org/techniques/T1082","Linux", SeverityLevel::High, true, environment_variables_discovery));

        event_rules.emplace_back(
            std::make_tuple("LIST_MOZILLA_FIREFOX_BOOKMARK_DATABASE_FILES", "DISCOVERY", "T1217", "https://attack.mitre.org/techniques/T1217", "Linux", SeverityLevel::High, true, list_mozilla_firefox_bookmark_database_files));

        // event_rules.emplace_back(
        //     std::make_tuple("SYSTEM_NETWORK_CONFIGURATION_DISCOVERY", "DISCOVERY", "T1016", "https://attack.mitre.org/techniques/T1016", "Linux", SeverityLevel::Information, true, system_network_configuration_discovery));

        // event_rules.emplace_back(
        //         std::make_tuple("NIX_FILE_AND_DIRECTORY_DISCOVERY","DISCOVERY","T1083","https://attack.mitre.org/techniques/T1083","Linux", SeverityLevel::High, true, nix_file_and_directory_discovery));

        // event_rules.emplace_back(
        //     std::make_tuple("SYSTEM_NETWORK_CONNECTIONS_DISCOVERY", "DISCOVERY", "T1049", "https://attack.mitre.org/techniques/T1049", "Linux", SeverityLevel::High, true, system_network_connections_discovery));

        // event_rules.emplace_back(
        //         std::make_tuple("PROCESS_DISCOVERY","DISCOVERY","T1057","https://attack.mitre.org/techniques/T1057","Linux", SeverityLevel::Low, true, process_discovery));

        event_rules.emplace_back(
            std::make_tuple("PERMISSION_GROUPS_DISCOVERY_LOCAL", "DISCOVERY", "T1069.001", "https://attack.mitre.org/techniques/T1069/001", "Linux", SeverityLevel::High, true, permission_groups_discovery_local));

        event_rules.emplace_back(
            std::make_tuple("SECURITY_SOFTWARE_DISCOVERY", "DISCOVERY", "T1518.001", "https://attack.mitre.org/techniques/T1518/001", "Linux", SeverityLevel::Information, true, security_software_discovery));

        event_rules.emplace_back(
            std::make_tuple("REMOTE_SYSTEM_DISCOVERY_IPNEIGHBOUR", "DISCOVERY", "T1018", "https://attack.mitre.org/techniques/T1018", "Linux", SeverityLevel::Information, true, remote_system_discovery_ipneighbour));

        event_rules.emplace_back(
            std::make_tuple("PORT_SCAN", "DISCOVERY", "T1046", "https://attack.mitre.org/techniques/T1046", "Linux", SeverityLevel::Information, true, port_scan));

        event_rules.emplace_back(
            std::make_tuple("ENCRYPT_FILE_USING_GPG", "IMPACT", "T1486", "https://attack.mitre.org/techniques/T1486", "Linux", SeverityLevel::Medium, true, encrypt_file_using_gpg));

        event_rules.emplace_back(
            std::make_tuple("ENCRYPT_FILE_USING_7Z", "IMPACT", "T1486", "https://attack.mitre.org/techniques/T1486", "Linux", SeverityLevel::Medium, true, encrypt_file_using_7z));

        event_rules.emplace_back(
            std::make_tuple("ENCRYPT_FILE_USING_OPENSSL", "IMPACT", "T1486", "https://attack.mitre.org/techniques/T1486", "Linux", SeverityLevel::Medium, true, encrypt_file_using_openssl));

        event_rules.emplace_back(
            std::make_tuple("OVERWRITE_FILE_WITH_DD", "IMPACT", "T1485", "https://attack.mitre.org/techniques/T1485", "Linux", SeverityLevel::Medium, true, overwrite_file_with_dd));

        event_rules.emplace_back(
            std::make_tuple("SYSTEM_SHUTDOWN_REBOOT", "IMPACT", "T1529", "https://attack.mitre.org/techniques/T1529", "Linux", SeverityLevel::Information, true, system_shutdown_reboot));

        // event_rules.emplace_back(
        //         std::make_tuple("EXFILTRATE_DATA_HTTPS_USING_CURL","EXFILTRATE","T1048","https://attack.mitre.org/techniques/T1048","Linux", SeverityLevel::High, true, exfiltrate_data_https_using_curl));

        event_rules.emplace_back(
            std::make_tuple("DATA_COMPRESSED_ZIP", "COLLECTION", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Linux", SeverityLevel::Information, true, data_compressed_zip));

        event_rules.emplace_back(
            std::make_tuple("DATA_COMPRESSED_ZIP_NIX_GZIP", "COLLECTION", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Linux", SeverityLevel::Information, true, data_compressed_zip_nix_gzip));

        event_rules.emplace_back(
            std::make_tuple("DATA_COMPRESSED_ZIP_NIX_TAR", "COLLECTION", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Linux", SeverityLevel::Information, true, data_compressed_zip_nix_tar));

        event_rules.emplace_back(
            std::make_tuple("X_WINDOWS_CAPTURE", "COLLECTION", "T1113", "https://attack.mitre.org/techniques/T1113", "Linux", SeverityLevel::High, true, x_windows_capture));

        event_rules.emplace_back(
            std::make_tuple("CAPTURE_LINUX_DESKTOP_USING_IMPORT_TOOL", "COLLECTION", "T1113", "https://attack.mitre.org/techniques/T1113", "Linux", SeverityLevel::High, true, capture_linux_desktop_using_import_tool));

        // event_rules.emplace_back(
        //     std::make_tuple("TERMINAL_INPUT_CAPTURE_LINUX_WITH_PAM_D", "COLLECTION", "T1056.001", "https://attack.mitre.org/techniques/T1056/001", "Linux", SeverityLevel::High, true, terminal_input_capture_linux_with_pam_d));

        // event_rules.emplace_back(
        //     std::make_tuple("LOGGING_BASH_HISTORY_TO_SYSLOG", "COLLECTION", "T1056.001", "https://attack.mitre.org/techniques/T1056/001", "Linux", SeverityLevel::High, true, logging_bash_history_to_syslog));

        // event_rules.emplace_back(
        //     std::make_tuple("SSHD_PAM_KEYLOGGER", "COLLECTION", "T1056.001", "https://attack.mitre.org/techniques/T1056/001", "Linux", SeverityLevel::High, true, sshd_pam_keylogger));

        event_rules.emplace_back(
            std::make_tuple("STAGE_DATA_FROM_DISCOVERY_SH", "COLLECTION", "T1074.001", "https://attack.mitre.org/techniques/T1074/001", "Linux", SeverityLevel::High, true, stage_data_from_discovery_sh));

        event_rules.emplace_back(
            std::make_tuple("ADD_OR_COPY_CONTENT_TO_CLIPBOARD_WITH_XCLIP", "COLLECTION", "T1115", "https://attack.mitre.org/techniques/T1115", "Linux", SeverityLevel::High, true, add_or_copy_content_to_clipboard_with_xclip));

        event_rules.emplace_back(
            std::make_tuple("COMPRESSING_DATA_USING_GZIP_IN_PYTHON", "COLLECTION", "T1560.002", "https://attack.mitre.org/techniques/T1560/002", "Linux", SeverityLevel::High, true, compressing_data_using_gzip_in_python));

        event_rules.emplace_back(
            std::make_tuple("COMPRESSING_DATA_USING_BZ2_IN_PYTHON", "COLLECTION", "T1560.002", "https://attack.mitre.org/techniques/T1560/002", "Linux", SeverityLevel::High, true, compressing_data_using_bz2_in_python));

        event_rules.emplace_back(
            std::make_tuple("COMPRESSING_DATA_USING_ZIPFILE_IN_PYTHON", "COLLECTION", "T1560.002", "https://attack.mitre.org/techniques/T1560/002", "Linux", SeverityLevel::High, true, compressing_data_using_zipfile_in_python));
        // event_rules.emplace_back(
        //        std::make_tuple("NON_STANDARD_PORT_COMMAND_CONTROL","","","","Linux", SeverityLevel::High, true, non_standard_port_command_control));

        event_rules.emplace_back(
            std::make_tuple("HARDWARE_ADDITIONS", "INITIAL ACCESS", "T1200", "https://attack.mitre.org/techniques/T1200/", "Linux", SeverityLevel::Low, true, hardware_additions));

        event_rules.emplace_back(
            std::make_tuple("INJECT_LD_PRELOAD", "INITIAL ACCESS", "T1190", "https://attack.mitre.org/tactics/TA0001/", "Linux", SeverityLevel::High, true, inject_ld_preload));

        // event_rules.emplace_back(
        //     std::make_tuple("MANIPULATION_SSH_AUTHORIZED_KEY", "PERSISTENCE", "T1098.004", "https://attack.mitre.org/techniques/T1098/004/", "Linux", SeverityLevel::High, true, manipulation_ssh_authorized_key));

        // event_rules.emplace_back(
        //     std::make_tuple("SHELL_CONFIG_MODIFY", "PERSISTENCE", "T1546-004", "https://attack.mitre.org/techniques/T1546/004/", "Linux", SeverityLevel::High, true, shell_config_modify));

        // event_rules.emplace_back(
        //         std::make_tuple("DYNAMIC_LINKER_HIJACKING_FILE","PERSISTENCE","T1574.006","https://attack.mitre.org/techniques/T1574/006/","Linux", SeverityLevel::High, true, dynamic_linker_hijacking_file));

        // event_rules.emplace_back(
        //         std::make_tuple("PLUGGABLE_AUTHENTICATION_MODULES_FILE","PERSISTENCE","T1556.003","https://attack.mitre.org/techniques/T1556/003/","Linux", SeverityLevel::High, true, pluggable_authentication_modules_file));

        event_rules.emplace_back(
            std::make_tuple("SCHEDULED_TASK_AT_FILE", "PERSISTENCE", "T1053.002", "https://attack.mitre.org/techniques/T1053/002/", "Linux", SeverityLevel::Medium, true, scheduled_task_at_file));

        event_rules.emplace_back(
            std::make_tuple("SCHEDULED_TASK_CRON_FILE", "PERSISTENCE", "T1053.003", "https://attack.mitre.org/techniques/T1053/003/", "Linux", SeverityLevel::Medium, true, scheduled_task_cron_file));

        event_rules.emplace_back(
            std::make_tuple("SCHEDULED_TASK_SYSTEMD_TIMERS_FILE", "PERSISTENCE", "T1053.006", "https://attack.mitre.org/techniques/T1053/006/", "Linux", SeverityLevel::Low, true, scheduled_task_systemd_timers_file));

        event_rules.emplace_back(
            std::make_tuple("MALICIOUS_PAM_RULES", "Credential Access", "T1556.003", "https://attack.mitre.org/techniques/T1556/003", "Linux", SeverityLevel::High, true, malicious_pam_rules));

        event_rules.emplace_back(
            std::make_tuple("INPUT_CAPTURE_KEYLOGGING", "Credential Access", "T1056.001", "https://attack.mitre.org/techniques/T1056/001", "Linux", SeverityLevel::High, true, input_capture_keylogging));

        // event_rules.emplace_back(
        //     std::make_tuple("SSHD PAM KEYLOGGER", "Credential Access", "T1056.001", "https://attack.mitre.org/techniques/T1056/001", "Linux", SeverityLevel::High, true, sshd_pam_keylogger_keylogging));

        event_rules.emplace_back(
            std::make_tuple("DUMP_CREDENTIALS_FROM_WEB_BROWSERS", "Credential Access", "T1555.003", "https://attack.mitre.org/techniques/T1555/003", "Linux", SeverityLevel::High, true, dump_credentials_from_web_browsers));

        event_rules.emplace_back(
            std::make_tuple("DISCOVER_PRIVATE_SSH_KEYS", "Credential Access", "T1552.004", "https://attack.mitre.org/techniques/T1552/004", "Linux", SeverityLevel::High, true, discover_private_ssh_keys));

        event_rules.emplace_back(
            std::make_tuple("COPY_PRIVATE_SSH_KEYS_WITH_CP", "Credential Access", "T1552.004", "https://attack.mitre.org/techniques/T1552/004", "Linux", SeverityLevel::High, true, copy_private_ssh_keys_with_cp));

        // event_rules.emplace_back(
        //        std::make_tuple("EXTRACT_PASSWORDS_WITH_GREP","Credential Access","T1552.001","https://attack.mitre.org/techniques/T1552/001","Linux", SeverityLevel::High, true, extract_passwords_with_grep));

        // event_rules.emplace_back(
        //        std::make_tuple("EXTRACT_PASSWORDS_WITH_GREP","Credential Access","T1003.008","https://attack.mitre.org/techniques/T1003/008","Linux", SeverityLevel::High, true, access_etc_shadow_passwd));

        event_rules.emplace_back(
            std::make_tuple("EXFILTRATE_DATA_ALTERNATE_PROTOCOL", "EXFILTRATION", "T1048", "https://attack.mitre.org/techniques/T1048", "Linux", SeverityLevel::Low, true, exfiltrate_data_alternate_protocol));

        event_rules.emplace_back(
            std::make_tuple("DATA_TRANSFER_SIZE_LIMITS", "EXFILTRATION", "T1030", "https://attack.mitre.org/techniques/T1030", "Linux", SeverityLevel::Information, true, data_transfer_size_limits));

        event_rules.emplace_back(
            std::make_tuple("EXFIL_COMPRESSED_ARCHIVE_TO_S3_VIA_AWS_CLI", "EXFILTRATION", "T1567", "https://attack.mitre.org/techniques/T1567/002", "Linux", SeverityLevel::Information, true, exfil_compressed_archive_to_s3_via_aws_cli));

        event_rules.emplace_back(
            std::make_tuple("EXFIL_COMPRESSED_ARCHIVE_TO_S3_VIA_AWS_GOLANG", "EXFILTRATION", "T1567", "https://attack.mitre.org/techniques/T1567/002", "Linux", SeverityLevel::Information, true, exfil_compressed_archive_to_s3_via_aws_golang));

        event_rules.emplace_back(
            std::make_tuple("MULTI_HOP_PROXY", "Command and Control", "T1090.003", "https://attack.mitre.org/techniques/T1090/003/", "Linux", SeverityLevel::High, true, multi_hop_proxy));

        event_rules.emplace_back(
            std::make_tuple("INGRESS_TOOL_TRANSFER", "Command and Control", "T1108", "https://attack.mitre.org/techniques/T1105/", "Linux", SeverityLevel::High, true, ingress_tool_transfer));

        // Review rule
        //  event_rules.emplace_back(
        //      std::make_tuple("ABUSE_ELEVATION_CONTROL_MECHANISM_FILE", "Privilege Escalation", "T1548.001", "https://attack.mitre.org/techniques/T1548/001/", "Linux", SeverityLevel::High, true, Abuse_elevation_control_mechanism_file));

        // event_rules.emplace_back(
        //     std::make_tuple("ABUSE_ELEVATION_CONTROL_MECHANISM_SUDO_CACHING_FILE", "Privilege Escalation", "T1548.003", "https://attack.mitre.org/techniques/T1548/003/", "Linux", SeverityLevel::Medium, true, abuse_elevation_control_mechanism_sudo_caching_file));

        // event_rules.emplace_back(
        //     std::make_tuple("MODIFY_SYSTEM_PROCESS_SYSTEMD_SERVICE_FILE", "Privilege Escalation", "T1543.002", "https://attack.mitre.org/techniques/T1543/002/", "Linux", SeverityLevel::Medium, true, modify_system_process_systemd_service_file));

        event_rules.emplace_back(
            std::make_tuple("PROCESS_INJECTION_PROC_MEMORY_FILE", "Privilege Escalation", "T1055.009", "https://attack.mitre.org/techniques/T1055/009/", "Linux", SeverityLevel::High, true, process_injection_proc_memory_file));

        // event_rules.emplace_back(
        //     std::make_tuple("BOOT_LOGON_INITIALIZATION_SCRIPTS_RC_SCRIPTS_FILE", "Privilege Escalation", "T1037.004", "https://attack.mitre.org/techniques/T1037/004/", "Linux", SeverityLevel::Medium, true, boot_logon_initialization_scripts_rc_scripts_file));

        event_rules.emplace_back(
            std::make_tuple("CHAOS_MALWARE_INFECTION", "User Execution", "T1204.002", "https://attack.mitre.org/techniques/T1204/002/", "Linux", SeverityLevel::High, true, chaos_malware_infection));

        event_rules.emplace_back(
            std::make_tuple("Attempt to stop a service", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489/", "Linux", SeverityLevel::High, true, service_stop_one));

        event_rules.emplace_back(
            std::make_tuple("Attempt to stop a service", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489/", "Linux", SeverityLevel::High, true, service_stop_two));

        event_rules.emplace_back(
            std::make_tuple("Attempt to stop a service", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489/", "Linux", SeverityLevel::High, true, service_stop_three));

        event_rules.emplace_back(
            std::make_tuple("Defacement: Internal Defacement", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489/", "Linux", SeverityLevel::High, true, internal_defacement_one));

        event_rules.emplace_back(
            std::make_tuple("Defacement: Internal Defacement", "Impact", "T1491.001", "https://attack.mitre.org/techniques/T1489/", "Linux", SeverityLevel::High, true, internal_defacement_two));

        event_rules.emplace_back(
            std::make_tuple("Data Encrypted for Impact", "Impact", "T1486", "https://attack.mitre.org/techniques/T1486/", "Linux", SeverityLevel::High, true, data_encrypted_impact));

        event_rules.emplace_back(
            std::make_tuple("DD File Overwrite", "Impact", "T1485", "https://attack.mitre.org/techniques/T1485/", "Linux", SeverityLevel::Low, true, dd_file_overwrite));

        event_rules.emplace_back(
            std::make_tuple("Potential Linux Process Code Injection Via DD Utility", "Defence Evasion", "T1055.009", "https://attack.mitre.org/techniques/T1055/009/", "Linux", SeverityLevel::Medium, true, potential_linux_process_code_injection_via_DD_utility));

        event_rules.emplace_back(
            std::make_tuple("Ufw Force Stop Using Ufw-Init", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004/", "Linux", SeverityLevel::Medium, true, ufw_force_stop_using_ufw_init));

        event_rules.emplace_back(
            std::make_tuple("Linux Doas Tool Execution", "Privilege Escalation", "T1548", "https://attack.mitre.org/techniques/T1548/", "Linux", SeverityLevel::Low, true, linux_doas_tool_execution));

        event_rules.emplace_back(
            std::make_tuple("ESXi Network Configuration Discovery Via ESXCLI", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033/", "Linux", SeverityLevel::Medium, true, ESXi_network_configuration_discovery_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi Admin Permission Assigned To Account Via ESXCLI", "Execution", "TA0002", "https://attack.mitre.org/tactics/TA0002/", "Linux", SeverityLevel::High, true, ESXi_admin_permission_assigned_to_account_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi Storage Information Discovery Via ESXCLI", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033/", "Linux", SeverityLevel::Medium, true, ESXi_storage_information_discovery_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi Syslog Configuration Change Via ESXCLI", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001/", "Linux", SeverityLevel::Medium, true, ESXi_syslog_configuration_change_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi System Information Discovery Via ESXCLI", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033/", "Linux", SeverityLevel::Medium, true, ESXi_system_information_discovery_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi Account Creation Via ESXCLI", "Persistence", "T1136", "https://attack.mitre.org/techniques/T1136/", "Linux", SeverityLevel::Medium, true, ESXi_account_creation_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi VM List Discovery Via ESXCLI", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033/", "Linux", SeverityLevel::Medium, true, ESXi_VM_list_discovery_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi VM Kill Via ESXCLI", "Execution", "TA0002", "https://attack.mitre.org/tactics/TA0002/", "Linux", SeverityLevel::Medium, true, ESXi_VM_kill_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("ESXi VSAN Information Discovery Via ESXCLI", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033/", "Linux", SeverityLevel::Medium, true, ESXi_VSAN_information_discovery_via_ESXCLI));

        event_rules.emplace_back(
            std::make_tuple("File Deletion", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004/", "Linux", SeverityLevel::Low, true, file_deletion));

        event_rules.emplace_back(
            std::make_tuple("OS Architecture Discovery Via Grep", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082/", "Linux", SeverityLevel::Low, true, OS_architecture_discovery_via_grep));

        event_rules.emplace_back(
            std::make_tuple("Group Has Been Deleted Via Groupdel", "Impact", "T1531", "https://attack.mitre.org/techniques/T1531/", "Linux", SeverityLevel::Low, true, group_has_been_deleted_via_groupdel));

        event_rules.emplace_back(
            std::make_tuple("Apt GTFOBin Abuse - Linux", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083/", "Linux", SeverityLevel::Medium, true, apt_GTFOBin_abuse_linux));

        event_rules.emplace_back(
            std::make_tuple("Vim GTFOBin Abuse - Linux", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083/", "Linux", SeverityLevel::High, true, vim_GTFOBin_abuse_linux));

        event_rules.emplace_back(
            std::make_tuple("Install Root Certificate", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004/", "Linux", SeverityLevel::Low, true, linux_install_root_certificate));

        event_rules.emplace_back(
            std::make_tuple("Linux HackTool Execution", "Execution", "T1587", "https://attack.mitre.org/techniques/T1587", "Linux", SeverityLevel::High, true, linux_hacktool_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Container Discovery Via Inodes Listing", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::Low, true, potential_container_discovery_via_inodes_listing));

        event_rules.emplace_back(
            std::make_tuple("Interactive Bash Suspicious Children", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Linux", SeverityLevel::Medium, true, interactive_bash_suspicious_children));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Java Children Processes", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, suspicious_java_children_processes));

        event_rules.emplace_back(
            std::make_tuple("Linux Network Service Scanning Tools Execution", "Discovery", "T1046", "https://attack.mitre.org/techniques/T1046", "Linux", SeverityLevel::Low, true, linux_network_service_scanning_tools_execution));

        event_rules.emplace_back(
            std::make_tuple("Linux Shell Pipe to Shell", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Medium, true, linux_shell_pipe_to_shell));

        event_rules.emplace_back(
            std::make_tuple("Linux Recon Indicators", "Credential Access", "T1592.004", "https://attack.mitre.org/techniques/T1592/004", "Linux", SeverityLevel::High, true, linux_recon_indicators));

        event_rules.emplace_back(
            std::make_tuple("Potential Suspicious Change To Sensitive/Critical Files", "Impact", "T1565.001", "https://attack.mitre.org/techniques/T1565/001", "Linux", SeverityLevel::Medium, true, potential_suspicious_change_to_sensitive_critical_files));

        event_rules.emplace_back(
            std::make_tuple("Shell Execution Of Process Located In Tmp Directory", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, shell_execution_of_process_located_in_tmp_directory));

        event_rules.emplace_back(
            std::make_tuple("Execution Of Script Located In Potentially Suspicious Directory", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::Medium, true, execution_of_script_located_in_potentially_suspicious_directory));

        // event_rules.emplace_back(
        //     std::make_tuple("System Information Discovery", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::Information, true, linux_system_information_discovery));

        event_rules.emplace_back(
            std::make_tuple("System Network Connections Discovery - Linux", "Discovery", "T1049", "https://attack.mitre.org/techniques/T1049", "Linux", SeverityLevel::Low, true, system_network_connections_discovery_linux));

        // event_rules.emplace_back(
        //     std::make_tuple("System Network Discovery - Linux", "Discovery", "T1016", "https://attack.mitre.org/techniques/T1016", "Linux", SeverityLevel::Information, true, system_network_discovery_linux));

        event_rules.emplace_back(
            std::make_tuple("Touch Suspicious Service File", "Defence Evasion", "T1070.006", "https://attack.mitre.org/techniques/T1070/006", "Linux", SeverityLevel::Medium, true, touch_suspicious_service_file));

        event_rules.emplace_back(
            std::make_tuple("Triple Cross eBPF Rootkit Execve Hijack", "Defence Evasion", "T1070.006", "https://attack.mitre.org/techniques/T1070/006", "Linux", SeverityLevel::High, true, triple_cross_ebpf_rootkit_execve_hijack));

        event_rules.emplace_back(
            std::make_tuple("Triple Cross eBPF Rootkit Install Commands", "Defence Evasion", "T1014", "https://attack.mitre.org/techniques/T1014", "Linux", SeverityLevel::High, true, triple_cross_ebpf_rootkit_install_commands));

        event_rules.emplace_back(
            std::make_tuple("User Has Been Deleted Via Userdel", "Impact", "T1531", "https://attack.mitre.org/techniques/T1531", "Linux", SeverityLevel::Medium, true, user_has_been_deleted_via_userdel));

        event_rules.emplace_back(
            std::make_tuple("User Added To Root/Sudoers Group Using Usermod", "Impact", "T1548", "https://attack.mitre.org/techniques/T1548", "Linux", SeverityLevel::Medium, true, user_added_to_root_sudoers_group_using_usermod));

        event_rules.emplace_back(
            std::make_tuple("Download File To Potentially Suspicious Directory Via Wget", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Linux", SeverityLevel::Medium, true, download_file_to_potentially_suspicious_directory_via_wget));

        event_rules.emplace_back(
            std::make_tuple("Potential Xterm Reverse Shell", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::Medium, true, potential_xterm_reverse_shell));

        event_rules.emplace_back(
            std::make_tuple("Linux Base64 Encoded Pipe to Shell", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Medium, true, linux_base64_encoded_pipe_shell));

        event_rules.emplace_back(
            std::make_tuple("Linux Base64 Encoded Shebang In CLI", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Linux", SeverityLevel::Medium, true, linux_base64_encoded_shebang_cli));

        event_rules.emplace_back(
            std::make_tuple("Bash Interactive Shell", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Linux", SeverityLevel::Low, true, bash_interactive_shell));

        event_rules.emplace_back(
            std::make_tuple("Enable BPF Kprobes Tracing", "Execution", "TA002", "https://attack.mitre.org/tactics/TA0002", "Linux", SeverityLevel::Medium, true, enable_bpf_kprobes_tracing));

        event_rules.emplace_back(
            std::make_tuple("BPFtrace Unsafe Option Usage", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Linux", SeverityLevel::Medium, true, bpftrace_unsafe_option_usage));

        event_rules.emplace_back(
            std::make_tuple("Capabilities Discovery - Linux", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083/", "Linux", SeverityLevel::Low, true, bpftrace_unsafe_option_usage));

        event_rules.emplace_back(
            std::make_tuple("Cat Sudoers", "Reconnaissance", "T1592.004 ", "https://attack.mitre.org/techniques/T1592/004 ", "Linux", SeverityLevel::Medium, true, cat_sudoers));

        event_rules.emplace_back(
            std::make_tuple("Remove Immutable File Attribute", "Defence Evasion", "T1222.002", "https://attack.mitre.org/techniques/T1222/002", "Linux", SeverityLevel::Medium, true, remove_immutable_file_attribute));

        event_rules.emplace_back(
            std::make_tuple("Clear Linux Logs", "Defence Evasion", "T1070.002", "https://attack.mitre.org/techniques/T1070/002", "Linux", SeverityLevel::Medium, true, clear_linux_logs));

        event_rules.emplace_back(
            std::make_tuple("Commands to Clear or Remove the Syslog", "Defence Evasion", "T1070.002", "https://attack.mitre.org/techniques/T1070/002", "Linux", SeverityLevel::High, true, commands_to_clear_remove_syslog));

        event_rules.emplace_back(
            std::make_tuple("Remove Scheduled Cron Task/Job", "Defence Evasion", "T1053.003", "https://attack.mitre.org/techniques/T1053/003", "Linux", SeverityLevel::Medium, true, remove_scheduled_cron_task));

        event_rules.emplace_back(
            std::make_tuple("Linux Crypto Mining Indicators", "Impact", "T1496", "https://attack.mitre.org/techniques/T1496", "Linux", SeverityLevel::High, true, crypto_mining_indicators));

        event_rules.emplace_back(
            std::make_tuple("Copy Passwd Or Shadow From TMP Path", "Credential Access", "T1552.001", "https://attack.mitre.org/techniques/T1552/001", "Linux", SeverityLevel::High, true, copy_password_shadow_tmp_path));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Netcat Reverse Shell Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, potential_netcat_reverse_shell_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Perl Reverse Shell Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, potential_perl_reverse_shell_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential PHP Reverse Shell", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, potential_php_reverse_shell));

        event_rules.emplace_back(
            std::make_tuple("Potential Python Reverse Shell", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, potential_python_reverse_shell));

        event_rules.emplace_back(
            std::make_tuple("Potential Ruby Reverse Shell", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, potential_ruby_reverse_shell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Reverse Shell Command Line", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Linux", SeverityLevel::High, true, suspicious_reverse_shell_command_line));

        event_rules.emplace_back(
            std::make_tuple("Linux Remote System Discovery", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018", "Linux", SeverityLevel::Low, true, linux_remote_system_discovery));

        event_rules.emplace_back(
            std::make_tuple("Linux Package Uninstall", "Defence Evasion", "T1070", "https://attack.mitre.org/techniques/T1070", "Linux", SeverityLevel::Low, true, linux_package_uninstall));

        event_rules.emplace_back(
            std::make_tuple("Potential Ruby Reverse Shell", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::Medium, true, potential_ruby_reverse_shell));

        event_rules.emplace_back(
            std::make_tuple("Scheduled Cron Task/Job", "Privilege Escalation", "T1053.003", "https://attack.mitre.org/techniques/T1053/003", "Linux", SeverityLevel::Medium, true, scheduled_cron_task_job));

        event_rules.emplace_back(
            std::make_tuple("Security Software Discovery", "Dicovery", "T1518.001", "https://attack.mitre.org/techniques/T1518/001", "Linux", SeverityLevel::Low, true, security_software_dicovery));

        event_rules.emplace_back(
            std::make_tuple("Disabling Security Tools", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::Medium, true, disabling_security_tools));

        event_rules.emplace_back(
            std::make_tuple("Disable Or Stop Services", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::Medium, true, disable_or_stop_services));

        event_rules.emplace_back(
            std::make_tuple("Setuid and Setgid", "Persistence", "T1548.001", "https://attack.mitre.org/techniques/T1548/001", "Linux", SeverityLevel::Low, true, setuid_and_setgid));

        event_rules.emplace_back(
            std::make_tuple("Potential Linux Amazon SSM Agent Hijacking", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Linux", SeverityLevel::Medium, true, potential_linux_amazon_ssm_agent_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Sudo Privilege Escalation", "Privilege Escalation", "T1548.003", "https://attack.mitre.org/techniques/T1548/003", "Linux", SeverityLevel::High, true, sudo_privilege_escalation));

        event_rules.emplace_back(
            std::make_tuple("Chmod Suspicious Directory", "Defence Evasion", "T1222.002", "https://attack.mitre.org/techniques/T1222/002", "Linux", SeverityLevel::Medium, true, chmod_suspicious_directory));

        event_rules.emplace_back(
            std::make_tuple("Container Residence Discovery Via Proc Virtual FS", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::Low, true, container_residence_discovery_via_proc_virtual_fs));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Curl File Upload", "Exfiltration", "T1567", "https://attack.mitre.org/techniques/T1567", "Linux", SeverityLevel::Medium, true, suspicious_curl_file_upload));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Curl Change User Agents", "Command and Control", "T1071.001", "https://attack.mitre.org/techniques/T1071/001", "Linux", SeverityLevel::Medium, true, suspicious_curl_change_user_agents));

        event_rules.emplace_back(
            std::make_tuple("Docker Container Discovery Via Dockerenv Listing", "Dicovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::Low, true, docker_container_discovery_via_dockerenv_listing));

        event_rules.emplace_back(
            std::make_tuple("Execution From Tmp Folder", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Linux", SeverityLevel::Information, true, potentially_suspicious_execution_from_tmp_folder));

        event_rules.emplace_back(
            std::make_tuple("Potential Discovery Activity Using Find", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083", "Linux", SeverityLevel::Medium, true, potential_discovery_activity_using_find));

        event_rules.emplace_back(
            std::make_tuple("History File Deletion", "Impact", "T1565.001", "https://attack.mitre.org/techniques/T1565/001", "Linux", SeverityLevel::High, true, history_file_deletion));

        // Chirag Rules

        event_rules.emplace_back(
            std::make_tuple("Package Installed - Linux", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004", "Linux", SeverityLevel::Information, true, suspicious_package_installed_linux));

        event_rules.emplace_back(
            std::make_tuple("Flush Iptables Ufw Chain", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Linux", SeverityLevel::Medium, true, flush_iptables_ufw_chain));

        event_rules.emplace_back(
            std::make_tuple("Terminate Linux Process Via Kill", "Defence Evasion", "T1562", "https://attack.mitre.org/techniques/T1562", "Linux", SeverityLevel::Low, true, terminate_linux_process_via_kill));

        // event_rules.emplace_back(
        //     std::make_tuple("Local System Accounts Discovery - Linux", "Discovery", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Linux", SeverityLevel::Low, true, local_system_accounts_discovery_linux));

        event_rules.emplace_back(
            std::make_tuple("Local Groups Discovery - Linux", "Discovery", "T1069.001", "https://attack.mitre.org/techniques/T1069/001", "Linux", SeverityLevel::Low, true, local_group_discovery_linux));

        event_rules.emplace_back(
            std::make_tuple("Potential GobRAT File Discovery Via Grep", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Linux", SeverityLevel::High, true, potential_gobrat_file_discovery_via_grep));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Named Pipe Created Via Mkfifo", "Execution", "-", "https://attack.mitre.org/techniques", "Linux", SeverityLevel::Medium, true, potentially_suspicious_named_pipe_created_via_mkfifo));

        event_rules.emplace_back(
            std::make_tuple("Named Pipe Created Via Mkfifo", "Execution", "-", "https://attack.mitre.org/techniques", "Linux", SeverityLevel::Information, true, named_pipe_created_via_mkfifo));

        event_rules.emplace_back(
            std::make_tuple("Mount Execution With Hidepid Parameter", "Credential Access", "T1564", "https://attack.mitre.org/techniques/T1564", "Linux", SeverityLevel::Medium, true, mount_execution_with_hidepid_parameter));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Nohup Execution", "Execution", "T1564", "https://attack.mitre.org/techniques/T1564", "Linux", SeverityLevel::Medium, true, suspicious_nohup_execution));

        event_rules.emplace_back(
            std::make_tuple("Nohup Execution", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Linux", SeverityLevel::Information, true, nohup_execution));

        event_rules.emplace_back(
            std::make_tuple("OMIGOD SCX RunAsProvider ExecuteScript or Shell", "Priviledge Escalation", "T1068", "https://attack.mitre.org/techniques/T1068", "Linux", SeverityLevel::High, true, omigod_scx_runasprovider_executescript));

        // event_rules.emplace_back(
        //     std::make_tuple("OMIGOD SCX RunAsProvider ExecuteShellCommand", "Priviledge Escalation", "T1068", "https://attack.mitre.org/techniques/T1068", "Linux", SeverityLevel::High, true, omigod_scx_runasprovider_executeshellcommand));

        // event_rules.emplace_back(
        //     std::make_tuple("Process Discovery", "Discovery", "T1057", "https://attack.mitre.org/techniques/T1057", "Linux", SeverityLevel::Information, true, process_discovery));

        event_rules.emplace_back(
            std::make_tuple("Connection Proxy", "Defence Evasion", "T1090", "https://attack.mitre.org/techniques/T1090", "Linux", SeverityLevel::Low, true, connection_proxy));

        event_rules.emplace_back(
            std::make_tuple("Python Spawning Pretty TTY", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Linux", SeverityLevel::High, true, python_spawning_pretty_tty));

        event_rules.emplace_back(
            std::make_tuple("Linux Package Uninstall", "Defence Evasion", "T1070", "https://attack.mitre.org/techniques/T1070", "Linux", SeverityLevel::Low, true, linux_package_uninstall));

        event_rules.emplace_back(
            std::make_tuple("XZ and liblzma vulnerable packages", "Discovery", "TA0007", "https://attack.mitre.org/tactics/TA0007/", "Linux", SeverityLevel::Medium, true, xzvuln));


        // Windows

        event_rules.emplace_back(
            std::make_tuple("SCHEDULED_TASK_JOB", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005/", "Windows", SeverityLevel::High, true, scheduled_task_job));

        event_rules.emplace_back(
            std::make_tuple("NATIVE_API", "Execution", "T1106", "https://attack.mitre.org/techniques/T1106/", "Windows", SeverityLevel::High, true, native_api));

        event_rules.emplace_back(
            std::make_tuple("COMMAND_AND_SCRIPTING_INTERPRETER", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059/", "Windows", SeverityLevel::High, true, command_and_scripting_interpreter));

        event_rules.emplace_back(
            std::make_tuple("SERVICE_EXECUTION", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002/", "Windows", SeverityLevel::High, true, service_execution));

        event_rules.emplace_back(
            std::make_tuple("COMMAND_AND_SCRIPTING_INTERPRETER: JAVASCRIPT", "Execution", "T1059.007", "https://attack.mitre.org/techniques/T1059/007/", "Windows", SeverityLevel::High, true, command_scripting_interpreter_javascript));

        event_rules.emplace_back(
            std::make_tuple("COMMAND_AND_SCRIPTING_INTERPRETER: POWERSHELL", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::High, true, command_scripting_interpreter_powershell));

        event_rules.emplace_back(
            std::make_tuple("COMMAND_AND_SCRIPTING_INTERPRETER: WINDOWS COMMAND SHELL", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003/", "Windows", SeverityLevel::High, true, command_scripting_interpreter_win_command_shell));

        event_rules.emplace_back(
            std::make_tuple("COMMAND_AND_SCRIPTING_INTERPRETER: VISUAL BASIC", "Execution", "T1059.005", "https://attack.mitre.org/techniques/T1059/005/", "Windows", SeverityLevel::High, true, command_scripting_interpreter_visual_basic));

        event_rules.emplace_back(
            std::make_tuple("User Execution: Malicious File", "Execution", "T1204.002", "https://attack.mitre.org/techniques/T1204/002", "Windows", SeverityLevel::High, true, malicious_file_user_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("BITS_jobs", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197/", "Windows", SeverityLevel::High, true, BITS_jobs));

        event_rules.emplace_back(
            std::make_tuple("Valid accounts: Default accounts", "Defence Evasion", "T1078.001", "https://attack.mitre.org/techniques/T1078/001/", "Windows", SeverityLevel::High, true, escalate_guest));

        // event_rules.emplace_back(
        // std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/","Windows", SeverityLevel::High, true, registry_modification));

        event_rules.emplace_back(
            std::make_tuple("Indirect Command Execution", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202/", "Windows", SeverityLevel::High, true, indirect_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Use Alternate Authentication Material", "Defence Evasion", "T1550.003", "https://attack.mitre.org/techniques/T1550/003/", "Windows", SeverityLevel::High, true, alternate_authentication));

        event_rules.emplace_back(
            std::make_tuple("Indicator Removal", "Defence Evasion", "T1070", "https://attack.mitre.org/techniques/T1070/", "Windows", SeverityLevel::High, true, indicator_removal));

        event_rules.emplace_back(
            std::make_tuple("Impair Defenses: Indicator Blocking", "Defence Evasion", "T1562.006", "https://attack.mitre.org/techniques/T1562/006/", "Windows", SeverityLevel::High, true, disable_powershell_etw));

        event_rules.emplace_back(
            std::make_tuple("Create process with token", "Defence Evasion", "T1134.002", "https://attack.mitre.org/techniques/T1134/002/", "Windows", SeverityLevel::High, true, create_process_with_token));

        event_rules.emplace_back(
            std::make_tuple("Process Hollowing", "Defence Evasion", "T1055.012", "https://attack.mitre.org/techniques/T1055/012/", "Windows", SeverityLevel::High, true, process_hollowing));

        event_rules.emplace_back(
            std::make_tuple("File and Directory Permissions Modification: Windows File and Directory Permissions Modification", "", "Defence Evasion", "T1222.001", "https://attack.mitre.org/techniques/T1222/001/", SeverityLevel::High, true, grant_access_to_C));

        event_rules.emplace_back(
            std::make_tuple("Hide Artifacts: Hidden Files and Directories", "Defence Evasion", "T1564.001", "https://attack.mitre.org/techniques/T1564/001/", "Windows", SeverityLevel::High, true, hide_artifacts));

        event_rules.emplace_back(
            std::make_tuple("Masquerading", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036/", "Windows", SeverityLevel::High, true, masquerading));

        event_rules.emplace_back(
            std::make_tuple("Trusted Developer Utilities Proxy Execution", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127/", "Windows", SeverityLevel::High, true, proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("Abuse Elevation Control Mechanism: Bypass User Account Control", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, bypass_user_account_control));

        event_rules.emplace_back(
            std::make_tuple("XSL Script Processing", "Defence Evasion", "T1220", "https://attack.mitre.org/techniques/T1220", "Windows", SeverityLevel::High, true, xsl_script_processing));

        event_rules.emplace_back(
            std::make_tuple("System Binary Proxy Execution: Mshta", "Defence Evasion", "T1218.005", "https://attack.mitre.org/techniques/T1218/005", "Windows", SeverityLevel::High, true, mshta));

        event_rules.emplace_back(
            std::make_tuple("System Binary Proxy Execution: Regsvr32", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::High, true, system_binary_proxy_execution_regsvr32));

        // event_rules.emplace_back(
        //     std::make_tuple("System Binary Proxy Execution: Msiexec", "Defence Evasion", "T1218.007", "https://attack.mitre.org/techniques/T1218/007", "Windows", SeverityLevel::High, true, system_binary_proxy_execution_msiexec));

        event_rules.emplace_back(
            std::make_tuple("Trusted Developer Utilities Proxy Execution: MSBuild", "Defence Evasion", "T1127.001", "https://attack.mitre.org/techniques/T1127/001", "Windows", SeverityLevel::High, true, proxy_execution_msbuild));

        event_rules.emplace_back(
            std::make_tuple("System Binary Proxy Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218/", "Windows", SeverityLevel::High, true, system_binary_proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("System Binary Proxy Execution: Rundll32", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011/", "Windows", SeverityLevel::High, true, system_binary_proxy_execution_rundll32));

        event_rules.emplace_back(
            std::make_tuple("Hijack Execution Flow: DLL Side-Loading", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574/002/", "Windows", SeverityLevel::High, true, dll_side_loading));

        event_rules.emplace_back(
            std::make_tuple("Hide Artifacts: NTFS File Attributes", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004/", "Windows", SeverityLevel::High, true, ntfs_file_attributes));

        event_rules.emplace_back(
            std::make_tuple("Indicator Removal: Clear Command History", "Defence Evasion", "T1070.003", "https://attack.mitre.org/techniques/T1070/003/", "Windows", SeverityLevel::High, true, clear_command_history));

        event_rules.emplace_back(
            std::make_tuple("Obfuscated Files or Information", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027/", "Windows", SeverityLevel::High, true, obfuscated_files_or_information));

        event_rules.emplace_back(
            std::make_tuple("Process Injection", "Defence Evasion", "T1055", "https://attack.mitre.org/techniques/T1055/", "Windows", SeverityLevel::High, true, process_injection));

        event_rules.emplace_back(
            std::make_tuple("Indicator Removal: File Deletion", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::High, true, indicator_removal_file_deletion));

        event_rules.emplace_back(
            std::make_tuple("Hide Artifacts: Hidden Window", "Defence Evasion", "T1564.003", "https://attack.mitre.org/techniques/T1564/003", "Windows", SeverityLevel::High, true, hidden_window_hide_artifacts));

        event_rules.emplace_back(
            std::make_tuple("Impair Defenses: Disable or Modify Tools", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, impair_defenses_disable_modify_tools));

        event_rules.emplace_back(
            std::make_tuple("Subvert Trust Controls: Install Root Certificate", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004", "Windows", SeverityLevel::High, true, install_root_certificate));

        event_rules.emplace_back(
            std::make_tuple("System Binary Proxy Execution: InstallUtil", "Defence Evasion", "T1218.004", "https://attack.mitre.org/techniques/T1218/004", "Windows", SeverityLevel::High, true, system_binary_proxy_execution_installutil));

        event_rules.emplace_back(
            std::make_tuple("Deobfuscate/Decode Files or Information", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Windows", SeverityLevel::High, true, decode_files_or_information));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_netwire));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_ursnif));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_terminal_server_client));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_blackbyte));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_load_service_safemode));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_disable_win_registry_tool));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_disable_win_security_notifications));

        event_rules.emplace_back(
            std::make_tuple("Modify Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112/", "Windows", SeverityLevel::High, true, modify_registry_win_group_policy_feature));

        event_rules.emplace_back(
            std::make_tuple("Impair Defenses: Disable or Modify Tools", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, impair_defenses_disable_modify_tools_AMSI_Byspass));

        event_rules.emplace_back(
            std::make_tuple("Impair Defenses: Disable or Modify Tools", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, impair_defenses_disable_modify_tools_office_security));

        event_rules.emplace_back(
            std::make_tuple("Impair Defenses: Disable or Modify System Firewall", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::High, true, impair_defenses_disable_defender_firewall));

        event_rules.emplace_back(
            std::make_tuple("Hijack Execution Flow: COR_PROFILER", "Defence Evasion", "T1574.012", "https://attack.mitre.org/techniques/T1574/012", "Windows", SeverityLevel::High, true, user_scope_cor_profile));

        event_rules.emplace_back(
            std::make_tuple("Impair Defenses: Disable or Modify Tools", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, impair_defenses_tamper_win_defender));

        event_rules.emplace_back(
            std::make_tuple("Hide Artifacts: Hidden Files and Directories", "Defence Evasion", "T1564.001", "https://attack.mitre.org/techniques/T1564/001", "Windows", SeverityLevel::High, true, hide_artifacts_through_registry));

        event_rules.emplace_back(
            std::make_tuple("Subvert Trust Controls: Install Root Certificate", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004", "Windows", SeverityLevel::High, true, install_root_certificate_win_certutil));

        event_rules.emplace_back(
            std::make_tuple("Indicator Removal: File Deletion", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::High, true, indicator_removal_del_single_file));

        event_rules.emplace_back(
            std::make_tuple("Scheduled Task/Job: Scheduled Task", "Privilege Escalation", "T1053.005", "https://attack.mitre.org/techniques/T1053/005/", "Windows", SeverityLevel::Medium, true, scheduled_task));

        // event_rules.emplace_back(
        //     std::make_tuple("Create or Modify System Process: Windows Service", "Privilege Escalation", "T1543.003", "https://attack.mitre.org/techniques/T1543/003/", "Windows", SeverityLevel::High, true, create_or_modify_windows_process));

        // event_rules.emplace_back(
        //     std::make_tuple("Event Triggered Execution: Application Shimming", "Privilege Escalation", "T1546.011", "https://attack.mitre.org/techniques/T1546/011/", "Windows", SeverityLevel::High, true, application_shimming));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Netsh Helper DLL", "Privilege Escalation", "T1546.007", "https://attack.mitre.org/techniques/T1546/007/", "Windows", SeverityLevel::High, true, netsh_helper_dll));

        // event_rules.emplace_back(
        //     std::make_tuple("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Privilege Escalation", "T1547.001", "https://attack.mitre.org/techniques/T1547/001/", "Windows", SeverityLevel::High, true, registry_run_keys));

        event_rules.emplace_back(
            std::make_tuple("Access Token Manipulation: SID-History Injection", "Privilege Escalation", "T1134.005", "https://attack.mitre.org/techniques/T1134/005/", "Windows", SeverityLevel::High, true, sid_history_injection));

        event_rules.emplace_back(
            std::make_tuple("Hijack Execution Flow: DLL Search Order Hijacking ", "Privilege Escalation", "T1574.001", "https://attack.mitre.org/techniques/T1574/001/", "Windows", SeverityLevel::High, true, dll_search_order_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Process Injection: Thread execution Hijacking", "Privilege Escalation", "T1055.003", "https://attack.mitre.org/techniques/T1055/003/", "Windows", SeverityLevel::High, true, thread_execution_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Access Token Manipulation: Parent PID Spoofing", "Privilege Escalation", "T1134.004", "https://attack.mitre.org/techniques/T1134/004/", "Windows", SeverityLevel::High, true, pid_parent_spoofing));

        event_rules.emplace_back(
            std::make_tuple("System Binary Proxy Execution: CMSTP", "Privilege Escalation", "T1218.003", "https://attack.mitre.org/techniques/T1218/003/", "Windows", SeverityLevel::High, true, cmstp));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Accessibility Features", "Privilege Escalation", "T1546.008", "https://attack.mitre.org/techniques/T1546/008/", "Windows", SeverityLevel::High, true, event_triggered_execution_accessibility_features));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Security Support Provider", "Privilege Escalation", "T1547.005", "https://attack.mitre.org/techniques/T1547/005/", "Windows", SeverityLevel::High, true, security_support_provider));

        event_rules.emplace_back(
            std::make_tuple("Domain Policy Modification: Group Policy Modification", "Privilege Escalation", "T1484.001", "https://attack.mitre.org/techniques/T1484/001/", "Windows", SeverityLevel::High, true, group_policy_modification));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Image File Execution Options Injection", "Privilege Escalation", "T1546.012", "https://attack.mitre.org/techniques/T1546/012", "Windows", SeverityLevel::High, true, image_file_execution_options_injection));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Winlogon Helper DLL", "Privilege Escalation", "T1547.004", "https://attack.mitre.org/techniques/T1547/004/", "Windows", SeverityLevel::High, true, winlogon_helper_dll));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Component Object Model Hijacking", "Privilege Escalation", "T1546.015", "https://attack.mitre.org/techniques/T1546/015", "Windows", SeverityLevel::High, true, com_hijacking_inprocserver32));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Winlogon Helper DLL", "Privilege Escalation", "T1547.004", "https://attack.mitre.org/techniques/T1547/004/", "Windows", SeverityLevel::High, true, winlogon_notify_key_logon));

        event_rules.emplace_back(
            std::make_tuple("Screen Capture", "Collection", "T1113", "https://attack.mitre.org/techniques/T1113", "Windows", SeverityLevel::High, true, screen_capture));

        event_rules.emplace_back(
            std::make_tuple("Data Staged: Local Data Staging", "Collection", "T1074.001", "https://attack.mitre.org/techniques/T1074/001/", "Windows", SeverityLevel::High, true, data_staged));

        event_rules.emplace_back(
            std::make_tuple("Automated Collection", "Collection", "T1119", "https://attack.mitre.org/techniques/T1119", "Windows", SeverityLevel::High, true, automated_collection));

        event_rules.emplace_back(
            std::make_tuple("Clipboard Data", "Collection", "T1115", "https://attack.mitre.org/techniques/T1115", "Windows", SeverityLevel::High, true, clipboard_data));

        event_rules.emplace_back(
            std::make_tuple("Archive Collected Data", "Collection", "T1560", "https://attack.mitre.org/techniques/T1560", "Windows", SeverityLevel::High, true, archive_collected_data));

        event_rules.emplace_back(
            std::make_tuple("Video Capture", "Collection", "T1125", "https://attack.mitre.org/techniques/T1125", "Windows", SeverityLevel::High, true, video_capture));

        event_rules.emplace_back(
            std::make_tuple("Data from Network Shared Drive", "Collection", "T1039", "https://attack.mitre.org/techniques/T1039", "Windows", SeverityLevel::High, true, network_shared_drive_data));

        event_rules.emplace_back(
            std::make_tuple("Audio Capture", "Collection", "T1123", "https://attack.mitre.org/techniques/T1123", "Windows", SeverityLevel::High, true, audio_capture));

        event_rules.emplace_back(
            std::make_tuple("Input Capture: GUI Input Capture", "Collection", "T1056.002", "https://attack.mitre.org/techniques/T1056/002", "Windows", SeverityLevel::High, true, gui_input_capture));

        event_rules.emplace_back(
            std::make_tuple("Group Policy Discovery", "Discovery", "T1615", "https://attack.mitre.org/techniques/T1615", "Windows", SeverityLevel::High, true, group_policy_discovery));

        event_rules.emplace_back(
            std::make_tuple("Browser Information Discovery", "Discovery", "T1217", "https://attack.mitre.org/techniques/T1217", "Windows", SeverityLevel::High, true, browser_information_discovery));

        event_rules.emplace_back(
            std::make_tuple("Account Discovery: Domain Account", "Discovery", "T1087.002", "https://attack.mitre.org/techniques/T1087/002", "Windows", SeverityLevel::High, true, account_discovery_domain_account));

        // event_rules.emplace_back(
        //     std::make_tuple("System Information Discovery", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Windows", SeverityLevel::High, true, system_information_discovery));

        event_rules.emplace_back(
            std::make_tuple("Domain Trust Discovery", "Discovery", "T1482", "https://attack.mitre.org/techniques/T1482", "Windows", SeverityLevel::High, true, domain_trust_discovery));

        event_rules.emplace_back(
            std::make_tuple("File and Directory Discovery", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083", "Windows", SeverityLevel::High, true, file_and_directory_discovery));

        event_rules.emplace_back(
            std::make_tuple("Software Discovery: Security Software Discovery", "Discovery", "T1518.001", "https://attack.mitre.org/techniques/T1518/001", "Windows", SeverityLevel::High, true, win_security_software_discovery));

        event_rules.emplace_back(
            std::make_tuple("System Location Discovery: System Language Discovery", "Discovery", "T1614.001", "https://attack.mitre.org/techniques/T1614/001", "Windows", SeverityLevel::High, true, discover_system_language_chcp));

        event_rules.emplace_back(
            std::make_tuple("Data Encoding: Standard Encoding", "Command and control", "T1132.001", "https://attack.mitre.org/techniques/T1132/001/", "Windows", SeverityLevel::High, true, data_encoding_standard_encoding));

        event_rules.emplace_back(
            std::make_tuple("Application Layer Protocol: DNS", "Command and control", "T1071.004", "https://attack.mitre.org/techniques/T1071/004/", "Windows", SeverityLevel::High, true, dns_large_query_volume));

        // event_rules.emplace_back(
        //     std::make_tuple("Remote Access Software", "Command and control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::High, true, remote_access_software));

        event_rules.emplace_back(
            std::make_tuple("Protocol Tunneling", "Command and control", "T1572", "https://attack.mitre.org/techniques/T1572/", "Windows", SeverityLevel::High, true, code_executed_via_excel));

        event_rules.emplace_back(
            std::make_tuple("Ingress Tool Transfer", "Command and control", "T1105", "https://attack.mitre.org/techniques/T1105/", "Windows", SeverityLevel::High, true, win_ingress_tool_transfer));

        event_rules.emplace_back(
            std::make_tuple("Non Standard Port", "Command and control", "T1571", "https://attack.mitre.org/techniques/T1571/", "Windows", SeverityLevel::High, true, non_standard_port));

        event_rules.emplace_back(
            std::make_tuple("Ingress Tool Transfer", "Command and control", "T1105", "https://attack.mitre.org/techniques/T1105/", "Windows", SeverityLevel::High, true, win_ingress_tool_transfer_certutil));

        event_rules.emplace_back(
            std::make_tuple("Ingress Tool Transfer", "Command and control", "T1105", "https://attack.mitre.org/techniques/T1105/", "Windows", SeverityLevel::High, true, win_ingress_tool_transfer_curl_download));

        event_rules.emplace_back(
            std::make_tuple("Proxy: Internal Proxy", "Command and control", "T1090.001", "https://attack.mitre.org/techniques/T1090/001", "Windows", SeverityLevel::High, true, internal_proxy_portproxy_regkey));

        event_rules.emplace_back(
            std::make_tuple("Ingress Tool Transfer", "Command and control", "T1105", "https://attack.mitre.org/techniques/T1105/", "Windows", SeverityLevel::High, true, win_ingress_tool_transfer_certutil));

        event_rules.emplace_back(
            std::make_tuple("Ingress Tool Transfer", "Command and control", "T1105", "https://attack.mitre.org/techniques/T1105/", "Windows", SeverityLevel::High, true, win_ingress_tool_transfer_curl_download));

        event_rules.emplace_back(
            std::make_tuple("Proxy: Internal Proxy", "Command and control", "T1090.001", "https://attack.mitre.org/techniques/T1090/001", "Windows", SeverityLevel::High, true, internal_proxy_portproxy_regkey));

        event_rules.emplace_back(
            std::make_tuple("Brute Force: Password Guessing", "Credential Access", "T1110.001", "https://attack.mitre.org/techniques/T1110/001/", "Windows", SeverityLevel::High, true, password_guessing));

        event_rules.emplace_back(
            std::make_tuple("Steal Web Session Cookie", "Credential Access", "T1539", "https://attack.mitre.org/techniques/T1539/", "Windows", SeverityLevel::High, true, steal_web_session_cookie));

        event_rules.emplace_back(
            std::make_tuple("Registry dump of SAM, creds, and secrets", "Credential Access", "T1003.002", "https://attack.mitre.org/techniques/T1003/002", "Windows", SeverityLevel::High, true, registry_dump_of_sam_creds_secrets));

        event_rules.emplace_back(
            std::make_tuple("Packet Capture Windows Command Prompt", "Credential Access", "T1040", "https://attack.mitre.org/techniques/T1040/", "Windows", SeverityLevel::High, true, packet_capture_windows_command_prompt));

        event_rules.emplace_back(
            std::make_tuple("Unsecured Credentials: Credentials in Registry", "Credential Access", "1552.002", "https://attack.mitre.org/techniques/T1552/002/", "Windows", SeverityLevel::High, true, enumeration_for_credentials_in_registry));

        event_rules.emplace_back(
            std::make_tuple("Modify Authentication Process: Password Filter DLL", "Credential Access", "1556.002", "https://attack.mitre.org/techniques/T1556/002/", "Windows", SeverityLevel::High, true, install_and_register_paassword_filter_dll));

        event_rules.emplace_back(
            std::make_tuple("Unsecured Credentials: Group Policy Preferences", "Credential Access", "T1552.006", "https://attack.mitre.org/techniques/T1552/006/", "Windows", SeverityLevel::High, true, unsecured_credentials_gpp_passwords));

        event_rules.emplace_back(
            std::make_tuple("OS Credential Dumping: LSASS Memory", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::High, true, lsass_memory_using_comsvcs_dll));

        event_rules.emplace_back(
            std::make_tuple("Brute Force: Password Spraying", "Credential Access", "T1110.003", "https://attack.mitre.org/techniques/T1110/003/", "Windows", SeverityLevel::High, true, password_spraying_kurbute));

        event_rules.emplace_back(
            std::make_tuple("Input Capture: Credential API Hooking", "Credential Access", "T1056.004", "https://attack.mitre.org/techniques/T1056/004/", "", SeverityLevel::High, true, input_capture_credential_api_hooking));

        event_rules.emplace_back(
            std::make_tuple("OS Credential Dumping: DCSync", "Credential Access", "T1003.006", "https://attack.mitre.org/techniques/T1003/006/", "Windows", SeverityLevel::High, true, os_credential_dumping_dcsync));

        event_rules.emplace_back(
            std::make_tuple("Credentials from Password Stores: Windows Credential Manager", "Credential Access", "T1555.004", "https://attack.mitre.org/techniques/T1555/004/", "Windows", SeverityLevel::High, true, password_stores_windows_credentail_manager));

        event_rules.emplace_back(
            std::make_tuple("OS Credential Dumping", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003/", "Windows", SeverityLevel::High, true, os_credential_dumping));

        event_rules.emplace_back(
            std::make_tuple("Forced Authentication", "Credential Access", "T1187", "https://attack.mitre.org/techniques/T1187/", "Windows", SeverityLevel::High, true, forced_authentication));

        event_rules.emplace_back(
            std::make_tuple("Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access", "T1558.003", "https://attack.mitre.org/techniques/T1558/003", "Windows", SeverityLevel::High, true, kerberoasting_steal_or_forge_Kerberos_tickets));

        event_rules.emplace_back(
            std::make_tuple("OS Credential Dumping: Security Account Manager", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, os_credential_dumping_esentutl));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: PowerShell Profile", "Persistence", "T1546.013", "https://attack.mitre.org/techniques/T1546/013/", "Windows", SeverityLevel::High, true, append_malicious_start_process_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("External Remote Services", "Persistence", "T1133", "https://attack.mitre.org/techniques/T1133/", "Windows", SeverityLevel::High, true, running_chrome_vpn_extensions));

        event_rules.emplace_back(
            std::make_tuple("Active Setup", "Persistence", "T1547.014", "https://attack.mitre.org/techniques/T1547/014/", "Windows", SeverityLevel::High, true, active_setup));

        event_rules.emplace_back(
            std::make_tuple("Time Providers", "Persistence", "T1547.03", "https://attack.mitre.org/techniques/T1547/003/", "Windows", SeverityLevel::High, true, time_providers_new));

        event_rules.emplace_back(
            std::make_tuple("Office Application Startup: Add-ins", "Persistence", "T1137.006", "https://attack.mitre.org/techniques/T1137/006/", "Windows", SeverityLevel::High, true, persistent_code_evecution_via_excel_vba_addin));

        event_rules.emplace_back(
            std::make_tuple("Office Application Startup: Add-ins", "Persistence", "T1137.006", "https://attack.mitre.org/techniques/T1137/006/", "Windows", SeverityLevel::High, true, persistent_code_execution_via_word_addin));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Port Monitors", "Persistence", "T1547.010", "https://attack.mitre.org/techniques/T1547/010/", "Windows", SeverityLevel::High, true, port_monitors));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Shortcut Modification", "Persistence", "T1547.009", "https://attack.mitre.org/techniques/T1547/009/", "Windows", SeverityLevel::High, true, shortcut_modification));

        event_rules.emplace_back(
            std::make_tuple("Hijack Execution Flow: Path Interception by Search Order Hijacking", "Persistence", "T1574.008", "https://attack.mitre.org/techniques/T1574/008/", "Windows", SeverityLevel::High, true, search_order_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Server Software Component: Web Shell", "Persistence", "T1505.003", "https://attack.mitre.org/techniques/T1505/003/", "Windows", SeverityLevel::High, true, server_software_component_web_shell));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Component Object Model Hijacking", "Persistence", "T1546.015", "https://attack.mitre.org/techniques/T1546/015/", "Windows", SeverityLevel::High, true, component_object_model_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Change Default File Association", "Persistence", "T1546.001", "https://attack.mitre.org/techniques/T1546/001/", "Windows", SeverityLevel::High, true, change_default_file_association));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Initialization Scripts: Logon Script (Windows)", "Persistence", "T1037.001", "https://attack.mitre.org/techniques/T1037/001", "Windows", SeverityLevel::High, true, win_logon_script));

        event_rules.emplace_back(
            std::make_tuple("Event Triggered Execution: Screensaver", "Persistence", "T1546.002", "https://attack.mitre.org/techniques/T1546/002/", "Windows", SeverityLevel::High, true, event_triggered_exevution_screensaver));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence", "T1547.001", "https://attack.mitre.org/techniques/T1547/001/", "Windows", SeverityLevel::High, true, registry_run_keys_persistence_via_recycle_bin));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Security Support Provider", "Persistence", "T1547.005", "https://attack.mitre.org/techniques/T1547/005/", "Windows", SeverityLevel::High, true, security_support_provider_ssp));

        event_rules.emplace_back(
            std::make_tuple("Abuse Elevation Control Mechanism: Bypass User Account Control", "Persistence", "T1548.002", "https://attack.mitre.org/techniques/T1548/002/", "Windows", SeverityLevel::High, true, bypass_uac_sdclt_delegate_execute));

        event_rules.emplace_back(
            std::make_tuple("Abuse Elevation Control Mechanism: Bypass User Account Control", "Persistence", "T1548.002", "https://attack.mitre.org/techniques/T1548/002/", "Windows", SeverityLevel::High, true, bypass_uac_eventviewer));

        event_rules.emplace_back(
            std::make_tuple("Abuse Elevation Control Mechanism: Bypass User Account Control", "Persistence", "T1548.002", "https://attack.mitre.org/techniques/T1548/002/", "Windows", SeverityLevel::High, true, bypass_uac_disable_reg));

        event_rules.emplace_back(
            std::make_tuple("Office Application Startup", "Persistence", "T1137", "https://attack.mitre.org/techniques/T1137", "Windows", SeverityLevel::High, true, office_applicatoin_startup));

        event_rules.emplace_back(
            std::make_tuple("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence", "T1547.001", "https://attack.mitre.org/techniques/T1547/001/", "Windows", SeverityLevel::High, true, boot_logon_autostart_execution_run_runonce));
        event_rules.emplace_back(
            std::make_tuple("Supply Chain Compromise", "Initial Access", "T1195", "https://attack.mitre.org/techniques/T1195", "Windows", SeverityLevel::High, true, scheduled_task));

        event_rules.emplace_back(
            std::make_tuple("Hardware Additions", "Initial Access", "T1200", "https://attack.mitre.org/techniques/T1200", "Windows", SeverityLevel::Low, true, win_hardware_additions));

        event_rules.emplace_back(
            std::make_tuple("Phishing: Spearphishing Attachment", "Initial Access", "T1566.001", "https://attack.mitre.org/techniques/T1566/001", "Windows", SeverityLevel::High, true, spearphishing_attack));

        event_rules.emplace_back(
            std::make_tuple("External Remote Service", "Initial Access", "T1133", "https://attack.mitre.org/techniques/T1113", "Windows", SeverityLevel::High, true, external_remote_services));

        event_rules.emplace_back(
            std::make_tuple("Automated Exfiltration", "Exfiltration", "T1020", "https://attack.mitre.org/techniques/T1020", "Windows", SeverityLevel::High, true, automated_exfiltration));

        event_rules.emplace_back(
            std::make_tuple("Exfiltration Over Alternative Protocol - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltration", "T1048.002", "https://attack.mitre.org/techniques/T1048/002", "Windows", SeverityLevel::High, true, exfiltration_over_encrypted_protocol));

        event_rules.emplace_back(
            std::make_tuple("Abuse Nslookup with DNS Records", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::Medium, true, abuse_nslookup));

        event_rules.emplace_back(
            std::make_tuple("Delete Volume Shadow Copies Via WMI With PowerShell", "Execution", "T1490", "https://attack.mitre.org/techniques/T1490/", "Windows", SeverityLevel::High, true, delete_volume_shadow_copies_via_WMI_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Downgrade Attack", "Defence Evasion", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, powerShell_downgrade_attack));

        event_rules.emplace_back(
            std::make_tuple("Netcat The Powershell Version", "Command_and_control", "T1095", "https://attack.mitre.org/techniques/T1095", "Windows", SeverityLevel::Medium, true, netcat_the_powershell_version));

        event_rules.emplace_back(
            std::make_tuple("Remote PowerShell Session (PS Classic)", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::High, true, remote_powershell_session));

        event_rules.emplace_back(
            std::make_tuple("Use Get-NetTCPConnection", "Discovery", "T1049", "https://attack.mitre.org/techniques/T1049/", "Windows", SeverityLevel::Low, true, use_get_net_tcp_connection));

        event_rules.emplace_back(
            std::make_tuple("Tamper Windows Defender - PSClassic", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, tamper_windows_defender));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Non PowerShell WSMAN COM Provider", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T059/001", "Windows", SeverityLevel::Medium, true, suspicious_non_powerShell_WSMAN_COM_provider));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Get Local Groups Information", "Discovery", "T1069.001", "https://attack.mitre.org/techniques/T1069/001/", "Windows", SeverityLevel::Low, true, suspicious_get_local_groups_information));

        event_rules.emplace_back(
            std::make_tuple("Access to Browser Login Data", "Credential_access", "T1555.003", "https://attack.mitre.org/techniques/T1555/003/", "Windows", SeverityLevel::Medium, true, access_to_browser_login_data));

        event_rules.emplace_back(
            std::make_tuple("AMSI Bypass Pattern Assembly GetType", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001/", "Windows", SeverityLevel::High, true, AMSI_bypass_pattern_assembly_getType));

        event_rules.emplace_back(
            std::make_tuple("Powershell Install a DLL in System Directory", "Credential_access", "T1556.002", "https://attack.mitre.org/techniques/T1556/002/", "Windows", SeverityLevel::Medium, true, powershell_install_a_DLL_in_system_directory));

        event_rules.emplace_back(
            std::make_tuple("Registry-Free Process Scope COR_PROFILER", "Persistence", "T1136.001", "https://attack.mitre.org/techniques/T1136/001/", "Windows", SeverityLevel::Medium, true, registry_free_process_scope_COR_PROFILER));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Create Local User", "Execution", "T1574.012", "https://attack.mitre.org/techniques/T1574/012/", "Windows", SeverityLevel::Medium, true, powershell_create_local_user));

        event_rules.emplace_back(
            std::make_tuple("Create Volume Shadow Copy with Powershell", "Credential_access", "T1003.003", "https://attack.mitre.org/techniques/T1003/003/", "Windows", SeverityLevel::High, true, create_volume_shadow_copy_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("Powershell Detect Virtualization Environment", "Defence Evasion", "T1497.001", "https://attack.mitre.org/techniques/T1497/001/", "Windows", SeverityLevel::Medium, true, powershell_detect_virtualization_environment));

        event_rules.emplace_back(
            std::make_tuple("DirectorySearcher Powershell Exploitation", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018/", "Windows", SeverityLevel::Medium, true, directorySearcher_powershell_exploitation));

        event_rules.emplace_back(
            std::make_tuple("Disable-WindowsOptionalFeature Command PowerShell", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001/", "Windows", SeverityLevel::High, true, disable_WindowsOptionalFeature_command_powershell));

        event_rules.emplace_back(
            std::make_tuple("Dump Credentials from Windows Credential Manager With PowerShell", "Credential_access", "T1555", "https://attack.mitre.org/techniques/T1555/", "Windows", SeverityLevel::Medium, true, dump_credentials_from_windows_credential_manager_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("Enable Windows Remote Management", "Lateral_movement", "T1021.006", "https://attack.mitre.org/techniques/T1021/006/", "Windows", SeverityLevel::Medium, true, enable_windows_remote_management));

        event_rules.emplace_back(
            std::make_tuple("Certificate Exported Via PowerShell", "Credential_access", "T1552.004", "https://attack.mitre.org/techniques/T1552/004/", "Windows", SeverityLevel::Medium, true, certificate_exported_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("Service Registry Permissions Weakness Check", "Persistence", "T1574.011", "https://attack.mitre.org/techniques/T1574/011/", "Windows", SeverityLevel::Medium, true, service_registry_permissions_weakness_check));

        event_rules.emplace_back(
            std::make_tuple("Active Directory Computers Enumeration with Get-AdComputer", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018/", "Windows", SeverityLevel::Low, true, active_directory_computers_enumeration_with_get_AdComputer));

        event_rules.emplace_back(
            std::make_tuple("Active Directory Computers Enumeration with Get-AdGroup", "Discovery", "T1069.002", "https://attack.mitre.org/techniques/T1069/002/", "Windows", SeverityLevel::Low, true, active_directory_computers_enumeration_with_get_AdGroup));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Get-ADReplAccount", "Credential_access", "T1003.006", "https://attack.mitre.org/techniques/T1003/006/", "Windows", SeverityLevel::Medium, true, suspicious_get_ADReplAccount));

        event_rules.emplace_back(
            std::make_tuple("PowerShell ICMP Exfiltration", "Exfiltration", "T1048.003", "https://attack.mitre.org/techniques/T1048/003/", "Windows", SeverityLevel::Medium, true, powershell_ICMP_exfiltration));

        event_rules.emplace_back(
            std::make_tuple("Execute Invoke-command on Remote Host", "Lateral_movement", "T1021.006", "https://attack.mitre.org/techniques/T1021/006/", "Windows", SeverityLevel::Medium, true, execute_invoke_command_on_remote_host));

        event_rules.emplace_back(
            std::make_tuple("Powershell DNSExfiltration", "Exfiltration", "T1048", "https://attack.mitre.org/techniques/T1048/", "Windows", SeverityLevel::High, true, powershell_DNSExfiltration));

        event_rules.emplace_back(
            std::make_tuple("Powershell Keylogging", "Collection", "T1056.001", "https://attack.mitre.org/techniques/T1056/001/", "Windows", SeverityLevel::Medium, true, powershell_keylogging));

        // Rule triggering, review later
        //  event_rules.emplace_back(
        //      std::make_tuple("Powershell LocalAccount Manipulation", "Persistence", "T1098", "https://attack.mitre.org/techniques/T1098/", "Windows", SeverityLevel::Medium, true, powershell_localAccount_manipulation));

        event_rules.emplace_back(
            std::make_tuple("Powershell MsXml COM Object", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::Medium, true, powershell_MsXml_COM_object));

        event_rules.emplace_back(
            std::make_tuple("NTFS Alternate Data Stream", "Defence Evasion", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::High, true, NTFS_alternate_data_stream));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Remote Session Creation", "execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::Medium, true, powershell_remote_session_creation));

        event_rules.emplace_back(
            std::make_tuple("Use Remove-Item to Delete File", "execution", "T1070.004", "https://attack.mitre.org/techniques/T1070/004/", "Windows", SeverityLevel::Low, true, use_remove_item_to_delete_file));

        event_rules.emplace_back(
            std::make_tuple("Request A Single Ticket via PowerShell", "Credential_access", "T1558.003", "https://attack.mitre.org/techniques/T1558/003/", "Windows", SeverityLevel::High, true, request_a_single_ticket_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Invoke-Item From Mount-DiskImage", "Defence Evasion", "T1553.005", "https://attack.mitre.org/techniques/T1553/005/", "Windows", SeverityLevel::High, true, suspicious_invoke_item_from_mount_diskImage));

        event_rules.emplace_back(
            std::make_tuple("Security Software Discovery by Powershell", "Discovery", "T1518.001", "https://attack.mitre.org/techniques/T1518/001/", "Windows", SeverityLevel::Low, true, security_software_discovery_by_powershell));

        event_rules.emplace_back(
            std::make_tuple("Powershell Exfiltration Over SMTP", "Exfiltration", "T1048.003", "https://attack.mitre.org/techniques/T1048/003/", "Windows", SeverityLevel::Medium, true, powershell_exfiltration_over_SMTP));

        event_rules.emplace_back(
            std::make_tuple("Detected Windows Software Discovery", "Discovery", "T1518", "https://attack.mitre.org/techniques/T1518/", "Windows", SeverityLevel::Medium, true, windows_software_discovery_powershell));

        event_rules.emplace_back(
            std::make_tuple("Powershell Store File In Alternate Data Stream", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004/", "Windows", SeverityLevel::Medium, true, powershell_store_file_in_alternate_data_stream));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Obfuscation Using Character Join", "Defence Evasion", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::Medium, true, potential_powershell_obfuscation_using_character_join));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Eventlog Clear", "Defence Evasion", "T1070.001", "https://attack.mitre.org/techniques/T1070/001/", "Windows", SeverityLevel::Medium, true, suspicious_eventlog_clear));

        event_rules.emplace_back(
            std::make_tuple("Powershell Execute Batch Script", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003/", "Windows", SeverityLevel::Medium, true, powershell_execute_batch_script));

        event_rules.emplace_back(
            std::make_tuple("Password Policy Discovery With Get-AdDefaultDomainPasswordPolicy", "Discovery", "T1201", "https://attack.mitre.org/techniques/T1201/", "Windows", SeverityLevel::Low, true, password_policy_discovery_with_Get_AdDefaultDomainPasswordPolicy));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Get Current User", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033/", "Windows", SeverityLevel::Low, true, suspicious_powershell_get_current_user));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Process Discovery With Get-Process", "Discovery", "T1057", "https://attack.mitre.org/techniques/T1057/", "Windows", SeverityLevel::Low, true, suspicious_process_discovery_with_get_process));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Get-Process LSASS in ScriptBlock", "Credential_access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::High, true, powershell_get_process_LSASS_in_scriptblock));

        event_rules.emplace_back(
            std::make_tuple("Suspicious GetTypeFromCLSID ShellExecute", "Persistence", "T1546.015", "https://attack.mitre.org/techniques/T1546/015/", "Windows", SeverityLevel::Medium, true, suspicious_GetTypeFromCLSID_shellexecute));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Hyper-V Cmdlets", "Defence Evasion", "T1564.006", "https://attack.mitre.org/techniques/T1564/006/", "Windows", SeverityLevel::Medium, true, suspicious_hyper_v_cmdlets));

        event_rules.emplace_back(
            std::make_tuple("Change User Agents with WebRequest", "Command_and_control", "T1071.001", "https://attack.mitre.org/techniques/T1071/001/", "Windows", SeverityLevel::Medium, true, change_user_agents_with_webRequest));

        event_rules.emplace_back(
            std::make_tuple("Suspicious IO.FileStream", "Defence Evasion", "T1070.003", "https://attack.mitre.org/techniques/T1070/003/", "Windows", SeverityLevel::Medium, true, suspicious_io_fileStream));

        event_rules.emplace_back(
            std::make_tuple("Powershell Local Email Collection", "Collection", "T1114.001", "https://attack.mitre.org/techniques/T1114/001/", "Windows", SeverityLevel::Medium, true, powershell_local_email_collection));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Deleted Mounted Share", "Defence Evasion", "T1070.005", "https://attack.mitre.org/techniques/T1070/005/", "Windows", SeverityLevel::Medium, true, powershell_deleted_mounted_share));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Connection to Remote Account", "Credential_access", "T1110.001", "https://attack.mitre.org/techniques/T1110/001/", "Windows", SeverityLevel::Low, true, suspicious_connection_to_remote_account));

        event_rules.emplace_back(
            std::make_tuple("Suspicious New-PSDrive to Admin Share", "Lateral_movement", "T1021.002", "https://attack.mitre.org/techniques/T1021/002/", "Windows", SeverityLevel::Medium, true, suspicious_new_PSDrive_to_admin_share));

        event_rules.emplace_back(
            std::make_tuple("Recon Information for Export with PowerShell", "Collection", "T1119", "https://attack.mitre.org/techniques/T1119/", "Windows", SeverityLevel::Medium, true, recon_information_for_export_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("Remove Account From Domain Admin Group", "Impact", "T1531", "https://attack.mitre.org/techniques/T1531/", "Windows", SeverityLevel::Medium, true, remove_account_from_domain_admin_group));
        //
        event_rules.emplace_back(
            std::make_tuple("Suspicious SSL Connection", "Command_and_control", "T1573", "https://attack.mitre.org/techniques/T1573/", "Windows", SeverityLevel::Low, true, suspicious_SSL_connection));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Unblock-File", "Defence Evasion", "T1553.005", "https://attack.mitre.org/techniques/T1553/005/", "Windows", SeverityLevel::Medium, true, suspicious_unblock_file));

        event_rules.emplace_back(
            std::make_tuple("Replace Desktop Wallpaper by Powershell", "Impact", "T1491.001", "https://attack.mitre.org/techniques/T1491/001/", "Windows", SeverityLevel::Low, true, replace_desktop_wallpaper_by_powershell));

        event_rules.emplace_back(
            std::make_tuple("Powershell Suspicious Win32_PnPEntity", "Discovery", "T1120", "https://attack.mitre.org/techniques/T1120/", "Windows", SeverityLevel::Low, true, powershell_suspicious_win32_PnPEntity));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell WindowStyle Option", "Defence Evasion", "T1564.003", "https://attack.mitre.org/techniques/T1564/003/", "Windows", SeverityLevel::Medium, true, suspicious_powershell_windowStyle_option));

        // event_rules.emplace_back(
        //     std::make_tuple("Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001/","Windows", SeverityLevel::High, true, tamper_windows_defender_remove_MpPreference_ScriptBlockLogging));
        //
        event_rules.emplace_back(
            std::make_tuple("Tamper Windows Defender - ScriptBlockLogging", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001/", "Windows", SeverityLevel::High, true, tamper_windows_defender_ScriptBlockLogging));

        event_rules.emplace_back(
            std::make_tuple("Powershell Timestomp", "Defence Evasion", "T1070.006", "https://attack.mitre.org/techniques/T1070/006/", "Windows", SeverityLevel::Medium, true, powershell_timestomp));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Via PowerShell User Profile Using Add-Content", "Persistence", "T1546.013", "https://attack.mitre.org/techniques/T1546/013/", "Windows", SeverityLevel::Medium, true, potential_persistence_via_powershell_user_profile_using_add_content));

        event_rules.emplace_back(
            std::make_tuple("PowerShell WMI Win32_Product Install MSI", "Defence Evasion", "T1218.007", "https://attack.mitre.org/techniques/T1218/007/", "Windows", SeverityLevel::Medium, true, powershell_WMI_Win32_product_install_MSI));

        event_rules.emplace_back(
            std::make_tuple("Windows Firewall Profile Disabled", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004/", "Windows", SeverityLevel::Medium, true, windows_firewall_profile_disabled));

        // event_rules.emplace_back(
        //     std::make_tuple("Winlogon Helper DLL", "Persistence", "T1547.004", "https://attack.mitre.org/techniques/T1547/004/", SeverityLevel::Medium, true, winlogon_helper_DLL));

        event_rules.emplace_back(
            std::make_tuple("Powershell WMI Persistence", "Privilege_escalation", "T1546.003", "https://attack.mitre.org/techniques/T1546/003/", "Windows", SeverityLevel::Medium, true, powershell_WMI_persistence));

        event_rules.emplace_back(
            std::make_tuple("Powershell XML Execute Command", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001/", "Windows", SeverityLevel::Medium, true, powershell_XML_execute_command));
        // Checkpoint
        event_rules.emplace_back(
            std::make_tuple("Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration", "T1567.002", "https://attack.mitre.org/techniques/T1567/002/", "Windows", SeverityLevel::High, true, exfiltration_over_web_service));

        event_rules.emplace_back(
            std::make_tuple("Regsvr32 Network Activity - DNS", "Defense_evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010/", "Windows", SeverityLevel::High, true, regsvr32_network_activity_dns));

        event_rules.emplace_back(
            std::make_tuple("Suspicious TeamViewer Domain Access", "Command_and_control", "T1219", "https://attack.mitre.org/techniques/T1219/", "Windows", SeverityLevel::Medium, true, suspicious_teamViewer_domain_access));

        event_rules.emplace_back(
            std::make_tuple("DNS Query Tor Onion Address - Sysmon", "Command_and_control", "T1090.003", "https://attack.mitre.org/techniques/T1090/003/", "Windows", SeverityLevel::High, true, dns_query_tor_onion_address_sysmon));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Scripts Run by Services", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002/", "Windows", SeverityLevel::High, true, powershell_scripts_run_by_services));

        event_rules.emplace_back(
            std::make_tuple("CMSTP Execution Process Access", "defense_evasion", "T1218.003", "https://attack.mitre.org/techniques/T1218/003/", "Windows", SeverityLevel::High, true, cmstp_execution_process_access));

        event_rules.emplace_back(
            std::make_tuple("Credential Dumping by LaZagne", "Credential_access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::High, true, credential_dumping_by_laZagne));

        event_rules.emplace_back(
            std::make_tuple("Lsass Memory Dump via Comsvcs DLL", "Credential_access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::High, true, lsass_memory_dump_via_comsvcs_dll));

        event_rules.emplace_back(
            std::make_tuple("Malware Shellcode in Verclsid Target Process", "Defense_evasion", "T1055", "https://attack.mitre.org/techniques/T1055/", "Windows", SeverityLevel::High, true, malware_shellcode_in_verclsid_target_process));

        // event_rules.emplace_back(
        //     std::make_tuple("Credential Dumping by Pypykatz", "Credential_access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows" , SeverityLevel::High, true, credential_dumping_by_pypykatz));

        event_rules.emplace_back(
            std::make_tuple("Potential Shellcode Injection", "Defense_evasion", "T1055", "https://attack.mitre.org/techniques/T1055/", "Windows", SeverityLevel::High, true, potential_shellcode_injection));

        // event_rules.emplace_back(
        //     std::make_tuple("Alternate PowerShell Hosts", "Execution", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::Medium, true, alternate_powershell_hosts));

        // event_rules.emplace_back(
        //     std::make_tuple("PowerShell Called from an Executable Version Mismatch", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows" , SeverityLevel::Low, true, powershell_called_from_an_executable_version_mismatch));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Download", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, suspicious_powershell_download));

        event_rules.emplace_back(
            std::make_tuple("Suspicious XOR Encoded PowerShell Command Line - PowerShell", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, suspicious_XOR_encoded_powershell_command_line_powershell));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Decompress Commands", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Windows", SeverityLevel::Low, true, powershell_decompress_commands));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Get-ADDBAccount Usage", "Credential access", "T1003.003", "https://attack.mitre.org/techniques/T1003/003", "Windows", SeverityLevel::High, true, suspicious_get_ADDBAccount_usage));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Get Clipboard", "Collection", "T1115", "https://attack.mitre.org/techniques/T1115", "Windows", SeverityLevel::Medium, true, powershell_get_clipboard));

        event_rules.emplace_back(
            std::make_tuple("Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, invoke_obfuscation_RUNDLL_LAUNCHER_powershell_module));

        event_rules.emplace_back(
            std::make_tuple("Invoke-Obfuscation Via Use MSHTA - PowerShell Module", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_via_use_mshta_powershell_module));

        event_rules.emplace_back(
            std::make_tuple("Remote PowerShell Session (PS Module)", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, remote_powershell_session_ps_module));

        event_rules.emplace_back(
            std::make_tuple("Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, potential_RemoteFXvGPUDisablement_abuse_powershell_module));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Computer Machine Password by PowerShell", "Initial Access", "T1078", "https://attack.mitre.org/techniques/T1078", "Windows", SeverityLevel::Medium, true, suspicious_computer_machine_password_by_powershell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Get Information for SMB Share - PowerShell Module", "Discovery", "T1069.001", "https://attack.mitre.org/techniques/T1069/001", "Windows", SeverityLevel::Low, true, suspicious_get_information_for_SMB_share_powershell_module));

        event_rules.emplace_back(
            std::make_tuple("SyncAppvPublishingServer Bypass Powershell Restriction - PS Module", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, SyncAppvPublishingServer_bypass_powershell_restriction_PS_module));

        event_rules.emplace_back(
            std::make_tuple("Powershell Add Name Resolution Policy Table Rule", "Impact", "T1565", "https://attack.mitre.org/techniques/T1565", "Windows", SeverityLevel::High, true, powershell_add_name_resolution_policy_table_rule));

        event_rules.emplace_back(
            std::make_tuple("PowerShell ADRecon Execution", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, powershell_ADRecon_execution));

        event_rules.emplace_back(
            std::make_tuple("Get-ADUser Enumeration Using UserAccountControl Flags", "Discovery", "T1069.002", "https://attack.mitre.org/techniques/T1069/002", "Windows", SeverityLevel::Medium, true, get_ADUser_enumeration_using_UserAccountControl_flags));
        // New
        event_rules.emplace_back(
            std::make_tuple("Clearing Windows Console History", "Defence Evasion", "T1070.003", "https://attack.mitre.org/techniques/T1070/003", "Windows", SeverityLevel::High, true, clearing_windows_console_history));

        event_rules.emplace_back(
            std::make_tuple("Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::Medium, true, computer_discovery_and_export_via_get_ADComputer_cmdlet_powershell));

        event_rules.emplace_back(
            std::make_tuple("Manipulation of User Computer or Group Security Principals Across AD", "Persistence", "T1136.002", "https://attack.mitre.org/techniques/T1136/002", "Windows", SeverityLevel::Medium, true, manipulation_of_user_computer_or_group_security_principals_across_AD));

        event_rules.emplace_back(
            std::make_tuple("Disable Powershell Command History", "Defence Evasion", "T1070.003", "https://attack.mitre.org/techniques/T1070/003", "Windows", SeverityLevel::High, true, disable_powershell_command_history));

        event_rules.emplace_back(
            std::make_tuple("Dnscat Execution", "Command and Control", "T1071.004", "https://attack.mitre.org/techniques/T1071/004", "Windows", SeverityLevel::High, true, dnscat_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential In-Memory Execution Using Reflection.Assembly", "Defence Evasion", "T1620", "https://attack.mitre.org/techniques/T1620", "Windows", SeverityLevel::Medium, true, potential_in_memory_execution_using_reflection_assembly));

        event_rules.emplace_back(
            std::make_tuple("Powershell Execute COM Object", "Privilege Escalation", "T1546.015", "https://attack.mitre.org/techniques/T1546/015", "Windows", SeverityLevel::Medium, true, powershell_execute_COM_object));

        event_rules.emplace_back(
            std::make_tuple("Enumerate Credentials from Windows Credential Manager With PowerShell", "Credential access", "T1555", "https://attack.mitre.org/techniques/T1555", "Windows", SeverityLevel::Medium, true, enumerate_credentials_from_windows_credential_manager_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious FromBase64String Usage On Gzip Archive - Ps Script", "Command and Control", "T1132.001", "https://attack.mitre.org/techniques/T1132/001", "Windows", SeverityLevel::Medium, true, suspicious_fromBase64String_usage_on_gzip_archive_ps_script));

        // 21Sept23
        event_rules.emplace_back(
            std::make_tuple("Live Memory Dump Using Powershell", "Credential access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, live_memory_dump_using_powershell));

        event_rules.emplace_back(
            std::make_tuple("Code Executed Via Office Add-in XLL File", "Persistance", "T1137.006", "https://attack.mitre.org/techniques/T1137/006", "Windows", SeverityLevel::High, true, code_executed_via_office_add_in_XLL_file));

        event_rules.emplace_back(
            std::make_tuple("Potential Invoke-Mimikatz PowerShell Script", "Credential access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, potential_invoke_mimikatz_powershell_script));

        event_rules.emplace_back(
            std::make_tuple("PSAsyncShell - Asynchronous TCP Reverse Shell", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, PSAsyncShell_synchronous_TCP_reverse_shell));

        event_rules.emplace_back(
            std::make_tuple("Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, potential_RemoteFXvGPUDisablement_EXE_abuse));

        event_rules.emplace_back(
            std::make_tuple("Powershell Sensitive File Discovery", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083", "Windows", SeverityLevel::Medium, true, powershell_sensitive_file_discovery));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Script Change Permission Via Set-Acl - PsScript", "Defence Evasion", "T1222", "https://attack.mitre.org/techniques/T1222", "Windows", SeverityLevel::Low, true, powershell_script_change_permission_via_set_acl_PsScript));

        event_rules.emplace_back(
            std::make_tuple("Malicious ShellIntel PowerShell Commandlets", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, malicious_shellIntel_powershell_commandlet));

        event_rules.emplace_back(
            std::make_tuple("AD Groups Or Users Enumeration Using PowerShell - ScriptBlock", "Discovery", "T1069.001", "https://attack.mitre.org/techniques/T1069/001", "Windows", SeverityLevel::Low, true, ad_groups_or_users_enumeration_using_powershell_scriptblock));

        event_rules.emplace_back(
            std::make_tuple("Powershell Directory Enumeration", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083", "Windows", SeverityLevel::Medium, true, powershell_directory_enumeration));

        event_rules.emplace_back(
            std::make_tuple("Extracting Information with PowerShell", "Credential access", "T1552.001", "https://attack.mitre.org/techniques/T1552/001", "Windows", SeverityLevel::Medium, true, extracting_information_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("Troubleshooting Pack Cmdlet Execution", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, troubleshooting_pack_cmdlet_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious TCP Tunnel Via PowerShell Script", "Command and Control", "T1090", "https://attack.mitre.org/techniques/T1090", "Windows", SeverityLevel::Medium, true, suspicious_TCP_tunnel_via_powershell_script));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Start-Process PassThru", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::Medium, true, suspicious_start_process_passthru));

        event_rules.emplace_back(
            std::make_tuple("Suspicious X509Enrollment - Ps Script", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004", "Windows", SeverityLevel::Medium, true, suspicious_X509Enrollment_ps_script));

        event_rules.emplace_back(
            std::make_tuple("Network Connection Initiated By AddinUtil.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, network_connection_initiated_by_AddinUtil_EXE));

        event_rules.emplace_back(
            std::make_tuple("Dfsvc.EXE Network Connection To Uncommon Ports", "Execution", "T1203", "https://attack.mitre.org/techniques/T1203", "Windows", SeverityLevel::Medium, true, Dfsvc_EXE_network_connection_to_uncommon_ports));

        event_rules.emplace_back(
            std::make_tuple("Equation Editor Network Connection", "Execution", "T1203", "https://attack.mitre.org/techniques/T1203", "Windows", SeverityLevel::High, true, equation_editor_network_connection));

        event_rules.emplace_back(
            std::make_tuple("HH.EXE Network Connections", "Defence Evasion", "T1218.001", "https://attack.mitre.org/techniques/T1218/001", "Windows", SeverityLevel::Medium, true, HH_EXE_network_connections));

        event_rules.emplace_back(
            std::make_tuple("Download a File with IMEWDBLD.exe", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, download_a_file_with_IMEWDBLD_exe));

        event_rules.emplace_back(
            std::make_tuple("Communication To Mega.nz", "Exfiltration", "T1567.001", "https://attack.mitre.org/techniques/T1567/001", "Windows", SeverityLevel::High, true, communication_to_mega_nz));

        event_rules.emplace_back(
            std::make_tuple("Communication To Ngrok.Io", "Exfiltration", "T1567.001", "https://attack.mitre.org/techniques/T1567/001", "Windows", SeverityLevel::High, true, communication_to_ngrok_io));

        // event_rules.emplace_back(
        //     std::make_tuple("Wuauclt Network Connection", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, wuauclt_network_connection));

        // event_rules.emplace_back(
        //     std::make_tuple("Load Arbitrary DLL via Wuauclt", "defense Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, load_arbitrary_DLL_via_wuauclt));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Add User to Remote Desktop Users Group", "Persistance", "T1133", "https://attack.mitre.org/techniques/T1133", "Windows", SeverityLevel::High, true, suspicious_add_user_to_remote_desktop_users_group));

        event_rules.emplace_back(
            std::make_tuple("Execute From Alternate Data Streams", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564.004", "Windows", SeverityLevel::High, true, execute_from_alternate_data_streams));

        event_rules.emplace_back(
            std::make_tuple("Arbitrary Shell Command Execution Via Settingcontent-Ms", "Execution", "T1204", "https://attack.mitre.org/techniques/T1204", "Windows", SeverityLevel::Medium, true, arbitrary_shell_command_execution_via_settingcontent_Ms));

        event_rules.emplace_back(
            std::make_tuple("Phishing Pattern ISO in Archive", "Initial Access", "T1566", "https://attack.mitre.org/techniques/T1566", "Windows", SeverityLevel::High, true, phishing_pattern_ISO_in_archive));

        event_rules.emplace_back(
            std::make_tuple("Automated Collection Command Prompt", "Collection", "T1119", "https://attack.mitre.org/techniques/T1119", "Windows", SeverityLevel::Medium, true, automated_collection_command_prompt));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Child Process Created as System", "Privilege Escalation", "T1134.002", "https://attack.mitre.org/techniques/T1134/002", "Windows", SeverityLevel::High, true, suspicious_child_process_created_as_system));

        event_rules.emplace_back(
            std::make_tuple("Potential Commandline Obfuscation Using Escape Characters", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Windows", SeverityLevel::Medium, true, potential_commandline_obfuscation_using_escape_characters));

        // Chirag Kathoye Rules
        event_rules.emplace_back(
            std::make_tuple("HackTool - Impacket Tools Execution", "Execution", "T1557.001", "https://attack.mitre.org/techniques/T1557/001/", "Windows", SeverityLevel::High, true, hacktool_impact_tools_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Impersonate Execution", "Privilege Escalation", "T1134.001", "https://attack.mitre.org/techniques/T1134/001/", "Windows", SeverityLevel::Medium, true, hacktool_impersonate_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Inveigh Execution", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::Critical, true, hacktool_inveigh_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation CLIP+ Launcher", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_clip_plus_launcher));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation Obfuscated IEX Invocation", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_obfuscated_iex_invocation));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation STDIN+ Launcher", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_stdin_launcher));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation VAR+ Launcher", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_var_plus_launcher));

        event_rules.emplace_back(
            std::make_tuple("Invoke-Obfuscation COMPRESS OBFUSCATION", "defense evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_compress_obfuscation));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation Via Stdin", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_via_stdin));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation Via Use Clip", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_via_use_clip));

        event_rules.emplace_back(
            std::make_tuple("Invoke-Obfuscation Via Use MSHTA", "defense evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_via_use_mshta));

        // event_rules.emplace_back(
        //     std::make_tuple("Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, invoke_obfuscation_var_plus_plus_obfuscation));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Jlaive In-Memory Assembly Execution", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003/", "Windows", SeverityLevel::Medium, true, hacktool_jlaive_inmemory_assembly_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Koadic Execution", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003/", "Windows", SeverityLevel::High, true, hacktool_koadic_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - KrbRelay Execution", "Credential Access", "T1558.003", "https://attack.mitre.org/techniques/T1558/003/", "Windows", SeverityLevel::High, true, hacktool_krbrelay_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - KrbRelayUp Execution", "Credential Access", "T1558.003", "https://attack.mitre.org/techniques/T1558/003/", "Windows", SeverityLevel::High, true, hacktool_krbrelayup_execution));

        // attack id not found
        event_rules.emplace_back(
            std::make_tuple("HackTool - LocalPotato Execution", "Defence Evasion", "T1558.003", "https://infosecwriteups.com/localpotato-tryhackme-writeup-walkthrough-by-md-amiruddin-a2d93747d5ad", "Windows", SeverityLevel::High, true, hacktool_localpotato_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Meterpreter/CobaltStrike Activity", "Priviledge Escalation", "T1134.001", "https://attack.mitre.org/techniques/T1134/001/", "Windows", SeverityLevel::High, true, potential_meterpreter_cobaltstrikeactivity));

        // event_rules.emplace_back(
        //     std::make_tuple("HackTool - Mimikatz Execution", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::High, true, hacktool_mimikatz_execution));

        // This rule doesn't have proper detection
        event_rules.emplace_back(
            std::make_tuple("HackTool - PCHunter Execution", "Execution", "T1082", "https://attack.mitre.org/techniques/T1082", "Windows", SeverityLevel::High, true, hacktool_pchunter_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Default PowerSploit/Empire Scheduled Task Creation", "Execution", "S0111", "https://attack.mitre.org/techniques/S0111", "Windows", SeverityLevel::High, true, hacktool_default_powersploit_or_empire_scheduled_task_creation));

        // cmdline output not present
        event_rules.emplace_back(
            std::make_tuple("HackTool - PowerTool Execution", "defense Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562.001", "Windows", SeverityLevel::High, true, hacktool_powertool_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - PurpleSharp Execution", "Resource Development", "T1587", "https://attack.mitre.org/techniques/T1587", "Windows", SeverityLevel::Critical, true, hacktool_purplesharp_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Pypykatz Credentials Dumping Activity", "Credential Access", "T1003.002", "https://attack.mitre.org/techniques/T1003/002", "Windows", SeverityLevel::High, true, hacktool_pypykatz_credential_dumping_activity));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Quarks PwDump Execution", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, hacktool_quarks_pwdump_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - RedMimicry Winnti Playbook Execution", "Execution", "T1106", "https://attack.mitre.org/techniques/T1106", "Windows", SeverityLevel::High, true, hacktool_redmimicry_winnti_playbook_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential SMB Relay Attack Tool Execution", "Execution", "T1557.001", "https://attack.mitre.org/techniques/T1557/001/", "Windows", SeverityLevel::Critical, true, potential_smb_relay_attack_tool_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Rubeus Execution", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::Critical, true, hacktool_rubeus_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - PPID Spoofing SelectMyParent Tool Execution", "Defence Evasion", "T1134.004", "https://attack.mitre.org/techniques/T1134/004/", "Windows", SeverityLevel::High, true, hacktool_ppid_spoofing_selectmyparent_tool_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("HackTool - SharpChisel Execution", "Command And Control", "T1090.001", "https://attack.mitre.org/techniques/T1090.001/", "Windows", SeverityLevel::High, true, hacktool_sharpchisel_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SharpImpersonation Execution", "Priviledge Escalation", "T1134.001", "https://attack.mitre.org/techniques/T1134/001/", "Windows", SeverityLevel::High, true, hacktool_sharpimpersonation_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SharpLDAPmonitor Execution", "Discovery", "No ID", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, hacktool_sharpldapmonitor_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SharPersist Execution", "Persistence", "T1053", "https://attack.mitre.org/techniques/T1053", "Windows", SeverityLevel::High, true, hacktool_sharpersist_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("HackTool - SharpEvtMute Execution", "Defence Evasion", "T1562.002", "https://attack.mitre.org/techniques/T1562/002/", "Windows", SeverityLevel::High, true, hacktool_sharpevtmute_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SharpLdapWhoami Execution", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::High, true, hacktool_sharpldapwhoami_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("HackTool - SharpUp PrivEsc Tool Execution", "Privilege Escalation", "T1615", "https://attack.mitre.org/techniques/T1615", "Windows", SeverityLevel::Critical, true, hacktool_sharpup_privesc_tool_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SharpView Execution", "Discovery", "T1049", "https://attack.mitre.org/techniques/T1049", "Windows", SeverityLevel::High, true, hacktool_sharpview_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SILENTTRINITY Stager Execution", "Command and Control", "T1071", "https://attack.mitre.org/techniques/T1071", "Windows", SeverityLevel::High, true, hacktool_silenttrinity_stager_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Sliver C2 Implant Activity Pattern", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Critical, true, hacktool_silverc2_implant_activity_pattern));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Windows Credential Editor (WCE) Execution", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001/", "Windows", SeverityLevel::Critical, true, hacktool_windows_credential_editor_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("HackTool - winPEAS Execution", "Privilege Escalation", "T1082", "https://attack.mitre.org/techniques/T1082", "Windows", SeverityLevel::High, true, hacktool_winpeas_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Wmiexec Default Powershell Command", "Defence Evasion", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, hacktool_wmiexec_default_powershell_command));

        event_rules.emplace_back(
            std::make_tuple("HackTool - XORDump Execution", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, hacktool_xordump_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious ZipExec Execution", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_zipexec_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Homoglyph Attack Using Lookalike Characters", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, potential_homoglyph_attack_using_lookalike_characters));

        event_rules.emplace_back(
            std::make_tuple("Fake Instance Of Hxtsr.exe", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, fake_instance_of_hxtsr));

        event_rules.emplace_back(
            std::make_tuple("Use Icacls to Hide File to Everyone", "Defence Evasion", "T1564.001", "https://attack.mitre.org/techniques/T1564/001", "Windows", SeverityLevel::Medium, true, use_icacls_to_hide_file_to_everyone));

        event_rules.emplace_back(
            std::make_tuple("Disable Windows IIS HTTP Logging", "Defence Evasion", "T1562.002", "https://attack.mitre.org/techniques/T1562/002", "Windows", SeverityLevel::High, true, disable_windows_iis_http_logging));

        event_rules.emplace_back(
            std::make_tuple("Microsoft IIS Service Account Password Dumped", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, microsoft_iis_service_account_password_dumped));

        event_rules.emplace_back(
            std::make_tuple("IIS Native-Code Module Command Line Installation", "Persistence", "T1505.003", "https://attack.mitre.org/techniques/T1505/003", "Windows", SeverityLevel::Medium, true, iis_native_code_module_commandline_installation));

        event_rules.emplace_back(
            std::make_tuple("Suspicious IIS URL GlobalRules Rewrite Via AppCmd", "Defence Evasion", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, suspicious_iis_url_globalrules_rewrite_via_appcmd));

        event_rules.emplace_back(
            std::make_tuple("Microsoft IIS Connection Strings Decryption", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, microsoft_iis_connection_strings_decryption));

        event_rules.emplace_back(
            std::make_tuple("Suspicious IIS Module Registration", "Persistence", "T1505.004", "https://attack.mitre.org/techniques/T1505/004", "Windows", SeverityLevel::High, true, suspicious_iis_module_registration));

        // event_rules.emplace_back(
        //     std::make_tuple("ImagingDevices Unusual Parent/Child Processes", "Defence Evasion", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, imagingdevices_unusual_parentchild_processes));

        event_rules.emplace_back(
            std::make_tuple("InfDefaultInstall.exe .inf Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, infdefaultinstallexe_inf_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Execution of InstallUtil Without Log", "Defence Evasion", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, suspicious_execution_of_installutil_without_log));

        // event_rules.emplace_back(
        // std::make_tuple("Suspicious Shells Spawn by Java Utility Keytool", "Initial Access", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, suspicious_shells_spawn_by_java_utility_keytool));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Child Process Of Manage Engine ServiceDesk", "Command and Control", "T1102", "https://attack.mitre.org/techniques/T1102", "Windows", SeverityLevel::High, true, suspicious_child_process_of_manage_engine_servicedesk));

        // event_rules.emplace_back(
        //     std::make_tuple("Java Running with Remote Debugging", "Execution", "T1203", "https://attack.mitre.org/techniques/T1203", "Windows", SeverityLevel::Medium, true, java_running_with_remote_debugging));

        event_rules.emplace_back(
            std::make_tuple("Shells Spawned by Java", "Initial Access", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, shells_spawned_by_java));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Shells Spawned by Java", "Initial Access", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, suspicious_shells_spawned_by_java));

        event_rules.emplace_back(
            std::make_tuple("Suspicious SysAidServer Child", "Lateral Movement", "T1210", "https://attack.mitre.org/techniques/T1210", "Windows", SeverityLevel::Medium, true, suspicious_sysaidserver_child));

        event_rules.emplace_back(
            std::make_tuple("Windows Kernel Debugger Execution", "Defence Evasion", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, windows_kernel_debugger_execution));

        event_rules.emplace_back(
            std::make_tuple("Computer Password Change Via Ksetup.EXE", "Execution", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, computer_password_change_via_ksetupexe));

        event_rules.emplace_back(
            std::make_tuple("Logged-On User Password Change Via Ksetup.EXE", "Execution", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, loggedon_user_password_change_via_ksetupexe));

        // event_rules.emplace_back(
        //     std::make_tuple("Active Directory Structure Export Via Ldifde.EXE", "Exfilteration", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, active_directory_structure_export_via_ldifdeexe));

        event_rules.emplace_back(
            std::make_tuple("Import LDAP Data Interchange Format File Via Ldifde.EXE", "Command and Control", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, import_ldap_data_interchange_format_file_via_ldifdeexe));

        event_rules.emplace_back(
            std::make_tuple("", "Execution", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::Medium, true, rebuilt_performance_counter_values_via_lodctrexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Windows Trace ETW Session Tamper Via Logman.EXE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, suspicious_windows_trace_etw_session_tamper_via_logmanexe));

        event_rules.emplace_back(
            std::make_tuple("Using AppVLP To Circumvent ASR File Path Rule", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, using_appvlp_to_circumvent_asr_file_path_rule));

        // event_rules.emplace_back(
        //     std::make_tuple("WinDbg/CDB LOLBIN Usage", "Execution", "T1106", "https://attack.mitre.org/techniques/T1106", "Windows", SeverityLevel::Medium, true, windbg_cdb_lolbin_usage));

        event_rules.emplace_back(
            std::make_tuple("Custom Class Execution via Xwizard", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, custom_class_execution_via_xwizard));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Cmdl32 Execution", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_cmdl32_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious ConfigSecurityPolicy Execution", "Exfiltration", "T1567", "https://attack.mitre.org/techniques/T1567", "Windows", SeverityLevel::Medium, true, suspicious_configsecuritypolicy_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious CustomShellHost Execution", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, suspicious_customshellhost_execution));

        event_rules.emplace_back(
            std::make_tuple("LOLBAS Data Exfiltration by DataSvcUtil.exe", "Exfiltration", "T1567", "https://attack.mitre.org/techniques/T1567", "Windows", SeverityLevel::Medium, true, lolbas_data_exfiltration_by_datasvcutilexe));

        event_rules.emplace_back(
            std::make_tuple("ZOHO Dctask64 Process Injection", "Defence Evasion", "T1055.001", "https://attack.mitre.org/techniques/T1055/001", "Windows", SeverityLevel::High, true, zoho_dctask64_process_injection));

        event_rules.emplace_back(
            std::make_tuple("Lolbin Defaultpack.exe Use As Proxy", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, lolbin_defaultpackexe_use_as_proxy));

        event_rules.emplace_back(
            std::make_tuple("DeviceCredentialDeployment Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, devicecredentialdeployment_execution));

        event_rules.emplace_back(
            std::make_tuple("Devtoolslauncher.exe Executes Specified Binary", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, devtoollauncherexe_executes_specified_binary));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Diantz Alternate Data Stream Execution", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004", "Windows", SeverityLevel::Medium, true, suspicious_diantz_alternate_data_stream_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Diantz Download and Compress Into a CAB File", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, suspicious_diantz_download_and_compress_into_a_cab_file));

        event_rules.emplace_back(
            std::make_tuple("Xwizard DLL Sideloading", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574/002", "Windows", SeverityLevel::High, true, xwizard_dll_sideloading));

        event_rules.emplace_back(
            std::make_tuple("Application Whitelisting Bypass via Dnx.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, application_whitelisting_bypass_via_dnxexe));

        event_rules.emplace_back(
            std::make_tuple("Process Memory Dump Via Dotnet-Dump", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, process_memory_dump_via_dotnet_dump));

        event_rules.emplace_back(
            std::make_tuple("Dotnet.exe Exec Dll and Execute Unsigned Code LOLBIN", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, dotnetexe_exec_dll_and_execute_unsigned_code_lolbin));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Dump64.exe Execution", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, suspicious_dump64_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Extexport Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_extexport_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Extrac32 Alternate Data Stream Execution", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004", "Windows", SeverityLevel::Medium, true, suspicious_extrac32_alternate_data_stream_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Extrac32 Execution", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, suspicious_extrac32_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Abusing Findstr for Defence Evasion", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, abusing_findstr_for_defense_evasion));

        event_rules.emplace_back(
            std::make_tuple("Use of Forfiles For Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, use_of_forfiles_for_execution));

        event_rules.emplace_back(
            std::make_tuple("Format.com FileSystem LOLBIN", "Defence Evasion", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, formatcom_filesystem_lolbin));

        event_rules.emplace_back(
            std::make_tuple("Use of FSharp Interpreters", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, use_of_fsharp_interpreters));

        // event_rules.emplace_back(
        //     std::make_tuple("LOLBIN Execution Of The FTP.EXE Binary", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, lolbin_execution_of_the_ftpexe));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Reconnaissance Activity Via GatherNetworkInfo.VBS", "Discovery", "T1615", "https://attack.mitre.org/techniques/T1615", "Windows", SeverityLevel::Medium, true, potential_reconnaissance_activity_via_gathernetworkinfovbs));

        // event_rules.emplace_back(
        //     std::make_tuple("Gpscript Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, gpscript_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Ie4uinit Lolbin Use From Invalid Path", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, ie4uinit_lolbin_use_from_invalid_path));

        // event_rules.emplace_back(
        //     std::make_tuple("Abusing IEExec To Download Payloads", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, abusing_ieexec_to_download_payload));

        event_rules.emplace_back(
            std::make_tuple("Ilasm Lolbin Use Compile C-Sharp", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, ilasm_lolbin_use_compile_c_sharp));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Execution of InstallUtil To Download", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_execution_of_installutil_to_download));

        // event_rules.emplace_back(
        //     std::make_tuple("JSC Convert Javascript To Executable", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, jsc_convert_javascript_to_executable));

        event_rules.emplace_back(
            std::make_tuple("Kavremover Dropped Binary LOLBIN Usage", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::High, true, kavremover_dropped_binary_lolbin_usage));

        event_rules.emplace_back(
            std::make_tuple("Launch-VsDevShell.PS1 Proxy Execution", "Defence Evasion", "T1216.001", "https://attack.mitre.org/techniques/T1216/001", "Windows", SeverityLevel::High, true, launch_vsdevshellps1_proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Manage-bde.wsf Abuse To Proxy Execution", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::High, true, potential_manage_bdewsf_abuse_to_proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("Mavinject Inject DLL Into Running Process", "Defence Evasion", "T1055.001", "https://attack.mitre.org/techniques/T1055/001", "Windows", SeverityLevel::High, true, mavinject_inject_dll_into_running_process));

        // event_rules.emplace_back(
        //     std::make_tuple("MpiExec Lolbin", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, mpiexec_lolbin));

        event_rules.emplace_back(
            std::make_tuple("Execute Files with Msdeploy.exe", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, execute_files_with_msdeployexe));

        // event_rules.emplace_back(
        //     std::make_tuple("Execute MSDT Via Answer File", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, execute_msdt_via_answer_file));

        // event_rules.emplace_back(
        //     std::make_tuple("Download Arbitrary Files Via MSOHTMED.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, downlaod_arbitrary_files_via_msohtmedexe));

        // event_rules.emplace_back(
        //     std::make_tuple("Arbitrary File Download Via MSPUB.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, abitrary_file_download_viamspuexe));

        event_rules.emplace_back(
            std::make_tuple("Use of OpenConsole", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, use_of_openconsole));

        // event_rules.emplace_back(
        //     std::make_tuple("OpenWith.exe Executes Specified Binary", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, openwitexe_executes_specified_binary));

        // event_rules.emplace_back(
        //     std::make_tuple("Use of Pcalua For Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, use_of_pcalua_for_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Execute Pcwrun.EXE To Leverage Follina", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, execute_pcwrunexe_to_leverage_follina));

        event_rules.emplace_back(
            std::make_tuple("Indirect Command Execution By Program Compatibility Wizard", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Low, true, indirect_command_execution_by_program_compatibility_wizard));

        event_rules.emplace_back(
            std::make_tuple("Code Execution via Pcwutl.dll", "Defence Evasion", "T1218.001", "https://attack.mitre.org/techniques/T1218/001", "Windows", SeverityLevel::Medium, true, code_execution_via_pcwutldll));

        event_rules.emplace_back(
            std::make_tuple("Execute Code with Pester.bat", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, execute_code_with_pesterbat));

        // event_rules.emplace_back(
        //     std::make_tuple("Execute Code with Pester.bat as Parent", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, execute_code_with_pesterbat_as_parent));

        event_rules.emplace_back(
            std::make_tuple("Execute Code with Pester.bat as Parent", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, execute_code_with_pesterbat_as_parent));

        // event_rules.emplace_back(
        //     std::make_tuple("Download Arbitrary Files Via PresentationHost.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, downlaod_arbitrary_files_via_presentationhostexe));

        event_rules.emplace_back(
            std::make_tuple("Application Whitelisting Bypass via PresentationHost.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, application_whitelisting_bypass_via_presentationhostexe));

        event_rules.emplace_back(
            std::make_tuple("PrintBrm ZIP Creation of Extraction", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, printbrm_zip_creation_of_extraction));

        // event_rules.emplace_back(
        //     std::make_tuple("File Download Using ProtocolHandler.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, file_download_using_protocol_handle));

        event_rules.emplace_back(
            std::make_tuple("Pubprn.vbs Proxy Execution", "Defence Evasion", "T1216.001", "https://attack.mitre.org/techniques/T1216/001", "Windows", SeverityLevel::Medium, true, pubprnvbs_proxy_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("DLL Execution via Rasautou.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, dll_execution_via_rasautouexe));

        // event_rules.emplace_back(
        //     std::make_tuple("REGISTER_APP.VBS Proxy Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, registerappvbs_proxy_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Use of Remote.exe", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, use_of_remoteexe));

        // event_rules.emplace_back(
        //     std::make_tuple("Replace.exe Usage", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, replaceexe_usage));

        event_rules.emplace_back(
            std::make_tuple("Lolbin Runexehelper Use As Proxy", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, lolbin_runexehelper_use_as_proxy));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Runscripthelper.exe", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, suspicious_runscripthelperexe));

        event_rules.emplace_back(
            std::make_tuple("Use of Scriptrunner.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, use_of_scriptrunnerexe));

        event_rules.emplace_back(
            std::make_tuple("Using SettingSyncHost.exe as LOLBin", "Execution", "T1574.008", "https://attack.mitre.org/techniques/T1574/008", "Windows", SeverityLevel::High, true, using_settingsynchostexe_as_lolbin));

        // event_rules.emplace_back(
        //     std::make_tuple("Use Of The SFTP.EXE Binary As A LOLBIN", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, use_of_sftpexe_binary_as_lolbin));

        event_rules.emplace_back(
            std::make_tuple("Sideloading Link.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, sideloading_linkexe));

        event_rules.emplace_back(
            std::make_tuple("Use of Squirrel.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, use_of_squirrelexe));

        event_rules.emplace_back(
            std::make_tuple("Lolbin Ssh.exe Use As Proxy", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, lolbin_sshexe_use_as_proxy));

        event_rules.emplace_back(
            std::make_tuple("Lolbin Ssh.exe Use As Proxy", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, lolbin_sshexe_use_as_proxy));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious LOLBIN AccCheckConsole", "Execution", "-", "https://attack.mitre.org/techniques/", "Windows", SeverityLevel::High, true, suspicious_lolbin_acccheckconsole));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Atbroker Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, suspicious_atbroker_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Certreq Command to Download", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, suspicious_certreq_command_to_download));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Driver Install by pnputil.exe", "Persistence", "T1547", "https://attack.mitre.org/techniques/T1547", "Windows", SeverityLevel::Medium, true, suspicious_driver_install_by_pnputilexe));

        // event_rules.emplace_back(
        //     std::make_tuple("Application Whitelisting Bypass via Dxcap.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, application_whitelisting_bypass_via_dxcapexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious GrpConv Execution", "Persistence", "T1547", "https://attack.mitre.org/techniques/T1547", "Windows", SeverityLevel::High, true, suspicious_grpconv_execution));

        // event_rules.emplace_back(
        //     std::make_tuple("Windows Defender Download Activity", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, windows_defender_download_activity));

        event_rules.emplace_back(
            std::make_tuple("Dumping Process via Sqldumper.exe", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::Medium, true, dumping_process_via_sqldumperexe));

        event_rules.emplace_back(
            std::make_tuple("SyncAppvPublishingServer Execute Arbitrary PowerShell Code", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, syncappvpublishingserver_execute_arbitrary_powershell_code));

        event_rules.emplace_back(
            std::make_tuple("SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, syncappvpublishingserver_vbs_execute_arbitrary_powershell_code));

        event_rules.emplace_back(
            std::make_tuple("Potential DLL Injection Or Execution Using Tracker.exe", "Defence Evasion", "T1055.001", "https://attack.mitre.org/techniques/T1055/001", "Windows", SeverityLevel::Medium, true, potential_dll_injection_or_execution_using_trackerexe));

        event_rules.emplace_back(
            std::make_tuple("Use of TTDInject.exe", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, use_of_ttdinjectexe));

        event_rules.emplace_back(
            std::make_tuple("Time Travel Debugging Utility Usage", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, time_travel_debugging_utility_usage));

        event_rules.emplace_back(
            std::make_tuple("Potential Download/Upload Activity Using Type Command", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, potential_upload_download_ctivity_using_type_command));

        event_rules.emplace_back(
            std::make_tuple("Lolbin Unregmp2.exe Use As Proxy", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, lolbin_unregmp2exe_use_as_proxy));

        event_rules.emplace_back(
            std::make_tuple("UtilityFunctions.ps1 Proxy Dll", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, utilityfunctionsps1_proxy_dll));

        event_rules.emplace_back(
            std::make_tuple("Visual Basic Command Line Compiler Usage", "Defence Evasion", "T1027.004", "https://attack.mitre.org/techniques/T1027/004", "Windows", SeverityLevel::High, true, visual_basic_command_line_compiler_usage));

        event_rules.emplace_back(
            std::make_tuple("Use of VisualUiaVerifyNative.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, use_of_visualuiaverifynativeexe));

        event_rules.emplace_back(
            std::make_tuple("Use of VSIISExeLauncher.exe", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, use_of_vsiisexelauncherexe));

        event_rules.emplace_back(
            std::make_tuple("Use of Wfc.exe", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, use_of_wfcexe));

        event_rules.emplace_back(
            std::make_tuple("Wlrmdr Lolbin Use as Launcher", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, wlrmdr_lolbin_use_as_launcher));

        event_rules.emplace_back(
            std::make_tuple("Microsoft Workflow Compiler Execution", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, microsoft_workflow_compiler_execution));

        event_rules.emplace_back(
            std::make_tuple("Proxy Execution via Wuauclt", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, proxy_execution_via_wuauclt));

        event_rules.emplace_back(
            std::make_tuple("Potential Register_App.Vbs LOLScript Abuse", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, potential_register_appvbs_lolscript_abuse));

        event_rules.emplace_back(
            std::make_tuple("Potential Credential Dumping Via LSASS Process Clone", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::Critical, true, potential_credential_dumping_via_lsass_process_clone));

        event_rules.emplace_back(
            std::make_tuple("Sensitive Registry Access via Volume Shadow Copy", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::High, true, sensitivity_registry_access_via_volume_shadow_copy));

        event_rules.emplace_back(
            std::make_tuple("WScript or CScript Dropper", "Execution", "T1059.005", "https://attack.mitre.org/techniques/T1059/005", "Windows", SeverityLevel::High, true, wscript_or_cscript_dropper));

        event_rules.emplace_back(
            std::make_tuple("Potential Mftrace.EXE Abuse", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, potential_mftraceexe_abuse));

        event_rules.emplace_back(
            std::make_tuple("MMC20 Lateral Movement", "Execution", "T1021.003", "https://attack.mitre.org/techniques/T1021/003", "Windows", SeverityLevel::High, true, mmc20_lateral_movement));

        event_rules.emplace_back(
            std::make_tuple("MMC Spawning Windows Shell", "Lateral Movement", "T1021.003", "https://attack.mitre.org/techniques/T1021/003", "Windows", SeverityLevel::High, true, mmc_spawning_windows_shell));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Suspicious Mofcomp Execution", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, potential_suspicious_mofcomp_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Mpclient.DLL Sideloading Via Defender Binaries", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574.002", "Windows", SeverityLevel::High, true, potential_mpclientdll_sideloading_via_defender_binaries));

        // Poras Zode Rules
        event_rules.emplace_back(
            std::make_tuple("Suspicious Child Process Of SQL Server", "Initial Access", "T1505.003", "https://attack.mitre.org/techniques/T1505/003", "Windows", SeverityLevel::High, true, suspicious_child_process_of_sql_server));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Child Process Of Veeam Database", "Initial Access", "T1505", "https://attack.mitre.org/techniques/T1505", "Windows", SeverityLevel::Critical, true, suspicious_child_process_of_veeam_database));

        event_rules.emplace_back(
            std::make_tuple("Potential MSTSC Shadowing Activity", "Lateral Movement", "T1563.002", "https://attack.mitre.org/techniques/T1563/002", "Windows", SeverityLevel::High, true, potential_mstsc_shadowing_activity));

        event_rules.emplace_back(
            std::make_tuple("New Remote Desktop Connection Initiated Via Mstsc.EXE", "Lateral Movement", "T1021.001", "https://attack.mitre.org/techniques/T1021/001", "Windows", SeverityLevel::Medium, true, new_remote_desktop_connection_initiated_via_mstsc_exe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Mstsc.EXE Execution With Local RDP File", "Command And Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::High, true, suspicious_mstsc_exe_execution_with_local_rdp_file));

        event_rules.emplace_back(
            std::make_tuple("Mstsc.EXE Execution With Local RDP File", "Command And Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Low, true, mstsc_exe_execution_with_local_rdp_file));

        event_rules.emplace_back(
            std::make_tuple("Mstsc.EXE Execution From Uncommon Parent", "Lateral Movement", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::High, true, mstsc_exe_execution_from_uncommon_parent));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Manipulation Of Default Accounts Via Net.EXE", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::High, true, suspicious_manipulation_of_default_accounts_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Group And Account Reconnaissance Activity Using Net.EXE", "Discovery", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Windows", SeverityLevel::Medium, true, suspicious_group_and_account_reconnaissance_activity_using_net_exe));

        event_rules.emplace_back(
            std::make_tuple("System Network Connections Discovery Via Net.EXE", "Discovery", "T1049", "https://attack.mitre.org/techniques/T1049", "Windows", SeverityLevel::Low, true, system_network_connections_discovery_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Share And Session Enumeration Using Net.EXE", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018", "Windows", SeverityLevel::Low, true, share_and_session_enumeration_using_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Unmount Share Via Net.EXE", "Defence Evasion", "T1070.005", "https://attack.mitre.org/techniques/T1070/005", "Windows", SeverityLevel::Low, true, unmount_share_via_net_exe));

        // event_rules.emplace_back(
        //     std::make_tuple("Start Windows Service Via Net.EXE", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002", "Windows", SeverityLevel::Low, true, start_windows_service_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Wsudo Suspicious Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, wsudo_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("Adidnsdump Execution", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018", "Windows", SeverityLevel::Low, true, adidnsdump_execution));

        event_rules.emplace_back(
            std::make_tuple("Python Inline Command Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, python_inline_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Python Spawning Pretty TTY", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, python_spawn_pretty_tty));

        event_rules.emplace_back(
            std::make_tuple("Query Usage To Exfil Data", "Execution", "T1041", "https://attack.mitre.org/techniques/T1041", "Windows", SeverityLevel::Medium, true, query_usage_to_exfil_data));

        event_rules.emplace_back(
            std::make_tuple("Files Added To An Archive Using Rar.EXE", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Low, true, files_added_to_archive_using_rar));

        event_rules.emplace_back(
            std::make_tuple("Rar Usage with Password and Compression Level", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::High, true, rar_usage_with_password_and_compression_level));

        event_rules.emplace_back(
            std::make_tuple("Suspicious RASdial Activity", "Defence Evasion", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, suspicious_rasdial_activity));

        event_rules.emplace_back(
            std::make_tuple("Process Memory Dump via RdrLeakDiag.EXE", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, process_memory_dump_via_rdrleakdiag));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Attempt Via Run Keys Using Reg.EXE", "Persistence", "T1547.001", "https://attack.mitre.org/techniques/T1547/001", "Windows", SeverityLevel::Medium, true, persistence_attempt_via_runkeys));

        event_rules.emplace_back(
            std::make_tuple("Potential Browser Data Stealing", "Credential Access", "T1555.003", "https://attack.mitre.org/techniques/T1555/003", "Windows", SeverityLevel::Medium, true, potential_browser_data_stealing));

        event_rules.emplace_back(
            std::make_tuple("Copy from Admin Share", "Collection", "T1039", "https://attack.mitre.org/techniques/T1039", "Windows", SeverityLevel::High, true, copy_from_admin_share));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Crypto Mining Activity", "Impact", "T1496", "https://attack.mitre.org/techniques/T1496", "Windows", SeverityLevel::High, true, potential_crypto_mining_activity));

        event_rules.emplace_back(
            std::make_tuple("Potential Crypto Monero Mining", "Impact", "T1496", "https://attack.mitre.org/techniques/T1496", "Windows", SeverityLevel::High, true, potential_crypto_monero_mining));

        event_rules.emplace_back(
            std::make_tuple("Potential Data Exfiltration Activity Via CommandLine Tools", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, potential_data_exfiltration_activity_via_commandLine_tools));

        event_rules.emplace_back(
            std::make_tuple("Raccine Uninstall", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, raccine_uninstall));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Double Extension File Execution", "Initial Access", "T1566.001", "https://attack.mitre.org/techniques/T1566/001", "Windows", SeverityLevel::Critical, true, suspicious_double_extension_file_execution));

        event_rules.emplace_back(
            std::make_tuple("DumpStack.log Defender Evasion", "Defence Evasion", "T1060", "https://attack.mitre.org/techniques/T1060", "Windows", SeverityLevel::Critical, true, dumpStack_log_defender_evasion));

        event_rules.emplace_back(
            std::make_tuple("Stop Windows Service Via Net.EXE", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489", "Windows", SeverityLevel::Low, true, stop_windows_service_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Net.exe Execution", "Discovery", "T1007", "https://attack.mitre.org/techniques/T1007", "Windows", SeverityLevel::Low, true, net_exe_execution));

        event_rules.emplace_back(
            std::make_tuple("Windows Admin Share Mount Via Net.EXE", "Lateral Movement", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::Medium, true, windows_admin_share_mount_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Windows Internet Hosted WebDav Share Mount Via Net.EXE", "Lateral Movement", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::High, true, windows_internet_hosted_webdav_share_mount_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Windows Share Mount Via Net.EXE", "Lateral Movement", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::Low, true, windows_share_mount_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("Password Provided In Command Line Of Net.EXE", "Lateral Movement", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::Medium, true, password_provided_in_command_line_of_net_exe));

        event_rules.emplace_back(
            std::make_tuple("New User Created Via Net.EXE With Never Expire Option", "Persistence", "T1136.001", "https://attack.mitre.org/techniques/T1136/001", "Windows", SeverityLevel::High, true, new_user_created_via_net_exe_with_never_expire_option));

        event_rules.emplace_back(
            std::make_tuple("New User Created Via Net.EXE", "Persistence", "T1136.001", "https://attack.mitre.org/techniques/T1136/001", "Windows", SeverityLevel::Medium, true, new_user_created_via_net_exe));

        event_rules.emplace_back(
            std::make_tuple("New Firewall Rule Added Via Netsh.EXE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::Medium, true, new_firewall_rule_added_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("RDP Connection Allowed Via Netsh.EXE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::High, true, rdp_connection_allowed_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Firewall Rule Deleted Via Netsh.EXE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::Medium, true, firewall_rule_deleted_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Always Install Elevated MSI Spawned Cmd And Powershell", "Privilege Escalation", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::Medium, true, always_install_elevated_MSI_spawned_cmd_and_powershell));

        event_rules.emplace_back(
            std::make_tuple("Elevated System Shell Spawned", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, elevated_system_shell_spawned));

        event_rules.emplace_back(
            std::make_tuple("Hidden Powershell in Link File Pattern", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, hidden_powershell_in_link_file_pattern));

        event_rules.emplace_back(
            std::make_tuple("Firewall Disabled via Netsh.EXE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::Medium, true, firewall_disabled_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Netsh Allow Group Policy on Microsoft Defender Firewall", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::Medium, true, netsh_allow_group_policy_on_microsoft_defender_firewall));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Firewall Configuration Discovery Via Netsh.EXE", "Discovery", "T1016", "https://attack.mitre.org/techniques/T1016", "Windows", SeverityLevel::Low, true, suspicious_firewall_configuration_discovery_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Firewall Rule Update Via Netsh.EXE", "Defence Evasion", "T1562.004", "https://attack.mitre.org/techniques/T1562/004", "Windows", SeverityLevel::Medium, true, firewall_rule_update_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Via Netsh Helper DLL", "Privilege Escalation", "T1546.007", "https://attack.mitre.org/techniques/T1546/007", "Windows", SeverityLevel::High, true, potential_persistence_via_netsh_helper_dll));

        event_rules.emplace_back(
            std::make_tuple("ETW Logging Tamper In .NET Processes", "Defence Evasion", "T1562", "https://attack.mitre.org/techniques/T1562", "Windows", SeverityLevel::High, true, ETW_logging_tamper_in_NET_processes));

        event_rules.emplace_back(
            std::make_tuple("Disable of ETW Trace", "Defence Evasion", "T1562.006", "https://attack.mitre.org/techniques/T1562/006", "Windows", SeverityLevel::High, true, disable_of_ETW_trace));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Execution From GUID Like Folder Names", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, suspicious_execution_from_GUID_like_folder_names));

        event_rules.emplace_back(
            std::make_tuple("Parent in Public Folder Suspicious Process", "Defence Evasion", "T1564", "https://attack.mitre.org/techniques/T1564", "Windows", SeverityLevel::High, true, parent_in_public_folder_suspicious_process));

        event_rules.emplace_back(
            std::make_tuple("Suspicious File Characteristics Due to Missing Fields", "Execution", "T1059.006", "https://attack.mitre.org/techniques/T1059/006", "Windows", SeverityLevel::Medium, true, suspicious_file_characteristics_due_to_missing_fields));

        event_rules.emplace_back(
            std::make_tuple("New Network Trace Capture Started Via Netsh.EXE", "Discovery", "T1040", "https://attack.mitre.org/techniques/T1040", "Windows", SeverityLevel::Medium, true, new_network_trace_capture_started_via_netsh_exe));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS", "Discovery", "T1615", "https://attack.mitre.org/techniques/T1615", "Windows", SeverityLevel::High, true, suspicious_reconnaissance_activity_via_GatherNetworkInfo_VBS));

        event_rules.emplace_back(
            std::make_tuple("Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream - CLI", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004", "Windows", SeverityLevel::Medium, true, potential_hidden_directory_creation_via_NTFS_INDEX_ALLOCATION_stream_CLI));

        event_rules.emplace_back(
            std::make_tuple("Writing Of Malicious Files To The Fonts Folder", "Defence Evasion", "T1211", "https://attack.mitre.org/techniques/T1211", "Windows", SeverityLevel::Medium, true, writing_of_malicious_files_to_the_fonts_folder));

        event_rules.emplace_back(
            std::make_tuple("Base64 MZ Header In CommandLine", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, base64_MZ_header_in_CommandLine));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential WinAPI Calls Via CommandLine", "Execution", "T1106", "https://attack.mitre.org/techniques/T1106", "Windows", SeverityLevel::High, true, potential_winAPI_calls_via_commandLine));

        event_rules.emplace_back(
            std::make_tuple("Local Accounts Discovery", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::Low, true, local_accounts_discovery));

        event_rules.emplace_back(
            std::make_tuple("LSASS Dump Keyword In CommandLine", "Credential Access", "T1033.001", "https://attack.mitre.org/techniques/T1033/001", "Windows", SeverityLevel::High, true, lsass_dump_keyword_in_commandLine));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Network Command", "Discovery", "T1016", "https://attack.mitre.org/techniques/T1016", "Windows", SeverityLevel::Low, true, suspicious_network_command));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Scan Loop Network", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018", "Windows", SeverityLevel::Medium, true, suspicious_scan_loop_network));

        event_rules.emplace_back(
            std::make_tuple("Non-privileged Usage of Reg or Powershell", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::High, true, non_privileged_usage_of_reg_or_powershell));

        event_rules.emplace_back(
            std::make_tuple("Add SafeBoot Keys Via Reg Utility", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, add_safeboot_keys_via_reg_utility));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Reg Add BitLocker", "Impact", "T1486", "https://attack.mitre.org/techniques/T1486", "Windows", SeverityLevel::High, true, suspicious_reg_add_bitlocker));

        event_rules.emplace_back(
            std::make_tuple("Dropping Of Password Filter DLL", "Credential Access", "T1556.002", "https://attack.mitre.org/techniques/T1556/002", "Windows", SeverityLevel::Medium, true, dropping_of_password_filter_dll));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, suspicious_windows_defender_folder_exclusion));

        event_rules.emplace_back(
            std::make_tuple("SafeBoot Registry Key Deleted Via Reg.EXE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, safeboot_registry_key_deleted_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Service Registry Key Deleted Via Reg.EXE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, service_registry_key_deleted_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Direct Autorun Keys Modification", "Persistence", "T1547.001", "https://attack.mitre.org/techniques/T1547/001", "Windows", SeverityLevel::Medium, true, direct_autorun_keys_modification));

        event_rules.emplace_back(
            std::make_tuple("Security Service Disabled Via Reg.EXE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, security_service_disabled_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Enumeration for Credentials in Registry", "Credential Access", "T1552.002", "https://attack.mitre.org/techniques/T1552/002", "Windows", SeverityLevel::Medium, true, enumeration_for_insecure_credentials_in_registry));

        event_rules.emplace_back(
            std::make_tuple("Potential Suspicious Registry File Imported Via Reg.EXE", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::Medium, true, suspicious_registry_file_imported_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Disabled RestrictedAdminMode For RDS - ProcCreation", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::High, true, disabled_restrictedadminmode_for_rds));

        event_rules.emplace_back(
            std::make_tuple("LSA PPL Protection Disabled Via Reg.EXE", "Defence Evasion", "T1562.010", "https://attack.mitre.org/techniques/T1562/010", "Windows", SeverityLevel::High, true, lsa_ppl_protection_disabled_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Query of MachineGUID", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Windows", SeverityLevel::Low, true, suspicious_query_of_machineguid));

        event_rules.emplace_back(
            std::make_tuple("Modify Group Policy Settings", "Defence Evasion", "T1484.001", "https://attack.mitre.org/techniques/T1484/001", "Windows", SeverityLevel::Medium, true, modify_group_policy_settings));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Reg Add Open Command", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::Medium, true, suspicious_reg_add_open_command));

        event_rules.emplace_back(
            std::make_tuple("Potential Configuration And Service Reconnaissance Via Reg.EXE", "Discovery", "T1012", "https://attack.mitre.org/techniques/T1012", "Windows", SeverityLevel::Medium, true, configuration_and_service_reconnaissance_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Process Patterns NTDS.DIT Exfil", "Credential Access", "T1003.003", "https://attack.mitre.org/techniques/T1003/003", "Windows", SeverityLevel::High, true, suspicious_process_patterns_NTDS_DIT_exfil));

        event_rules.emplace_back(
            std::make_tuple("Use NTFS Short Name in Command Line", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004", "Windows", SeverityLevel::Medium, true, use_NTFS_short_name_in_command_ine));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Office Token Search Via CLI", "Credential Access", "T1528", "https://attack.mitre.org/techniques/T1528", "Windows", SeverityLevel::Medium, true, suspicious_office_token_search_via_CLI));

        event_rules.emplace_back(
            std::make_tuple("Privilege Escalation via Named Pipe Impersonation", "Lateral Movement", "T1021", "https://attack.mitre.org/techniques/T1021", "Windows", SeverityLevel::High, true, privilege_escalation_via_named_pipe_impersonation));

        event_rules.emplace_back(
            std::make_tuple("Potential Tampering With RDP Related Registry Keys Via Reg.EXE", "Defence Evasion", "T1021.001", "https://attack.mitre.org/techniques/T1021/001", "Windows", SeverityLevel::High, true, tampering_with_rdp_related_registry_keys_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious ScreenSave Change by Reg.exe", "Privilege Escalation", "T1546.002", "https://attack.mitre.org/techniques/T1546/002", "Windows", SeverityLevel::Medium, true, suspicious_screensave_change_by_regexe));

        event_rules.emplace_back(
            std::make_tuple("Changing Existing Service ImagePath Value Via Reg.EXE", "Persistence", "T1574.011", "https://attack.mitre.org/techniques/T1574/011", "Windows", SeverityLevel::Medium, true, changing_existing_service_imagepath_value_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Obfuscated IP Download", "Discovery", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, obfuscated_IP_download));

        event_rules.emplace_back(
            std::make_tuple("Recon Information for Export with Command Prompt", "Collection", "T1119", "https://attack.mitre.org/techniques/T1119", "Windows", SeverityLevel::Medium, true, recon_information_for_export_with_command_prompt));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Process Execution From Fake Recycle.Bin Folder", "persistence", "T1547.001", "https://attack.mitre.org/techniques/T1547/001", "Windows", SeverityLevel::High, true, suspicious_process_execution_from_fake_recycle_bin_folder));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Redirection to Local Admin Share", "Exfiltration", "T1048", "https://attack.mitre.org/techniques/T1048", "Windows", SeverityLevel::High, true, suspicious_redirection_to_local_admin_share));

        event_rules.emplace_back(
            std::make_tuple("Potential Remote Desktop Tunneling", "Lateral Movement", "T1021", "https://attack.mitre.org/techniques/T1021", "Windows", SeverityLevel::Medium, true, potential_remote_desktop_tunneling));

        event_rules.emplace_back(
            std::make_tuple("Potential Defence Evasion Via Right-to-Left Override", "Persistance", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::High, true, potential_defense_evasion_via_right_to_left_override));

        event_rules.emplace_back(
            std::make_tuple("Suspicious New Service Creation", "Defence Evasion", "T1036.002", "https://attack.mitre.org/techniques/T1036/002", "Windows", SeverityLevel::High, true, suspicious_new_service_creation));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Windows Service Tampering", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, suspicious_windows_service_tampering));

        event_rules.emplace_back(
            std::make_tuple("Process Creation Using Sysnative Folder", "Defence Evasion", "T1055", "https://attack.mitre.org/techniques/T1055", "Windows", SeverityLevel::Medium, true, process_creation_using_sysnative_folder));

        event_rules.emplace_back(
            std::make_tuple("Suspicious SYSVOL Domain Group Policy Access", "Credential Access", "T1552.006", "https://attack.mitre.org/techniques/T1552/006", "Windows", SeverityLevel::Medium, true, suspicious_SYSVOL_domain_group_policy_access));

        event_rules.emplace_back(
            std::make_tuple("Tasks Folder Evasion", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574/002", "Windows", SeverityLevel::High, true, tasks_folder_evasion));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Userinit Child Process", "Defence Evasion", "T1055", "https://attack.mitre.org/techniques/T1055", "Windows", SeverityLevel::Medium, true, suspicious_userinit_child_process));

        event_rules.emplace_back(
            std::make_tuple("Usage Of Web Request Commands And Cmdlets", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, usage_of_web_request_commands_and_cmdlets));

        event_rules.emplace_back(
            std::make_tuple("WhoAmI as Parameter", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::High, true, whoami_as_parameter));

        event_rules.emplace_back(
            std::make_tuple("Execution via WorkFolders.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, execution_via_workFolders_exe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Svchost Process", "Defence Evasion", "T1036.005", "https://attack.mitre.org/techniques/T1036/005", "Windows", SeverityLevel::High, true, suspicious_svchost_process));

        event_rules.emplace_back(
            std::make_tuple("Permission Check Via Accesschk.EXE", "Discovery", "T1069.001", "https://attack.mitre.org/techniques/T1069/001", "Windows", SeverityLevel::Medium, true, permission_check_via_accesschk_EXE));

        event_rules.emplace_back(
            std::make_tuple("Active Directory Database Snapshot Via ADExplorer", "Credential Access", "T1552.001", "https://attack.mitre.org/techniques/T1552/001", "Windows", SeverityLevel::Medium, true, active_directory_database_snapshot_via_ADExplorer));

        event_rules.emplace_back(
            std::make_tuple("Potential Execution of Sysinternals Tools", "Resource Development", "T1588.002", "https://attack.mitre.org/techniques/T1588/002", "Windows", SeverityLevel::Low, true, potential_execution_of_sysinternals_tools));

        event_rules.emplace_back(
            std::make_tuple("Kernel Memory Dump Via LiveKD", "Defence Evasion", "TA0005", "https://attack.mitre.org/tactics/TA0005/", "Windows", SeverityLevel::High, true, kernel_memory_dump_via_liveKD)); // Tactic to be converted to subtechnique. REVIEW LATER

        event_rules.emplace_back(
            std::make_tuple("Potential SysInternals ProcDump Evasion", "Defence Evasion", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, potential_sysInternals_procDump_evasion));

        event_rules.emplace_back(
            std::make_tuple("Detected Windows Software Discovery", "Discovery", "T1518", "https://attack.mitre.org/techniques/T1518", "Windows", SeverityLevel::Medium, true, detected_windows_software_discovery));

        event_rules.emplace_back(
            std::make_tuple("Reg Add Suspicious Paths", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::High, true, reg_add_suspicious_paths));

        event_rules.emplace_back(
            std::make_tuple("Disabled Volume Snapshots", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, disabled_volume_snapshots));

        event_rules.emplace_back(
            std::make_tuple("Write Protect For Storage Disabled", "Defence Evasion", "T1562", "https://attack.mitre.org/techniques/T1562", "Windows", SeverityLevel::Medium, true, write_protect_for_storage_disabled));

        event_rules.emplace_back(
            std::make_tuple("Exports Critical Registry Keys To a File", "Exfiltration", "T1012", "https://attack.mitre.org/techniques/T1012", "Windows", SeverityLevel::High, true, exports_critical_registry_keys_to_a_file));

        event_rules.emplace_back(
            std::make_tuple("Exports Registry Key To a File", "Exfiltration", "T1012", "https://attack.mitre.org/techniques/T1012", "Windows", SeverityLevel::Low, true, exports_registry_key_to_a_file));

        event_rules.emplace_back(
            std::make_tuple("Regedit as Trusted Installer", "Privilege Escalation", "T1548", "https://attack.mitre.org/techniques/T1548", "Windows", SeverityLevel::High, true, regedit_as_trusted_installer));

        event_rules.emplace_back(
            std::make_tuple("DLL Execution Via Register-cimprovider.exe", "Defence Evasion", "T1574", "https://attack.mitre.org/techniques/T1574", "Windows", SeverityLevel::Medium, true, dll_execution_via_register_cimprovider));

        event_rules.emplace_back(
            std::make_tuple("Enumeration for 3rd Party Creds From CLI", "Credential Access", "T1552.002", "https://attack.mitre.org/techniques/T1552/002", "Windows", SeverityLevel::Medium, true, enumeration_for_third_party_creds_from_cli));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential LSASS Process Dump Via Procdump", "Defence Evasion", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, potential_LSASS_process_dump_via_procdump));

        event_rules.emplace_back(
            std::make_tuple("PsExec/PAExec Escalation to LOCAL SYSTEM", "Resource Development", "T1587.001", "https://attack.mitre.org/techniques/T1587/001", "Windows", SeverityLevel::High, true, psExec_PAExec_escalation_to_LOCAL_SYSTEM));

        event_rules.emplace_back(
            std::make_tuple("Potential PsExec Remote Execution", "Resource Development", "T1587.001", "https://attack.mitre.org/techniques/T1587/001", "Windows", SeverityLevel::High, true, potential_PsExec_remote_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Use of PsLogList", "Discovery", "T1087", "https://attack.mitre.org/techniques/T1587/001", "Windows", SeverityLevel::Medium, true, suspicious_use_of_PsLogList));

        event_rules.emplace_back(
            std::make_tuple("Sysinternals PsSuspend Suspicious Execution", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, sysinternals_psSuspend_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Debugger Registration Cmdline", "Persistence", "T1546.008", "https://attack.mitre.org/techniques/T1546/008", "Windows", SeverityLevel::High, true, suspicious_debugger_registration_cmdline));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Via Logon Scripts - CommandLine", "Persistence", "T1037.001", "https://attack.mitre.org/techniques/T1037/001", "Windows", SeverityLevel::High, true, potential_persistence_via_logon_scripts_commandline));

        event_rules.emplace_back(
            std::make_tuple("Potential Credential Dumping Attempt Using New NetworkProvider - CLI", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, potential_credential_dumping_attempt_using_new_networkprovider_cli));

        event_rules.emplace_back(
            std::make_tuple("Potential Privilege Escalation via Service Permissions Weakness", "Credential Access", "T1574.011", "https://attack.mitre.org/techniques/T1574/011", "Windows", SeverityLevel::High, true, potential_privilege_escalation_via_service_permissions_weakness));

        event_rules.emplace_back(
            std::make_tuple("Potential File Overwrite Via Sysinternals SDelete", "Impact", "T1485", "https://attack.mitre.org/techniques/T1485", "Windows", SeverityLevel::High, true, potential_file_overwrite_via_sysinternals_sDelete));

        event_rules.emplace_back(
            std::make_tuple("Sysmon Configuration Update", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, sysmon_configuration_update)); // Severity level to be reviewed

        event_rules.emplace_back(
            std::make_tuple("Uninstall Sysinternals Sysmon", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, uninstall_sysinternal_sysmon));

        event_rules.emplace_back(
            std::make_tuple("Sysprep on AppData Folder", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, sysprep_on_appData_folder));

        event_rules.emplace_back(
            std::make_tuple("System Information Discovery", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Windows", SeverityLevel::Low, true, system_information_discovery));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Recursive Takeown", "Defence Evasion", "T1222.001", "https://attack.mitre.org/techniques/T1222/001", "Windows", SeverityLevel::Medium, true, suspicious_recursive_takeown));

        // event_rules.emplace_back(
        //     std::make_tuple("Tap Installer Execution", "Exfiltration", "T1048", "https://attack.mitre.org/techniques/T1048", "Windows", SeverityLevel::Medium, true, tap_installer_execution));

        event_rules.emplace_back(
            std::make_tuple("Taskkill Symantec Endpoint Protection", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, taskkill_symantec_endpoint_protection));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Tasklist Discovery Command", "Discovery", "T1057", "https://attack.mitre.org/techniques/T1057", "Windows", SeverityLevel::Low, true, suspicious_tasklist_discovery_command));

        event_rules.emplace_back(
            std::make_tuple("Taskmgr as LOCAL_SYSTEM", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, taskmgr_LOCAL_SYSTEM));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Command With Teams Objects Paths", "Credential Access", "T1528", "https://attack.mitre.org/techniques/T1528", "Windows", SeverityLevel::High, true, suspicious_command_with_teams_objects_paths));

        event_rules.emplace_back(
            std::make_tuple("New Virtual Smart Card Created Via TpmVscMgr.EXE", "Execution", "TA0002", "https://attack.mitre.org/tactics/TA0002", "Windows", SeverityLevel::Medium, true, new_virtual_smart_card_created_via_TpmVscMgr_EXE));

        event_rules.emplace_back(
            std::make_tuple("Suspicious TSCON Start as SYSTEM", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::High, true, suspicious_TSCON_start_as_SYSTEM));

        event_rules.emplace_back(
            std::make_tuple("Suspicious RDP Redirect Using TSCON", "Lateral Movement", "T1021.001", "https://attack.mitre.org/techniques/T1021/001", "Windows", SeverityLevel::High, true, suspicious_RDP_redirect_using_TSCON));

        event_rules.emplace_back(
            std::make_tuple("Changing RDP Port to Non Standard Port via Powershell", "Lateral Movement", "T1021.001", "https://attack.mitre.org/techniques/T1021/001", "Windows", SeverityLevel::High, true, changing_RDP_port_to_non_standard_port_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using ChangePK and SLUI", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_changePK_and_SLUI));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using Disk Cleanup", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_disk_cleanup));

        event_rules.emplace_back(
            std::make_tuple("Potential Provisioning Registry Key Abuse For Binary Proxy Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, potential_provisioning_registry_key_abuse_for_binary_proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Execution Policy Tampering - ProcCreation", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, potential_powerShell_execution_policy_tampering_proccreation));

        event_rules.emplace_back(
            std::make_tuple("Persistence Via TypedPaths - CommandLine", "Persistence", "T1037.001", "https://attack.mitre.org/techniques/T1037/001", "Windows", SeverityLevel::Medium, true, persistence_via_typedpaths_commandline));

        event_rules.emplace_back(
            std::make_tuple("Potential Regsvr32 Commandline Flag Anomaly", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::Medium, true, potential_regsvr32_commandline_flag_anomaly));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Regsvr32 HTTP IP Pattern", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::High, true, potentially_suspicious_regsvr32_http_ip_pattern));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Regsvr32 HTTP/FTP Pattern", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::Medium, true, potentially_suspicious_regsvr32_http_ftp_pattern));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Regsvr32 Execution From Remote Share", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::High, true, suspicious_regsvr32_execution_from_remote_share));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Child Process Of Regsvr32", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::High, true, potentially_suspicious_child_process_of_regsvr32));

        event_rules.emplace_back(
            std::make_tuple("Regsvr32 Execution From Potential Suspicious Location", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::Medium, true, regsvr32_execution_from_potential_suspicious_location));

        event_rules.emplace_back(
            std::make_tuple("Regsvr32 DLL Execution With Suspicious File Extension", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::High, true, regsvr32_dll_execution_with_suspicious_file_extension));

        event_rules.emplace_back(
            std::make_tuple("Bypass UAC via CMSTP", "Defence Evasion", "T1218.003", "https://attack.mitre.org/techniques/T1218/003", "Windows", SeverityLevel::High, true, bypass_UAC_via_CMSTP));

        event_rules.emplace_back(
            std::make_tuple("CMSTP UAC Bypass via COM Object Access", "Defence Evasion", "T1218.003", "https://attack.mitre.org/techniques/T1218/003", "Windows", SeverityLevel::High, true, cmstp_UAC_bypass_via_COM_object_access));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Tools Using ComputerDefaults", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_tools_using_computerDefaults));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using DismHost", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_dismHost));

        event_rules.emplace_back(
            std::make_tuple("RDP Port Forwarding Rule Added Via Netsh.EXE", "Lateral Movement", "T1090", "https://attack.mitre.org/techniques/T1090", "Windows", SeverityLevel::High, true, rdp_port_forwarding_rule_added_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("New Port Forwarding Rule Added Via Netsh.EXE", "Lateral Movement", "T1090", "https://attack.mitre.org/techniques/T1090", "Windows", SeverityLevel::Medium, true, new_port_forwarding_rule_added_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Harvesting Of Wifi Credentials Via Netsh.EXE", "Discovery", "T1040", "https://attack.mitre.org/techniques/T1040", "Windows", SeverityLevel::Medium, true, harvesting_of_wifi_credentials_via_netsh_exe));

        event_rules.emplace_back(
            std::make_tuple("Potential Network Sniffing Activity Using Network Tools", "Credential Access", "T1040", "https://attack.mitre.org/techniques/T1040", "Windows", SeverityLevel::Medium, true, potential_network_sniffing_activity_using_network_tools));

        event_rules.emplace_back(
            std::make_tuple("Nltest.EXE Execution", "Discovery", "T1016", "https://attack.mitre.org/techniques/T1016", "Windows", SeverityLevel::Low, true, nltest_exe_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Recon Activity Via Nltest.EXE", "Discovery", "T1016", "https://attack.mitre.org/techniques/T1016", "Windows", SeverityLevel::High, true, potential_recon_activity_via_nltest_exe));

        event_rules.emplace_back(
            std::make_tuple("Potential Arbitrary Code Execution Via Node.EXE", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::High, true, potential_arbitrary_code_execution_via_node_exe));

        event_rules.emplace_back(
            std::make_tuple("Node Process Executions", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, node_process_executions));

        event_rules.emplace_back(
            std::make_tuple("Network Reconnaissance Activity", "Discovery", "T1087", "https://attack.mitre.org/techniques/T1087", "Windows", SeverityLevel::High, true, network_reconnaissance_activity));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Usage Of Active Directory Diagnostic Tool", "Credential Access", "T1003.003", "https://attack.mitre.org/techniques/T1003.003", "Windows", SeverityLevel::Medium, true, suspicious_usage_of_active_directory_diagnostic_tool));

        event_rules.emplace_back(
            std::make_tuple("Bypass UAC using Event Viewer (PowerShell)", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, bypass_UAC_using_event_viewer_powerShell));

        event_rules.emplace_back(
            std::make_tuple("Bypass UAC using Event Viewer (cmd)", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, bypass_UAC_using_event_viewer_cmd));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using Event Viewer RecentViews", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_event_viewer_recentViews));

        event_rules.emplace_back(
            std::make_tuple("Bypass UAC via Fodhelper.exe", "Privilege Escalation", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, bypass_UAC_via_fodhelper_exe));

        event_rules.emplace_back(
            std::make_tuple("Bypass UAC via Fodhelper.exe - Powershell", "Privilege Escalation", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, bypass_UAC_via_fodhelper_exe_powershell));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass via Windows Firewall Snap-In Hijack", "Privilege Escalation", "T1548", "https://attack.mitre.org/techniques/T1548", "Windows", SeverityLevel::Medium, true, uac_bypass_via_windows_firewall_snap_in_hijack));

        event_rules.emplace_back(
            std::make_tuple("Scripting/CommandLine Process Spawned Regsvr32", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::Medium, true, scripting_commandline_process_spawned_regsvr32));

        event_rules.emplace_back(
            std::make_tuple("Regsvr32 DLL Execution With Uncommon Extension", "Defence Evasion", "T1574", "https://attack.mitre.org/techniques/T1574", "Windows", SeverityLevel::Medium, true, regsvr32_dll_execution_with_uncommon_extension));

        event_rules.emplace_back(
            std::make_tuple("Use of UltraViewer Remote Access Software", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, use_of_ultraviewer_remote_access_software));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - AnyDesk Piped Password Via CLI", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, remote_access_tool_anydesk_piped_password_via_cli));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - AnyDesk Silent Installation", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::High, true, remote_access_tool_anydesk_silent_installation));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - Anydesk Execution From Suspicious Folder", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::High, true, remote_access_tool_anydesk_execution_from_suspicious_folder));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - GoToAssist Execution", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, remote_access_tool_gotoassist_execution));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - LogMeIn Execution", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, remote_access_tool_logmein_execution));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - NetSupport Execution", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, remote_access_tool_netsupport_execution));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - RURAT Execution From Unusual Location", "Defence Evasion", "T1574", "https://attack.mitre.org/techniques/T1574", "Windows", SeverityLevel::Medium, true, remote_access_tool_rurat_execution_from_unusual_location));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - ScreenConnect Suspicious Execution", "Initial Access", "T1133", "https://attack.mitre.org/techniques/T1133", "Windows", SeverityLevel::High, true, remote_access_tool_screenconnect_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - ScreenConnect Backstage Mode Anomaly", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, remote_access_tool_screenconnect_backstage_mode_anomaly));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - ScreenConnect Remote Command Execution", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003", "Windows", SeverityLevel::Medium, true, remote_access_tool_screenconnect_remote_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - ScreenConnect Execution", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, remote_access_tool_screenconnect_execution));

        event_rules.emplace_back(
            std::make_tuple("Invocation of Active Directory Diagnostic Tool", "Credential Access", "T1003.003", "https://attack.mitre.org/techniques/T1003.003", "Windows", SeverityLevel::Medium, true, invocation_of_active_directory_diagnostic_tool));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Driver/DLL Installation Via Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::High, true, suspicious_driver_ddl_installation_via_odbccnf_exe));

        event_rules.emplace_back(
            std::make_tuple("Driver/DLL Installation Via Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::Medium, true, driver_ddl_installation_via_odbccnf_exe));

        event_rules.emplace_back(
            std::make_tuple("Odbcconf.EXE Suspicious DLL Location", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::High, true, odbcconf_exe_suspicious_dll_location));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious DLL Registered Via Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::High, true, potentially_suspicious_dll_registered_via_odbcconf_exe));

        event_rules.emplace_back(
            std::make_tuple("New DLL Registered Via Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::Medium, true, new_dll_registered_via_odbcconf_exe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Response File Execution Via Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::High, true, suspicious_response_file_execution_via_odbcconf_exe));

        event_rules.emplace_back(
            std::make_tuple("Response File Execution Via Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::Medium, true, response_file_execution_via_odbcconf_exe));

        event_rules.emplace_back(
            std::make_tuple("Uncommon Child Process Spawned By Odbcconf.EXE", "Defence Evasion", "T1218.008", "https://attack.mitre.org/techniques/T1218.008", "Windows", SeverityLevel::Medium, true, uncommon_child_process_spawned_by_odbcconf_exe));

        event_rules.emplace_back(
            std::make_tuple("Potential Arbitrary File Download Using Office Application", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::High, true, potential_arbitrary_file_download_using_office_application));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Office Document Executed From Trusted Location", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::High, true, potentially_suspicious_office_document_executed_from_trusted_location));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Microsoft OneNote Child Process", "Initial Access", "T1566.001", "https://attack.mitre.org/techniques/T1566.001", "Windows", SeverityLevel::High, true, suspicious_microsoft_onenote_clid_process));

        event_rules.emplace_back(
            std::make_tuple("Outlook EnableUnsafeClientMailRules Setting Enabled", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, outlook_enableunsafeclientmailrules_setting_enabled));

        event_rules.emplace_back(
            std::make_tuple("Execution in Outlook Temp Folder", "Initial Access", "T1566.001", "https://attack.mitre.org/techniques/T1566.001", "Windows", SeverityLevel::High, true, execution_in_outlook_temp_folder));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Remote Child Process From Outlook", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, suspicious_remote_child_process_from_outlook));

        event_rules.emplace_back(
            std::make_tuple("Discovery of a System Time", "Discovery", "T1124", "https://attack.mitre.org/techniques/T1124", "Windows", SeverityLevel::Low, true, discovery_of_a_system_time));

        event_rules.emplace_back(
            std::make_tuple("Renamed AdFind Execution", "Discovery", "T1018", "https://attack.mitre.org/techniques/T1018", "Windows", SeverityLevel::High, true, renamed_adfind_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed AutoHotkey.EXE Execution", "Defence Evasion", "T1574", "https://attack.mitre.org/techniques/T1574", "Windows", SeverityLevel::Medium, true, renamed_autohotkeyexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed AutoIt Execution", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, renamed_autoit_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Defence Evasion Via Rename Of Highly Relevant Binaries", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, potential_defense_evasion_via_rename_of_highly_relevant_binaries));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Defence Evasion Via Binary Rename", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, potential_defense_evasion_via_binary_rename));

        event_rules.emplace_back(
            std::make_tuple("Renamed BrowserCore.EXE Execution", "Defence Evasion", "T1528", "https://attack.mitre.org/techniques/T1528", "Windows", SeverityLevel::High, true, renamed_browsercoreexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed CreateDump Utility Execution", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, renamed_createdump_utility_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed CURL.EXE Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, renamed_curlexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed ZOHO Dctask64 Execution", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, renamed_zoho_dctask64_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed FTP.EXE Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, renamed_ftpexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Gpg.EXE Execution", "Impact", "T1486", "https://attack.mitre.org/techniques/T1486", "Windows", SeverityLevel::High, true, renamed_gpgexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Jusched.EXE Execution", "Execution", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, renamed_juschedexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Mavinject.EXE Execution", "Defence Evasion", "T1055.001", "https://attack.mitre.org/techniques/T1055/001", "Windows", SeverityLevel::High, true, renamed_mavinjectexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed MegaSync Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, renamed_megasync_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Msdt.EXE Execution", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, renamed_msdtexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed NetSupport RAT Execution", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, renamed_netsupport_rat_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Office Binary Execution", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, renamed_office_binary_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed PAExec Execution", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::High, true, renamed_paexec_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Plink Execution", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, renamed_plink_execution));

        event_rules.emplace_back(
            std::make_tuple("Visual Studio NodejsTools PressAnyKey Renamed Execution", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, visual_studio_nodejstools_pressanykey_renamed_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Renamed Rundll32 Execution", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, potential_renamed_rundll32_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Remote Utilities RAT (RURAT) Execution", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, renamed_remote_utilities_rat_rurat_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed SysInternals DebugView Execution", "Resource Development", "T1588.002", "https://attack.mitre.org/techniques/T1588/002", "Windows", SeverityLevel::High, true, renamed_sysinternals_debugview_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed ProcDump Execution", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::High, true, renamed_procdump_execution));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using IEInstal - Process", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_IEInstal_process));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using MSConfig Token Modification - Process", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_MSConfig_token_modification_process));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Using PkgMgr and DISM", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_using_PkgMgr_and_DISM));

        event_rules.emplace_back(
            std::make_tuple("UAC Bypass Abusing Winsat Path Parsing - Process", "Defence Evasion", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_abusing_winsat_path_parsing_process));

        event_rules.emplace_back(
            std::make_tuple("Use of UltraVNC Remote Access Software", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, use_of_ultraVNC_remote_access_software));

        event_rules.emplace_back(
            std::make_tuple("Suspicious UltraVNC Execution", "Lateral Movement", "T1021.005", "https://attack.mitre.org/techniques/T1021/005", "Windows", SeverityLevel::High, true, suspicious_ultraVNC_execution));

        event_rules.emplace_back(
            std::make_tuple("Uninstall Crowdstrike Falcon Sensor", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, uninstall_crowdstrike_falcon_sensor));

        // event_rules.emplace_back(
        //     std::make_tuple("Uncommon Userinit Child Process", "Persistance", "T1037.001", "https://attack.mitre.org/techniques/T1037/001", "Windows", SeverityLevel::High, true, uncommon_userinit_child_process));

        event_rules.emplace_back(
            std::make_tuple("Windows Credential Manager Access via VaultCmd", "Credential Access", "T1555.004", "https://attack.mitre.org/techniques/T1555/004", "Windows", SeverityLevel::Medium, true, windows_credential_manager_access_via_vaultCmd));

        event_rules.emplace_back(
            std::make_tuple("Verclsid.exe Runs COM Object", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, verclsid_exe_runs_COM_object));

        event_rules.emplace_back(
            std::make_tuple("Detect Virtualbox Driver Installation OR Starting Of VMs", "Defence Evasion", "T1564.006", "https://attack.mitre.org/techniques/T1564/006", "Windows", SeverityLevel::Low, true, detect_virtualbox_driver_installation_OR_starting_of_VMs));

        event_rules.emplace_back(
            std::make_tuple("Suspicious VBoxDrvInst.exe Parameters", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::Medium, true, suspicious_VBoxDrvInst_exe_parameters));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, potential_persistence_via_VMwareToolBoxCmd_EXE_VM_state_change_script));

        event_rules.emplace_back(
            std::make_tuple("VMToolsd Suspicious Child Process", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, vmtoolsd_suspicious_child_process));

        event_rules.emplace_back(
            std::make_tuple("VsCode Child Process Anomaly", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, vsCode_child_process_anomaly));

        event_rules.emplace_back(
            std::make_tuple("Potential Binary Proxy Execution Via VSDiagnostics.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, potential_binary_proxy_execution_via_VSDiagnostics_EXE));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Vsls-Agent Command With AgentExtensionPath Load", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_vsls_agent_command_with_agentExtensionPath_load));

        // event_rules.emplace_back(
        //     std::make_tuple("Use of W32tm as Timer", "Discovery", "T1124", "https://attack.mitre.org/techniques/T1124", "Windows", SeverityLevel::High, true, use_of_W32tm_as_timer));

        event_rules.emplace_back(
            std::make_tuple("Wab Execution From Non Default Location", "Execution", "TA0002", "https://attack.mitre.org/tactics/TA0002", "Windows", SeverityLevel::High, true, wab_execution_from_non_default_location)); // ID was not given in SigmaHQ Rule

        event_rules.emplace_back(
            std::make_tuple("SystemStateBackup Deleted Using Wbadmin.EXE", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490   ", "Windows", SeverityLevel::High, true, systemStateBackup_deleted_using_wbadmin_EXE));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious WebDAV LNK Execution", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, potentially_suspicious_webDAV_LNK_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Arbitrary DLL Load Using Winword", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, potential_arbitrary_dll_load_using_winword));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspicious Execution Of PDQDeployRunner", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, suspicious_execution_of_pdqdeployrunner));

        event_rules.emplace_back(
            std::make_tuple("Perl Inline Command Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, perl_inline_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Php Inline Command Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, php_inline_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Ping Hex IP", "Execution", "T1140", "https://attack.mitre.org/techniques/T1140", "Windows", SeverityLevel::High, true, ping_hex_ip));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Powercfg Execution To Change Lock Screen Timeout", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, suspicious_powercfg_execution_to_change_lock_screen_timeout));

        event_rules.emplace_back(
            std::make_tuple("AADInternals PowerShell Cmdlets Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, aadinternals_powershell_cmdlets_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Active Directory Enumeration Using AD Module", "Discovery", "T1016", "https://attack.mitre.org/techniques/T1016", "Windows", SeverityLevel::Medium, true, potential_active_directory_enumeration_using_ad_module));

        event_rules.emplace_back(
            std::make_tuple("Add Windows Capability Via PowerShell Cmdlet", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, add_windows_capability_via_powershell_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("Potential AMSI Bypass Via .NET Reflection", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, potential_amsi_bypass_via_net_reflection));

        event_rules.emplace_back(
            std::make_tuple("Potential AMSI Bypass Using NULL Bits", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, potential_amsi_bypass_using_null_bits));

        event_rules.emplace_back(
            std::make_tuple("Audio Capture via PowerShell", "Collection", "T1123", "https://attack.mitre.org/techniques/T1123", "Windows", SeverityLevel::Medium, true, audio_capture_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Encoded PowerShell Command Line", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, suspicious_encoded_powershell_command_line));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Base64 Encoded FromBase64String Cmdlet", "Defence Evasion", "T1140", "https://attack.mitre.org/techniques/T1140", "Windows", SeverityLevel::High, true, powershell_base64_encoded_frombase64string_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Base64 Encoded IEX Cmdlet", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, powershell_base64_encoded_iex_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Base64 Encoded Invoke Keyword", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, powershell_base64_encoded_invoke_keyword));

        event_rules.emplace_back(
            std::make_tuple("Powershell Base64 Encoded MpPreference Cmdlet", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, powershell_base64_encoded_mppreference_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("Potential Process Execution Proxy Via CL_Invocation.ps1", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, potential_process_execution_proxy_via_cl_invocation_ps1));

        event_rules.emplace_back(
            std::make_tuple("Assembly Loading Via CL_LoadAssembly.ps1", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, assembly_loading_via_cl_loadassembly_ps1));

        event_rules.emplace_back(
            std::make_tuple("Potential Script Proxy Execution Via CL_Mutexverifiers.ps1", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, potential_script_proxy_execution_via_cl_mutexverifiers_ps1));

        event_rules.emplace_back(
            std::make_tuple("ConvertTo-SecureString Cmdlet Usage Via CommandLine", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, convertto_securestring_cmdlet_usage_via_commandline));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Obfuscation Via Reversed Commands", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, potential_powershell_obfuscation_via_reversed_commands));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Command Line Obfuscation", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, potential_powershell_command_line_obfuscation));

        event_rules.emplace_back(
            std::make_tuple("Computer Discovery And Export Via Get-ADComputer Cmdlet", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::Medium, true, computer_discovery_and_export_via_get_adcomputer_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("New Service Creation Using PowerShell", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::Low, true, new_service_creation_using_powershell));

        event_rules.emplace_back(
            std::make_tuple("Gzip Archive Decode Via PowerShell", "Command and Control", "T1132.001", "https://attack.mitre.org/techniques/T1132/001", "Windows", SeverityLevel::Medium, true, gzip_archive_decode_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Execution With Potential Decryption Capabilities", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, powershell_execution_with_potential_decryption_capabilities));

        event_rules.emplace_back(
            std::make_tuple("Powershell Defender Disable Scan Feature", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, powershell_defender_disable_scan_feature));

        event_rules.emplace_back(
            std::make_tuple("Powershell Defender Exclusion", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, powershell_defender_exclusion));

        event_rules.emplace_back(
            std::make_tuple("Renamed PsExec Service Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, renamed_psexec_service_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Sysinternals Sdelete Execution", "Impact", "T1485", "https://attack.mitre.org/techniques/T1485", "Windows", SeverityLevel::High, true, renamed_sysinternals_sdelete_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Vmnat.exe Execution", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574/002", "Windows", SeverityLevel::High, true, renamed_vmnatexe_execution));

        event_rules.emplace_back(
            std::make_tuple("Renamed Whoami Execution", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::Critical, true, renamed_whoami_execution));
        event_rules.emplace_back(
            std::make_tuple("Capture Credentials with Rpcping.exe", "Credential Access", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::Medium, true, capture_credentials_with_rpcpingexe));

        event_rules.emplace_back(
            std::make_tuple("Ruby Inline Command Execution", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, ruby_inline_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Disable Windows Defender AV Security Monitoring", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, disable_windows_defender_av_security_monitoring));

        event_rules.emplace_back(
            std::make_tuple("Windows Firewall Disabled via PowerShell", "Defence Evasion", "T1562", "https://attack.mitre.org/techniques/T1562", "Windows", SeverityLevel::Medium, true, windows_firewall_disabled_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("Disabled IE Security Features", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, disabled_ie_security_features));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Execution Via DLL", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, potential_powershell_execution_via_dll));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Downgrade Attack", "Defence Evasion", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, potential_powershell_downgrade_attack));

        event_rules.emplace_back(
            std::make_tuple("Chopper Webshell Process Pattern", "Persistance", "T1505.003", "https://attack.mitre.org/techniques/T1505/003", "Windows", SeverityLevel::High, true, chopper_webshell_process_pattern));

        event_rules.emplace_back(
            std::make_tuple("Webshell Detection With Command Line Keywords", "Persistance", "T1505.003", "https://attack.mitre.org/techniques/T1505/003", "Windows", SeverityLevel::High, true, webshell_detection_with_command_line_keywords));

        event_rules.emplace_back(
            std::make_tuple("Potential COM Objects Download Cradles Usage", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, potential_com_objects_download_cradles_usage));

        event_rules.emplace_back(
            std::make_tuple("Potential DLL File Download Via PowerShell Invoke-WebRequest", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, potential_dll_file_download_via_powershell_invoke_webrequest));

        // event_rules.emplace_back(
        //     std::make_tuple("PowerShell Download and Execution Cradles", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, powershell_download_and_execution_cradles));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Download Pattern", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, powershell_download_pattern));

        event_rules.emplace_back(
            std::make_tuple("Email Exifiltration Via Powershell", "Exfiltration", "T1048", "https://attack.mitre.org/techniques/T1048", "Windows", SeverityLevel::High, true, email_exfiltration_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("Potential Suspicious Windows Feature Enabled", "Defence Evasion", "T1562", "https://attack.mitre.org/techniques/T1562", "Windows", SeverityLevel::Medium, true, potential_suspicious_windows_feature_enabled));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Execution of Powershell with Base64", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, suspicious_execution_of_powershell_with_base64));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Encoded Command Patterns", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, suspicious_powershell_encoded_command_patterns));

        event_rules.emplace_back(
            std::make_tuple("Potential Encoded PowerShell Patterns In CommandLine", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Low, true, potential_encoded_powershell_patterns_in_commandline));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Advpack Call Via Rundll32.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, suspicious_advpack_call_via_rundll32exe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Call by Ordinal", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, suspicious_call_by_ordinal));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Rundll32 Invoking Inline VBScript", "Defence Evasion", "T1055", "https://attack.mitre.org/techniques/T1055", "Windows", SeverityLevel::High, true, suspicious_rundll32_invoking_inline_vbScript));

        event_rules.emplace_back(
            std::make_tuple("Rundll32 InstallScreenSaver Execution", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::Medium, true, rundll32_installscreensaver_execution));

        event_rules.emplace_back(
            std::make_tuple("Rundll32 JS RunHTMLApplication Pattern", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, rundll32_js_runhtmlapplication_pattern));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Key Manager Access", "Credential Access", "T1555.004", "https://attack.mitre.org/techniques/T1555/004", "Windows", SeverityLevel::High, true, suspicious_key_manager_access));

        event_rules.emplace_back(
            std::make_tuple("Powershell Inline Execution From A File", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, powershell_inline_execution_from_a_file));

        event_rules.emplace_back(
            std::make_tuple("Certificate Exported Via PowerShell", "Credential Access", "T1552.004", "https://attack.mitre.org/techniques/T1552/004", "Windows", SeverityLevel::Medium, true, certificate_exported_via_powershell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious FromBase64String Usage On Gzip Archive", "Command and Control", "T1132.001", "https://attack.mitre.org/techniques/T1132/001", "Windows", SeverityLevel::Medium, true, suspicious_frombase64string_usage_on_gzip_archive));

        event_rules.emplace_back(
            std::make_tuple("Base64 Encoded PowerShell Command Detected", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::High, true, base64_encoded_powershell_command_detected));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Get-Clipboard Cmdlet Via CLI", "Collection", "T1115", "https://attack.mitre.org/techniques/T1115", "Windows", SeverityLevel::Medium, true, powershell_get_clipboard_cmdlet_via_cli));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet", "Dicovery", "T1087.001", "https://attack.mitre.org/techniques/T1087/001", "Windows", SeverityLevel::Medium, true, suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Get-Process LSASS", "Credential Access", "T1552.004", "https://attack.mitre.org/techniques/T1552/004", "Windows", SeverityLevel::High, true, powershell_get_process_lsass));

        event_rules.emplace_back(
            std::make_tuple("Malicious Base64 Encoded PowerShell Keywords in Command Lines", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, malicious_base64_encoded_powershell_keywords_in_command_lines));

        event_rules.emplace_back(
            std::make_tuple("Abuse of Service Permissions to Hide Services Via Set-Service", "Privilege Escalation", "T1574.011", "https://attack.mitre.org/techniques/T1574/011", "Windows", SeverityLevel::High, true, abuse_of_service_permission_to_hide_services_via_set_service));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell IEX Execution Patterns", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, suspicious_powershell_iex_execution_patterns));

        event_rules.emplace_back(
            std::make_tuple("Root Certificate Installed From Susp Locations", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004", "Windows", SeverityLevel::High, true, root_certificate_installed_from_susp_locations));

        event_rules.emplace_back(
            std::make_tuple("Import PowerShell Modules From Suspicious Directories", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, import_powershell_modules_from_suspicious_directories));

        event_rules.emplace_back(
            std::make_tuple("Unsigned AppX Installation Attempt Using Add-AppxPackage", "Persistence", "T1505", "https://attack.mitre.org/techniques/T1505", "Windows", SeverityLevel::Medium, true, unsigned_appx_installation_attempt_using_add_appxpackage));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Invocations", "Defence Evasion", "T1553", "https://attack.mitre.org/techniques/T1553", "Windows", SeverityLevel::Medium, true, suspicious_powershell_invocations));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Invoke-WebRequest Execution With DirectIP", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, suspicious_invoke_webRequest_execution_with_directip));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Invoke-WebRequest Execution", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, suspicious_invoke_webRequest_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Mailbox Export to Share", "Exfiltration", "T1048", "https://attack.mitre.org/techniques/T1048", "Windows", SeverityLevel::Critical, true, suspicious_powershell_mailbox_export_to_share));

        event_rules.emplace_back(
            std::make_tuple("MSExchange Transport Agent Installation", "Persistence", "T1505.002", "https://attack.mitre.org/techniques/T1505/002", "Windows", SeverityLevel::Medium, true, msexchange_transport_agent_installation));

        event_rules.emplace_back(
            std::make_tuple("Non Interactive PowerShell Process Spawned", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Low, true, non_interactive_powershell_process_spawned));

        event_rules.emplace_back(
            std::make_tuple("Potential PowerShell Obfuscation Via WCHAR", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, potential_powershell_obfuscation_via_wchar));

        event_rules.emplace_back(
            std::make_tuple("Execution of Powershell Script in Public Folder", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, execution_of_powershell_script_in_public_folder));

        event_rules.emplace_back(
            std::make_tuple("RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, remotefxvgpudisablement_abuse_via_atomictestharnesses));

        event_rules.emplace_back(
            std::make_tuple("Potential Powershell ReverseShell Connection", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, potential_powershell_reverseshell_connection));

        event_rules.emplace_back(
            std::make_tuple("Run PowerShell Script from ADS", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004", "Windows", SeverityLevel::High, true, run_powershell_script_from_ads));

        event_rules.emplace_back(
            std::make_tuple("PowerShell SAM Copy", "Credential Access", "T1003.002", "https://attack.mitre.org/techniques/T1003/002", "Windows", SeverityLevel::High, true, powershell_sam_copy));

        event_rules.emplace_back(
            std::make_tuple("Mshtml DLL RunHTMLApplication Abuse", "Defence Evasion", "T1564.004", "https://attack.mitre.org/techniques/T1564/004", "Windows", SeverityLevel::High, true, mshtml_dll_runhtmlapplication_abuse));

        // event_rules.emplace_back(
        //     std::make_tuple("Rundll32 Execution Without CommandLine Parameters", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::High, true, rundll32_execution_without_commandline_parameters));

        event_rules.emplace_back(
            std::make_tuple("Suspicious NTLM Authentication on the Printer Spooler Service", "Privilege Escalation", "T1212", "https://attack.mitre.org/techniques/T1212", "Windows", SeverityLevel::High, true, suspicious_nltm_authentication_on_the_printer_spooler_service));

        event_rules.emplace_back(
            std::make_tuple("Potential Obfuscated Ordinal Call Via Rundll32", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, potential_obfuscated_ordinal_call_via_rundll32));

        event_rules.emplace_back(
            std::make_tuple("Rundll32 Spawned Via Explorer.EXE", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, rundll32_spawned_via_explorerexe));

        event_rules.emplace_back(
            std::make_tuple("Process Memory Dump Via Comsvcs.DLL", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, process_memory_dump_via_comsvcsdll));

        event_rules.emplace_back(
            std::make_tuple("Potential Credential Dumping Via WER", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, potential_credential_dumping_via_WER));

        event_rules.emplace_back(
            std::make_tuple("Potential ReflectDebugger Content Execution Via WerFault.EXE", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, potential_reflectDebugger_content_execution_via_werFault_EXE));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Child Process Of Wermgr.EXE", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, suspicious_child_process_of_wermgr_EXE));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Execution Location Of Wermgr.EXE", "Execution", "TA0002", "https://attack.mitre.org/tactics/TA0002", "Windows", SeverityLevel::High, true, suspicious_execution_location_of_wermgr_EXE)); // ID To be reviewed

        event_rules.emplace_back(
            std::make_tuple("Potential Recon Activity Using Wevtutil", "Discovery", "TA0007", "https://attack.mitre.org/tactics/TA0007", "Windows", SeverityLevel::Medium, true, potential_recon_activity_using_wevtutil)); // ID To be reviewed

        event_rules.emplace_back(
            std::make_tuple("Suspicious File Download From IP Via Wget.EXE", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Windows", SeverityLevel::High, true, suspicious_file_download_from_IP_via_wget_EXE)); // ID To be reviewed

        event_rules.emplace_back(
            std::make_tuple("Suspicious File Download From File Sharing Domain Via Wget.EXE", "Execution", "T1059.004", "https://attack.mitre.org/techniques/T1059/004", "Windows", SeverityLevel::High, true, suspicious_file_download_from_file_sharing_domain_via_wget_EXE)); // ID To be reviewed

        event_rules.emplace_back(
            std::make_tuple("Suspicious Where Execution", "Discovery", "T1217", "https://attack.mitre.org/techniques/T1217", "Windows", SeverityLevel::Low, true, suspicious_where_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Whoami.EXE Execution From Privileged Process", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::High, true, suspicious_whoami_EXE_execution_from_privileged_process));

        event_rules.emplace_back(
            std::make_tuple("Group Membership Reconnaissance Via Whoami.EXE", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::Medium, true, group_membership_reconnaissance_via_whoami_EXE));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Service DACL Modification Via Set-Service Cmdlet", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::High, true, suspicious_service_dacl_modification_via_set_service_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Set-Acl On Windows Folder", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, powershell_set_acl_on_windows_folder));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Script Change Permission Via Set-Acl", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, powershell_script_change_permission_via_set_acl));

        event_rules.emplace_back(
            std::make_tuple("Change PowerShell Policies to an Insecure Level", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, change_powershell_policies_to_an_insecure_level));

        event_rules.emplace_back(
            std::make_tuple("Service StartupType Change Via PowerShell Set-Service", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, service_startuptype_change_via_powershell_set_service));

        event_rules.emplace_back(
            std::make_tuple("Deletion of Volume Shadow Copies via WMI with PowerShell", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::High, true, deletion_of_volume_shadow_copies_via_wmi_with_powershell));

        event_rules.emplace_back(
            std::make_tuple("Exchange PowerShell Snap-Ins Usage", "Collection", "T1114", "https://attack.mitre.org/techniques/T1114", "Windows", SeverityLevel::High, true, exchange_powershell_snapins_usage));

        event_rules.emplace_back(
            std::make_tuple("Stop Windows Service Via PowerShell Stop-Service", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::Low, true, stop_windows_service_via_powershell_stop_service));

        // event_rules.emplace_back(
        //     std::make_tuple("Potentially Suspicious PowerShell Child Processes", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, potentially_suspicious_powershell_child_processes));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Download and Execute Pattern", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, suspicious_powershell_download_and_execute_pattern));

        event_rules.emplace_back(
            std::make_tuple("Suspicious PowerShell Parent Process", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, suspicious_powershell_parent_process));

        event_rules.emplace_back(
            std::make_tuple("PowerShell Script Run in AppData", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, powershell_script_run_in_appdata));

        event_rules.emplace_back(
            std::make_tuple("PowerShell DownloadFile", "Command and Control", "T1104", "https://attack.mitre.org/techniques/T1104", "Windows", SeverityLevel::High, true, powershell_downloadfile));

        event_rules.emplace_back(
            std::make_tuple("Tamper Windows Defender Remove-MpPreference", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, tamper_windows_defender_remove_mppreference));

        event_rules.emplace_back(
            std::make_tuple("User Discovery And Export Via Get-ADUser Cmdlet", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::Medium, true, user_directory_and_export_via_get_aduser_cmdlet));

        event_rules.emplace_back(
            std::make_tuple("Suspicious XOR Encoded PowerShell Command", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, suspicious_xor_encoded_powershell_command));

        event_rules.emplace_back(
            std::make_tuple("Rundll32 Registered COM Objects", "Privilege Escalation", "T1546.015", "https://attack.mitre.org/techniques/T1546/015", "Windows", SeverityLevel::High, true, rundll32_registered_com_objects));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Process Start Locations", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, suspicious_process_start_locations));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Rundll32 Script in CommandLine", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::Medium, true, suspicious_rundll32_script_in_commandline));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Rundll32 Setupapi.dll Activity", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::Medium, true, suspicious_rundll32_setupapidll_activity));

        event_rules.emplace_back(
            std::make_tuple("Shell32 DLL Execution in Suspicious Directory", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, shell32_dll_execution_in_suspicious_directory));

        event_rules.emplace_back(
            std::make_tuple("Potential ShellDispatch.DLL Functionality Abuse", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, potential_shelldispatchdll_functionality_abuse));

        event_rules.emplace_back(
            std::make_tuple("RunDLL32 Spawning Explorer", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, rundll32_spawning_explorer));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Control Panel DLL Load", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, suspicious_control_panel_dll_load));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Rundll32 Execution With Image Extension", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, suspicious_rundll32_execution_with_image_extension));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Usage Of ShellExec_RunDLL", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, suspicious_usage_of_shellexec_rundll));

        event_rules.emplace_back(
            std::make_tuple("ShimCache Flush", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::High, true, shimcache_flush));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Rundll32 Activity Invoking Sys File", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, suspicious_rundll32_activity_invoking_sys_file));

        event_rules.emplace_back(
            std::make_tuple("Rundll32 UNC Path Execution", "Defence Evasion", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::High, true, rundll32_unc_path_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Workstation Locking via Rundll32", "Defence Evasion", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::Medium, true, suspicious_workstation_locking_via_rundll32));

        event_rules.emplace_back(
            std::make_tuple("WebDav Client Execution Via Rundll32.EXE", "Exfiltration", "T1048.003", "https://attack.mitre.org/techniques/T1048/003", "Windows", SeverityLevel::Medium, true, webdav_client_execution_via_rundll32exe));

        event_rules.emplace_back(
            std::make_tuple("Run Once Task Execution as Configured in Registry", "Defence Evasion", "T1112", "https://attack.mitre.org/techniques/T1112", "Windows", SeverityLevel::Low, true, run_once_task_execution_as_configured_in_registry));

        event_rules.emplace_back(
            std::make_tuple("Possible Privilege Escalation via Weak Service Permissions", "Persistence", "T1574.011", "https://attack.mitre.org/techniques/T1574/011", "Windows", SeverityLevel::High, true, possible_privilege_escalation_via_weak_service_permissions));

        event_rules.emplace_back(
            std::make_tuple("New Service Creation Using Sc.EXE", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::Low, true, new_service_creation_using_scexe));

        event_rules.emplace_back(
            std::make_tuple("Service StartupType Change Via Sc.EXE", "Execution", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, service_startuptype_change_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("New Kernel Driver Via SC.EXE", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::Medium, true, new_kernel_driver_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("SC.EXE Query Execution", "Discovery", "T1007", "https://attack.mitre.org/techniques/T1007", "Windows", SeverityLevel::Low, true, scexe_query_execution));

        event_rules.emplace_back(
            std::make_tuple("Allow Service Access Using Security Descriptor Tampering Via Sc.EXE", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::High, true, allow_service_access_using_security_descriptor_tampering_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("Deny Service Access Using Security Descriptor Tampering Via Sc.EXE", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::High, true, deny_service_access_using_security_descriptor_tampering_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("Service DACL Abuse To Hide Services Via Sc.EXE", "Persistence", "T1574.011", "https://attack.mitre.org/techniques/T1574/011", "Windows", SeverityLevel::High, true, service_dacl_abuse_to_hide_services_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("Service Security Descriptor Tampering Via Sc.EXE", "Persistence", "T1574.011", "https://attack.mitre.org/techniques/T1574/011", "Windows", SeverityLevel::Medium, true, service_security_descriptor_tampering_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Service Path Modification", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::High, true, suspicious_service_path_modification));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Attempt Via Existing Service Tampering", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::Medium, true, potential_persistence_attempt_via_existing_service_tampering));

        event_rules.emplace_back(
            std::make_tuple("Security Privileges Enumeration Via Whoami.EXE", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::High, true, security_privileges_enumeration_via_whoami_EXE));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Whoami.EXE Execution", "Discovery", "T1033", "https://attack.mitre.org/techniques/T1033", "Windows", SeverityLevel::High, true, suspicious_whoami_EXE_execution));

        event_rules.emplace_back(
            std::make_tuple("Add New Download Source To Winget", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, add_new_download_source_to_winget));

        event_rules.emplace_back(
            std::make_tuple("Add Insecure Download Source To Winget", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, add_insecure_download_source_to_winget));

        event_rules.emplace_back(
            std::make_tuple("Add Potential Suspicious New Download Source To Winget", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, add_potential_suspicious_new_download_source_to_winget));

        event_rules.emplace_back(
            std::make_tuple("Winrar Compressing Dump Files", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Medium, true, winrar_compressing_dump_files));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Child Process Of WinRAR.EXE", "Execution", "T1203", "https://attack.mitre.org/techniques/T1203", "Windows", SeverityLevel::Medium, true, potentially_suspicious_child_process_of_winRAR_EXE));

        event_rules.emplace_back(
            std::make_tuple("AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, awl_bypass_with_winrm_vbs_and_malicious_wsmPty_xsl_wsmTxt_xsl));

        event_rules.emplace_back(
            std::make_tuple("Remote Code Execute via Winrm.vbs", "Defence Evasion", "T1216", "https://attack.mitre.org/techniques/T1216", "Windows", SeverityLevel::Medium, true, remote_code_execute_via_winrm_vbs));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Processes Spawned by WinRM", "Initial Access", "T1190", "https://attack.mitre.org/techniques/T1190", "Windows", SeverityLevel::High, true, suspicious_processes_spawned_by_winRM));

        event_rules.emplace_back(
            std::make_tuple("Compress Data and Lock With Password for Exfiltration With WINZIP", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Medium, true, compress_data_and_lock_with_password_for_exfiltration_with_WINZIP));

        event_rules.emplace_back(
            std::make_tuple("New ActiveScriptEventConsumer Created Via Wmic.EXE", "Persistence", "T1546.003", "https://attack.mitre.org/techniques/T1546/003", "Windows", SeverityLevel::High, true, new_activeScriptEventConsumer_created_via_wmic_EXE));

        event_rules.emplace_back(
            std::make_tuple("Tamper with Windows Defender using Command Prompt", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, tamper_with_windows_defender_using_command_prompt));

        event_rules.emplace_back(
            std::make_tuple("New Process Created Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, new_process_created_via_Wmic_EXE));

        event_rules.emplace_back(
            std::make_tuple("Computer System Reconnaissance Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, computer_system_reconnaissance_via_wmic_EXE));

        event_rules.emplace_back(
            std::make_tuple("Hardware Model Reconnaissance Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, hardware_model_reconnaissance_via_wmic_EXE));

        event_rules.emplace_back(
            std::make_tuple("Local Groups Reconnaissance Via Wmic.EXE", "Discovery", "T1069.001", "https://attack.mitre.org/techniques/T1069/001", "Windows", SeverityLevel::Low, true, local_groups_reconnaissance_via_wmic_EXE));

        event_rules.emplace_back(
            std::make_tuple("Zip A Folder With PowerShell For Staging In Temp", "Collection", "T1074.001", "https://attack.mitre.org/techniques/T1074/001", "Windows", SeverityLevel::Medium, true, zip_a_folder_with_powershell_for_staging_in_temp));

        event_rules.emplace_back(
            std::make_tuple("Abusing Print Executable", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, abusing_print_executable));

        // event_rules.emplace_back(
        //     std::make_tuple("Potential Provlaunch.EXE Binary Proxy Execution Abuse", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, potential_provlaunch_exe_binary_proxy_execution_abuse));

        event_rules.emplace_back(
            std::make_tuple("Psr.exe Capture Screenshots", "Collection", "T1113", "https://attack.mitre.org/techniques/T1113", "Windows", SeverityLevel::Medium, true, psr_exe_capture_screenshot));

        event_rules.emplace_back(
            std::make_tuple("PUA - 3Proxy Execution", "Command and Control", "T1572", "https://attack.mitre.org/techniques/T1572", "Windows", SeverityLevel::High, true, pua_3proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE", "Discovery", "T1087.002", "https://attack.mitre.org/techniques/T1087/002", "Windows", SeverityLevel::High, true, pua_suspicious_activedirectory_enumeration_via_adfindexe));

        event_rules.emplace_back(
            std::make_tuple("PUA - AdFind Suspicious Execution", "Discovery", "T1087.002", "https://attack.mitre.org/techniques/T1087/002", "Windows", SeverityLevel::High, true, pua_adfind_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Advanced IP Scanner Execution", "Discovery", "T1046", "https://attack.mitre.org/techniques/T1046", "Windows", SeverityLevel::Medium, true, pua_advanced_ip_scanner_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Advanced Port Scanner Execution", "Discovery", "T1046", "https://attack.mitre.org/techniques/T1046", "Windows", SeverityLevel::Medium, true, pua_advanced_port_scanner_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - AdvancedRun Suspicious Execution", "Privilege Escalation", "T1134.002", "https://attack.mitre.org/techniques/T1134/002", "Windows", SeverityLevel::High, true, pua_advancedrun_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - AdvancedRun Execution", "Privilege Escalation", "T1134.002", "https://attack.mitre.org/techniques/T1134/002", "Windows", SeverityLevel::Medium, true, pua_advancedrun_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Chisel Tunneling Tool Execution", "Command and Control", "T1090.001", "https://attack.mitre.org/techniques/T1090/001", "Windows", SeverityLevel::High, true, pua_chisel_tunneling_tool_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - CleanWipe Execution", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, pua_cleanwipe_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - DIT Snapshot Viewer", "Credential Access", "T1003.003", "https://attack.mitre.org/techniques/T1003/003", "Windows", SeverityLevel::High, true, pua_dit_snapshot_viewer));

        event_rules.emplace_back(
            std::make_tuple("PUA - Fast Reverse Proxy (FRP) Execution", "Command and Control", "T1090", "https://attack.mitre.org/techniques/T1090", "Windows", SeverityLevel::High, true, pua_fast_reverse_proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - IOX Tunneling Tool Execution", "Command and Control", "T1090", "https://attack.mitre.org/techniques/T1090", "Windows", SeverityLevel::High, true, pua_iox_tunneling_tool_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Mouse Lock Execution", "Credential Access", "T1056.002", "https://attack.mitre.org/techniques/T1056/002", "Windows", SeverityLevel::Medium, true, pua_mouse_lock_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Netcat Suspicious Execution", "Command and Control", "T1095", "https://attack.mitre.org/techniques/T1095", "Windows", SeverityLevel::High, true, pua_netcat_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Ngrok Execution", "Command and Control", "T1572", "https://attack.mitre.org/techniques/T1572", "Windows", SeverityLevel::High, true, pua_ngrok_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - NirCmd Execution As LOCAL SYSTEM", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002", "Windows", SeverityLevel::High, true, pua_nircmd_execution_as_local_system));

        event_rules.emplace_back(
            std::make_tuple("PUA - NirCmd Execution", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002", "Windows", SeverityLevel::Medium, true, pua_nircmd_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - NPS Tunneling Tool Execution", "Command and Control", "T1090", "https://attack.mitre.org/techniques/T1090", "Windows", SeverityLevel::High, true, pua_nps_tunneling_tool_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - NSudo Execution", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002", "Windows", SeverityLevel::High, true, pua_nsudo_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Process Hacker Execution", "Persistence", "T1543", "https://attack.mitre.org/techniques/T1543", "Windows", SeverityLevel::High, true, pua_process_hacker_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Potential PE Metadata Tamper Using Rcedit", "Defence Evasion", "T1036.003", "https://attack.mitre.org/techniques/T1036/003", "Windows", SeverityLevel::Medium, true, pua_potential_pe_metadata_tamper_using_rcedit));

        event_rules.emplace_back(
            std::make_tuple("PUA - Rclone Execution", "Exfiltration", "T1567.002", "https://attack.mitre.org/techniques/T1567/002", "Windows", SeverityLevel::High, true, pua_rclone_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - RunXCmd Execution", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002", "Windows", SeverityLevel::High, true, pua_runxcmd_execution));

        event_rules.emplace_back(
            std::make_tuple("PUA - Seatbelt Execution", "Discovery", "T1087", "https://attack.mitre.org/techniques/T1087", "Windows", SeverityLevel::High, true, pua_seatbelt_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Unquoted Service Path Reconnaissance Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, potential_unquoted_service_path_reconnaissance_via_wmicexe));

        event_rules.emplace_back(
            std::make_tuple("WMIC Remote Command Execution", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, wmic_remote_command_execution));

        event_rules.emplace_back(
            std::make_tuple("Service Started/Stopped Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, service_started_stopped_via_wmicexe));

        event_rules.emplace_back(
            std::make_tuple("Potential SquiblyTwo Technique Execution", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, potential_squiblytwo_technique_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious WMIC Execution Via Office Process", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::High, true, suspicious_wmic_execution_via_office_process));

        event_rules.emplace_back(
            std::make_tuple("Stop Windows Service Via Sc.EXE", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489", "Windows", SeverityLevel::Low, true, stop_windows_service_via_scexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Schtasks Execution AppData Folder", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, suspicious_schtasks_execution_appdata_folder));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Modification Of Scheduled Tasks", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, suspicious_modification_of_scheduled_tasks));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Scheduled Task Creation Involving Temp Folder", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, suspicious_scheduled_task_creation_involving_temp_folder));

        event_rules.emplace_back(
            std::make_tuple("Scheduled Task Creation", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::Low, true, scheduled_task_creation));

        event_rules.emplace_back(
            std::make_tuple("Delete All Scheduled Tasks", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489", "Windows", SeverityLevel::High, true, delete_all_scheduled_tasks));

        event_rules.emplace_back(
            std::make_tuple("Delete Important Scheduled Task", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489", "Windows", SeverityLevel::High, true, delete_important_scheduled_tasks));

        event_rules.emplace_back(
            std::make_tuple("Disable Important Scheduled Task", "Impact", "T1489", "https://attack.mitre.org/techniques/T1489", "Windows", SeverityLevel::High, true, disable_important_scheduled_tasks));

        event_rules.emplace_back(
            std::make_tuple("Schtasks From Suspicious Folders", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, schtasks_from_suspicious_folders));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Scheduled Task Name As GUID", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::Medium, true, suspicious_scheduled_task_name_as_guid));

        event_rules.emplace_back(
            std::make_tuple("Uncommon One Time Only Scheduled Task At 00:00", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, uncommon_one_time_only_scheduled_task_at_0000));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Add Scheduled Task Parent", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::Medium, true, suspicious_add_scheduled_task_parent));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Via Microsoft Compatibility Appraiser", "Persistence", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::Medium, true, potential_persistence_via_microsoft_compatibility_appraiser));

        event_rules.emplace_back(
            std::make_tuple("Potential Persistence Via Powershell Search Order Hijacking - Task", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, potential_persistence_via_powershell_search_order_hijacking_task));

        event_rules.emplace_back(
            std::make_tuple("Scheduled Task Executing Encoded Payload from Registry", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, scheduled_task_executing_encoded_payload_from_registry));

        event_rules.emplace_back(
            std::make_tuple("Scheduled Task Executing Payload from Registry", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::Medium, true, scheduled_task_executing_payload_from_registry));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Schtasks Schedule Type With High Privileges", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::Medium, true, suspicious_schtasks_schedule_type_with_high_privileges));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Schtasks Schedule Types", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, suspicious_schtasks_schedule_types));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Scheduled Task Creation via Masqueraded XML File", "Defence Evasion", "T1036.005", "https://attack.mitre.org/techniques/T1036/005", "Windows", SeverityLevel::Medium, true, suspicious_scheduled_task_creation_via_masqueraded_xml_file));

        event_rules.emplace_back(
            std::make_tuple("Script Event Consumer Spawning Process", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::High, true, script_event_consumer_spawning_process));

        event_rules.emplace_back(
            std::make_tuple("Potential Shim Database Persistence via Sdbinst.EXE", "Persistence", "T1546.011", "https://attack.mitre.org/techniques/T1546/011", "Windows", SeverityLevel::Medium, true, potential_shim_database_persistence_via_sdbinstexe));

        event_rules.emplace_back(
            std::make_tuple("Sdclt Child Processes", "Privilege Escalation", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::Medium, true, sdclt_child_processes));

        event_rules.emplace_back(
            std::make_tuple("Sdiagnhost Calling Suspicious Child Process", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::High, true, sdiagnhost_calling_suspicious_child_process));

        event_rules.emplace_back(
            std::make_tuple("Potential Suspicious Activity Using SeCEdit", "Discovery", "T1562.002", "https://attack.mitre.org/techniques/T1562/002", "Windows", SeverityLevel::Medium, true, potential_suspicious_activity_using_secedit));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Serv-U Process Pattern", "Credential Access", "T1555", "https://attack.mitre.org/techniques/T1555", "Windows", SeverityLevel::High, true, suspicious_serv_u_process_pattern));

        event_rules.emplace_back(
            std::make_tuple("Potential SPN Enumeration Via Setspn.EXE", "Credential Access", "T1558.003", "https://attack.mitre.org/techniques/T1558/003", "Windows", SeverityLevel::Medium, true, potential_spn_enumeration_via_setspnexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Execution of Shutdown", "Impact", "T1529", "https://attack.mitre.org/techniques/T1529", "Windows", SeverityLevel::Medium, true, suspicious_execution_of_shutdown));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Execution of Shutdown to Log Out", "Impact", "T1529", "https://attack.mitre.org/techniques/T1529", "Windows", SeverityLevel::Medium, true, suspicious_execution_of_shutdown_to_log_out));

        event_rules.emplace_back(
            std::make_tuple("Uncommon Child Processes Of SndVol.exe", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, uncommon_child_processes_of_sndvolexe));

        event_rules.emplace_back(
            std::make_tuple("Audio Capture via SoundRecorder", "Collection", "T1123", "https://attack.mitre.org/techniques/T1123", "Windows", SeverityLevel::Medium, true, audio_capture_via_soundrecorder));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Splwow64 Without Params", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::High, true, suspicious_splwow64_without_params));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Spool Service Child Process", "Execution", "T1203", "https://attack.mitre.org/techniques/T1203", "Windows", SeverityLevel::High, true, suspicious_spool_service_child_process));

        event_rules.emplace_back(
            std::make_tuple("Veeam Backup Database Suspicious Query", "Collection", "T1005", "https://attack.mitre.org/techniques/T1005", "Windows", SeverityLevel::Medium, true, veeam_backup_database_suspicious_query));

        event_rules.emplace_back(
            std::make_tuple("VeeamBackup Database Credentials Dump Via Sqlcmd.EXE", "Collection", "T1005", "https://attack.mitre.org/techniques/T1005", "Windows", SeverityLevel::High, true, veeambackup_database_credentials_dump_via_sqlcmdexe));

        event_rules.emplace_back(
            std::make_tuple("SQLite Chromium Profile Data DB Access", "Credential Access", "T1539", "https://attack.mitre.org/techniques/T1539", "Windows", SeverityLevel::High, true, sqlite_chromium_profile_data_db_access));

        event_rules.emplace_back(
            std::make_tuple("SQLite Firefox Profile Data DB Access", "Credential Access", "T1539", "https://attack.mitre.org/techniques/T1539", "Windows", SeverityLevel::High, true, sqlite_firefox_profile_data_db_access));

        event_rules.emplace_back(
            std::make_tuple("Port Forwarding Attempt Via SSH", "Command and Control", "T1572", "https://attack.mitre.org/techniques/T1572", "Windows", SeverityLevel::High, true, port_forwarding_attempt_via_ssh));

        event_rules.emplace_back(
            std::make_tuple("Potential RDP Tunneling Via SSH", "Command and Control", "T1572", "https://attack.mitre.org/techniques/T1572", "Windows", SeverityLevel::High, true, potential_rdp_tunneling_via_ssh));

        event_rules.emplace_back(
            std::make_tuple("Potential Amazon SSM Agent Hijacking", "Command and Control", "T1219", "https://attack.mitre.org/techniques/T1219", "Windows", SeverityLevel::Medium, true, potential_amazon_ssm_agent_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Execution via stordiag.exe", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::High, true, execution_via_stordiagexe));

        event_rules.emplace_back(
            std::make_tuple("Start of NT Virtual DOS Machine", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, start_of_nt_virtual_dos_machine));

        event_rules.emplace_back(
            std::make_tuple("Abused Debug Privilege by Arbitrary Parent Processes", "Privilege Escalation", "T1548", "https://attack.mitre.org/techniques/T1548", "Windows", SeverityLevel::High, true, abused_debug_privilege_by_arbitrary_parent_processes));

        event_rules.emplace_back(
            std::make_tuple("Add User to Local Administrators Group", "Persistence", "T1098", "https://attack.mitre.org/techniques/T1098", "Windows", SeverityLevel::Medium, true, add_user_to_local_administrators_group));

        event_rules.emplace_back(
            std::make_tuple("WMI Persistence - Script Event Consumer", "Persistence", "T1546.003", "https://attack.mitre.org/techniques/T1546/003", "Windows", SeverityLevel::Medium, true, wmi_persistence_script_event_consumer));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Process Created Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::High, true, suspicious_process_created_via_wmicexe));

        event_rules.emplace_back(
            std::make_tuple("Application Terminated Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, application_terminated_via_wmicexe));

        event_rules.emplace_back(
            std::make_tuple("Application Removed Via Wmic.EXE", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, application_removed_via_wmicexe));

        event_rules.emplace_back(
            std::make_tuple("Potential Tampering With Security Products Via WMIC", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, potential_tampering_with_security_products_via_wmic));

        event_rules.emplace_back(
            std::make_tuple("XSL Script Processing", "Defence Evasion", "T1220", "https://attack.mitre.org/techniques/T1220", "Windows", SeverityLevel::Medium, true, xsl_script_processing));

        event_rules.emplace_back(
            std::make_tuple("Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, potential_wmi_lateral_movement_wmiprvse_spawned_powershell));

        event_rules.emplace_back(
            std::make_tuple("Suspicious WmiPrvSE Child Process", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::High, true, suspicious_wmiprvse_child_process));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Greedy Compression Using Rar.EXE", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, suspicious_greedy_compression_using_rarexe));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Windows Defender Registry Key Tampering Via Reg.EXE", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::High, true, suspicious_windows_defender_registry_key_tampering_via_regexe));

        event_rules.emplace_back(
            std::make_tuple("Regasm/Regsvcs Suspicious Execution", "Defence Evasion", "T1218.009", "https://attack.mitre.org/techniques/T1218/009", "Windows", SeverityLevel::High, true, regasm_regsvcs_suspicious_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Command Patterns In Scheduled Task Creation", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, suspicious_command_patterns_in_scheduled_task_creation));

        event_rules.emplace_back(
            std::make_tuple("Schtasks Creation Or Modification With SYSTEM Privileges", "Execution", "T1053.005", "https://attack.mitre.org/techniques/T1053/005", "Windows", SeverityLevel::High, true, schtasks_creation_or_modification_with_system_privileges));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Shim Database Installation via Sdbinst.EXE", "Persistence", "T1546.011", "https://attack.mitre.org/techniques/T1546/011", "Windows", SeverityLevel::High, true, suspicious_shim_database_installation_via_sdbinstexe));

        event_rules.emplace_back(
            std::make_tuple("Potential Powershell ReverseShell Connection", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, potential_powershell_reverseShell_connection));

        event_rules.emplace_back(
            std::make_tuple("HackTool - SecurityXploded Execution", "Credential Access", "T1555", "https://attack.mitre.org/techniques/T1555", "Windows", SeverityLevel::Critical, true, hackTool_securityXploded_execution));

        event_rules.emplace_back(
            std::make_tuple("7Zip Compressing Dump Files", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Medium, true, compress_and_exfiltrate_dump_files));

        event_rules.emplace_back(
            std::make_tuple("Compress Data and Lock With Password for Exfiltration With 7-ZIP", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Medium, true, compress_data_and_lock_with_password_for_exfiltration_with_7zip));

        event_rules.emplace_back(
            std::make_tuple("Password Protected Compressed File Extraction Via 7Zip", "Collection", "T1560.001", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Medium, true, password_protected_compressed_file_7zip));

        event_rules.emplace_back(
            std::make_tuple("Esentutl Steals Browser Information", "Collection", "T1005", "https://attack.mitre.org/techniques/T1005", "Windows", SeverityLevel::Medium, true, esentutl_steals_browser_information));

        event_rules.emplace_back(
            std::make_tuple("Browser Execution In Headless Mode", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, browser_execution_headless));

        event_rules.emplace_back(
            std::make_tuple("File Download with Headless Browser", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, file_download_headless_browser));

        event_rules.emplace_back(
            std::make_tuple("Chromium Browser Headless Execution To Mockbin Like Site", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, chromium_headless_execution_mockbin));

        event_rules.emplace_back(
            std::make_tuple("File Download From Browser Process Via Inline Link", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Information, true, file_download_browser_inline_link));

        event_rules.emplace_back(
            std::make_tuple("Tor Client/Browser Execution", "Command and Control", "T1090.003", "https://attack.mitre.org/techniques/T1090/003", "Windows", SeverityLevel::Medium, true, tor_browser_execution));

        event_rules.emplace_back(
            std::make_tuple("File Download via CertOC.EXE", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, file_download_certoc));

        event_rules.emplace_back(
            std::make_tuple("Cloudflared Tunnel Connections Cleanup", "Command and Control", "T1102", "https://attack.mitre.org/techniques/T1102", "Windows", SeverityLevel::Medium, true, cloudflared_tunnel_connection_cleanup));

        event_rules.emplace_back(
            std::make_tuple("Cloudflared Tunnel Execution", "Command and Control", "T1102", "https://attack.mitre.org/techniques/T1102", "Windows", SeverityLevel::Medium, true, cloudflared_tunnel_execution));

        event_rules.emplace_back(
            std::make_tuple("Curl Download And Execute Combination", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::High, true, curl_download_execute_combination));

        event_rules.emplace_back(
            std::make_tuple("Remote File Download Via Desktopimgdownldr Utility", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, remote_file_download_desktopimgdownldr));

        event_rules.emplace_back(
            std::make_tuple("Finger.exe Suspicious Invocation", "Command and Control", "T1105", "https://attack.mitre.org/techniques/T1105", "Windows", SeverityLevel::Medium, true, finger_invocation));

        event_rules.emplace_back(
            std::make_tuple("Potential Data Stealing Via Chromium Headless Debugging", "Credential Access", "T1185", "https://attack.mitre.org/techniques/T1185", "Windows", SeverityLevel::Medium, true, potenital_data_stealing_chromium));

        event_rules.emplace_back(
            std::make_tuple("Browser Started with Remote Debugging", "Credential Access", "T1185", "https://attack.mitre.org/techniques/T1185", "Windows", SeverityLevel::Medium, true, browser_started_remote_debugging));

        event_rules.emplace_back(
            std::make_tuple("Create Symlink to Volume Shadow Copy", "Credential Access", "T1003.003", "https://attack.mitre.org/techniques/T1003/003", "Windows", SeverityLevel::Medium, true, create_symlink_volume_shadow_copy));

        // event_rules.emplace_back(
        //     std::make_tuple("Credentials Cmdkey.EXE", "Credential Access", "T1003.005", "https://attack.mitre.org/techniques/T1003/005", "Windows", SeverityLevel::Medium, true, credentials_cmdkey));

        event_rules.emplace_back(
            std::make_tuple("LSASS Process Reconnaissance Via Findstr.EXE", "Credential Access", "T1552.006", "https://attack.mitre.org/techniques/T1552/006", "Windows", SeverityLevel::High, true, findstr_lssass_process));

        event_rules.emplace_back(
            std::make_tuple("Permission Misconfiguration Reconnaissance Via Findstr.EXE", "Credential Access", "T1552.006", "https://attack.mitre.org/techniques/T1552/006", "Windows", SeverityLevel::Medium, true, permission_misconfiguration_findstr));

        event_rules.emplace_back(
            std::make_tuple("HackTool - ADCSPwn Execution", "Credential Access", "T1557.001", "https://attack.mitre.org/techniques/T1557/001", "Windows", SeverityLevel::High, true, hacktool_adcspwn_execution));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Certify Execution", "Credential Access", "T1649", "https://attack.mitre.org/techniques/T1649", "Windows", SeverityLevel::High, true, hacktool_certify_execution));

        event_rules.emplace_back(
            std::make_tuple("Files And Subdirectories Listing Using Dir", "Discovery", "T1217", "https://attack.mitre.org/techniques/T1217", "Windows", SeverityLevel::Medium, true, files_subdirectories_dir));

        event_rules.emplace_back(
            std::make_tuple("DirLister Execution", "Discovery", "T1083", "https://attack.mitre.org/techniques/T1083", "Windows", SeverityLevel::Low, true, dirlister_execution));

        event_rules.emplace_back(
            std::make_tuple("Domain Trust Discovery Via Dsquery", "Discovery", "T1482", "https://attack.mitre.org/techniques/T1482", "Windows", SeverityLevel::Medium, true, domain_trust_discovery_dsquery));

        event_rules.emplace_back(
            std::make_tuple("Kernel Dump using Dtrace", "Discovery", "T1082", "https://attack.mitre.org/techniques/T1082", "Windows", SeverityLevel::High, true, kernel_dump_dtrace));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Findstr.EXE Execution", "Discovery", "T1057", "https://attack.mitre.org/techniques/T1057", "Windows", SeverityLevel::Medium, true, suspicious_findstr_execution));

        event_rules.emplace_back(
            std::make_tuple("Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE", "Discovery", "T1518.001", "https://attack.mitre.org/techniques/T1518/001", "Windows", SeverityLevel::High, true, sysmon_discovery_findstr));

        event_rules.emplace_back(
            std::make_tuple("Fsutil Drive Enumeration", "Discovery", "T1120", "https://attack.mitre.org/techniques/T1120", "Windows", SeverityLevel::Low, true, fsutil_drive_enumeration));

        event_rules.emplace_back(
            std::make_tuple("Gpresult Display Group Policy Information", "Discovery", "T1615", "https://attack.mitre.org/techniques/T1615", "Windows", SeverityLevel::Medium, true, gpresult_display_group_policy_information));

        event_rules.emplace_back(
            std::make_tuple("Suspicious File Execution From Internet Hosted WebDav Share", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, file_execution_internet_hosted_webdav_share));

        event_rules.emplace_back(
            std::make_tuple("Suspicious CMD Shell Output Redirect", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, cmd_shell_output_redirect));

        event_rules.emplace_back(
            std::make_tuple("Unusual Parent Process For Cmd.EXE", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, suspicious_parent_process_cmd));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Use of CSharp Interactive Console", "Execution", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, suspicious_csharp_interactive_console));

        event_rules.emplace_back(
            std::make_tuple("Potential Cookies Session Hijacking", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, cookies_session_hijacking));

        event_rules.emplace_back(
            std::make_tuple("Curl Web Request With Potential Custom User-Agent", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059/", "Windows", SeverityLevel::Medium, true, curl_web_req_custom_user_agent));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious Child Process Of DiskShadow.EXE", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_child_diskshadow));

        event_rules.emplace_back(
            std::make_tuple("Diskshadow Script Mode - Execution From Potential Suspicious Location", "Execution", "T1218", "https://attack.mitre.org/techniques/1218", "Windows", SeverityLevel::Medium, true, diskshadow_script_mode_suspicious_location));

        event_rules.emplace_back(
            std::make_tuple("Potential Discovery Activity Via Dnscmd.EXE", "Execution", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::Medium, true, discovery_activity_dnscmd));

        event_rules.emplace_back(
            std::make_tuple("Potentially Over Permissive Permissions Granted Using Dsacls.EXE", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, permissive_permissions_granted_dsacls));

        event_rules.emplace_back(
            std::make_tuple("Potential Password Spraying Attempt Using Dsacls.EXE", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, potential_password_spraying_attempt_dsacls));

        event_rules.emplace_back(
            std::make_tuple("Fsutil Behavior Set SymlinkEvaluation", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, fsutil_behaviour_set_symlinkevaluation));

        event_rules.emplace_back(
            std::make_tuple("File Decryption Using Gpg4win", "Execution", "TA002", "https://attack.mitre.org/tactics/TA0002", "Windows", SeverityLevel::Medium, true, file_decryption_gpg4win));

        event_rules.emplace_back(
            std::make_tuple("File Encryption Using Gpg4win", "Execution", "TA002", "https://attack.mitre.org/tactics/TA0002", "Windows", SeverityLevel::Medium, true, file_encryption_gpg4win));

        event_rules.emplace_back(
            std::make_tuple("File Encryption/Decryption Via Gpg4win From Suspicious Locations", "Execution", "TA002", "https://attack.mitre.org/tactics/TA0002", "Windows", SeverityLevel::Medium, true, file_encryption_decryption_gpg4win_locations));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Bloodhound/Sharphound Execution", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, hacktool_bloodhound_sharphound));

        event_rules.emplace_back(
            std::make_tuple("Operator Bloopers Cobalt Strike Commands", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003", "Windows", SeverityLevel::Medium, true, operator_bloopers_cobalt_strike_commands));

        event_rules.emplace_back(
            std::make_tuple("Operator Bloopers Cobalt Strike Modules", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003", "Windows", SeverityLevel::Medium, true, operator_bloopers_cobalt_strike_modules));

        event_rules.emplace_back(
            std::make_tuple("Potential CobaltStrike Process Patterns", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::Medium, true, cobaltstrike_process_pattern));

        event_rules.emplace_back(
            std::make_tuple("HackTool - Covenant PowerShell Launcher", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::Medium, true, hacktool_convenant_powershell_launcher));

        event_rules.emplace_back(
            std::make_tuple("WSL Child Process Anomaly", "Execution", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, wsl_child_process_anomaly));

        event_rules.emplace_back(
            std::make_tuple("Boot Configuration Tampering Via Bcdedit.EXE", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::Medium, true, boot_configuration_tampering_bcdedit));

        event_rules.emplace_back(
            std::make_tuple("Deleted Data Overwritten Via Cipher.EXE", "Impact", "T1485", "https://attack.mitre.org/techniques/T1485", "Windows", SeverityLevel::Medium, true, deleted_data_overwritten_cipher));

        event_rules.emplace_back(
            std::make_tuple("Copy From VolumeShadowCopy Via Cmd.EXE", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::Medium, true, copy_volumeshadowcopy));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Chromium Browser Instance Executed With Custom Extensions", "Persistence", "T1176", "https://attack.mitre.org/techniques/T1176", "Windows", SeverityLevel::Medium, true, suspicious_chromium_custom_extensions));

        event_rules.emplace_back(
            std::make_tuple("Sticky Key Like Backdoor Execution", "Persistence", "T1546.008", "https://attack.mitre.org/techniques/T1546/008", "Windows", SeverityLevel::Critical, true, sticky_key_backdoor_execution));

        event_rules.emplace_back(
            std::make_tuple("Persistence Via Sticky Key Backdoor", "Persistence", "T1546.008", "https://attack.mitre.org/techniques/T1546/008", "Windows", SeverityLevel::Critical, true, sticky_key_backdoor_persistence));

        event_rules.emplace_back(
            std::make_tuple("Interactive AT Job", "Privilege Escalation", "T1053.002", "https://attack.mitre.org/techniques/T1053/002", "Windows", SeverityLevel::Medium, true, interactive_at_job));

        event_rules.emplace_back(
            std::make_tuple("Potential Privilege Escalation Using Symlink Between Osk and Cmd", "Privilege Escalation", "T1546.008", "https://attack.mitre.org/techniques/T1546/008", "Windows", SeverityLevel::Medium, true, symlink_osk_and_cmd));

        event_rules.emplace_back(
            std::make_tuple("HackTool - CoercedPotato Execution", "Privilege Escalation", "T1055", "https://attack.mitre.org/techniques/T1055", "Windows", SeverityLevel::Medium, true, hacktool_coercedPotato));

        event_rules.emplace_back(
            std::make_tuple("Suspicious AddinUtil.EXE CommandLine Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, addinutil_commandline_execution));

        event_rules.emplace_back(
            std::make_tuple("Potential Adplus.EXE Abuse", "Defence Evasion", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::Medium, true, potentital_adplus_abuse));

        event_rules.emplace_back(
            std::make_tuple("AgentExecutor PowerShell Execution", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, agentexecutor_powershell));

        event_rules.emplace_back(
            std::make_tuple("AspNetCompiler Execution", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, aspnetcompiler_execution));

        event_rules.emplace_back(
            std::make_tuple("Suspicious Child Process of AspNetCompiler", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, suspicious_child_process_aspnetcompiler));

        event_rules.emplace_back(
            std::make_tuple("Potentially Suspicious ASP.NET Compilation Via AspNetCompiler", "Defence Evasion", "T1127", "https://attack.mitre.org/techniques/T1127", "Windows", SeverityLevel::Medium, true, potential_suspicious_compilation_aspnet));

        event_rules.emplace_back(
            std::make_tuple("Hiding Files with Attrib.exe", "Defence Evasion", "T1564.001", "https://attack.mitre.org/techniques/T1564/001", "Windows", SeverityLevel::Medium, true, hide_files_attrib));

        event_rules.emplace_back(
            std::make_tuple("Set Files as System Files Using Attrib.EXE", "Defence Evasion", "T1564.001", "https://attack.mitre.org/techniques/T1564/001", "Windows", SeverityLevel::Medium, true, set_files_system_files_attrib));

        event_rules.emplace_back(
            std::make_tuple("Set Suspicious Files as System Files Using Attrib.EXE", "Defence Evasion", "T1564.001", "https://attack.mitre.org/techniques/T1564/001", "Windows", SeverityLevel::Medium, true, suspicious_files_system_files_attrib));

        event_rules.emplace_back(
            std::make_tuple("Audit Policy Tampering Via NT Resource Kit Auditpol", "Defence Evasion", "T1562.002", "https://attack.mitre.org/techniques/T1562/002", "Windows", SeverityLevel::High, true, audit_policy_tampering_via_NT_resource));

        event_rules.emplace_back(std::make_tuple("Audit Policy Tampering Via Auditpol", "Defence Evasion", "T1562.002", "https://attack.mitre.org/techniques/T1562/002", "Windows", SeverityLevel::High, true, audit_policy_tampering_auditpol));

        event_rules.emplace_back(std::make_tuple("Indirect Inline Command Execution Via Bash.EXE", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, indirect_inline_command_execution_bash));

        event_rules.emplace_back(std::make_tuple("Indirect Command Execution From Script File Via Bash.EXE", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, indirect_command_execution_script_bash));

        event_rules.emplace_back(std::make_tuple("Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE", "Defence Evasion", "T1070", "https://attack.mitre.org/techniques/T1070", "Windows", SeverityLevel::Medium, true, potenital_ransomware_bcdedit));

        event_rules.emplace_back(std::make_tuple("Suspicious Child Process Of BgInfo.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_child_bginfo));

        event_rules.emplace_back(std::make_tuple("Uncommon Child Process Of BgInfo.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, uncommon_child_bginfo));

        event_rules.emplace_back(std::make_tuple("File download via Bitsadmin", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::Medium, true, file_download_bitsadmin));

        event_rules.emplace_back(std::make_tuple("Suspicious Download From Direct IP Via Bitsadmin", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::High, true, suspicious_download_ip_bitsadmin));

        event_rules.emplace_back(std::make_tuple("Suspicious Download From File-Sharing Website Via Bitsadmin", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::Medium, true, suspicious_download_file_sharing_bitsadmin));

        event_rules.emplace_back(std::make_tuple("File With Suspicious Extension Downloaded Via Bitsadmin", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::Medium, true, file_download_suspicious_extension_bitsadmin));

        event_rules.emplace_back(std::make_tuple("File Download Via Bitsadmin To A Suspicious Target Folder", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::Medium, true, file_download_bitsadmin_suspicious_target_folder));

        event_rules.emplace_back(std::make_tuple("File Download Via Bitsadmin To An Uncommon Target Folder", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::Medium, true, file_download_bitsadmin_uncommon_target_folder));

        event_rules.emplace_back(std::make_tuple("Monitoring For Persistence Via BITS", "Defence Evasion", "T1197", "https://attack.mitre.org/techniques/T1197", "Windows", SeverityLevel::Medium, true, monitoring_persistence_bits));

        event_rules.emplace_back(std::make_tuple("New Root Certificate Installed Via CertMgr.EXE", "Defence Evasion", "T1553.004", "https://attack.mitre.org/techniques/T1553/004", "Windows", SeverityLevel::Medium, true, new_root_certificate_certmgr));

        event_rules.emplace_back(std::make_tuple("DLL Loaded via CertOC.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, dll_loaded_certoc));

        event_rules.emplace_back(std::make_tuple("Suspicious DLL Loaded via CertOC.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_dll_loaded_certoc));

        event_rules.emplace_back(std::make_tuple("Suspicious Download Via Certutil.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, suspicious_download_certutil));

        event_rules.emplace_back(std::make_tuple("Suspicious File Downloaded From Direct IP Via Certutil.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, suspicious_download_certutil_ip));

        event_rules.emplace_back(std::make_tuple("Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, suspicious_file_download_certutil_file_sharing));

        event_rules.emplace_back(std::make_tuple("Suspicious File Encoded To Base64 Via Certutil.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, suspicious_file_encoded_base64_certutil));

        event_rules.emplace_back(std::make_tuple("File In Suspicious Location Encoded To Base64 Via Certutil.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, file_in_suspicious_location_cerutil));

        event_rules.emplace_back(std::make_tuple("Certificate Exported Via Certutil.EXE", "Defence Evasion", "T1027", "https://attack.mitre.org/techniques/T1027", "Windows", SeverityLevel::Medium, true, certificate_exported_certutil));

        event_rules.emplace_back(std::make_tuple("Potential NTLM Coercion Via Certutil.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, potential_ntlm_coercion_certutil));

        event_rules.emplace_back(std::make_tuple("Greedy File Deletion Using Del", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::Information, true, greedy_file_deletion_using_del));

        event_rules.emplace_back(std::make_tuple("Suspicious Ping/Copy Command Combination", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::Medium, true, ping_copy_command_combination));

        event_rules.emplace_back(std::make_tuple("Ping/Del Command Combination", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::Medium, true, ping_del_command_combination));

        event_rules.emplace_back(std::make_tuple("Directory Removal Via Rmdir", "Defence Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::Information, true, directory_removal_rmdir));

        event_rules.emplace_back(std::make_tuple("Suspicious High IntegrityLevel Conhost Legacy Option", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::Medium, true, suspicious_high_integrity_level_conhost_legacy_option));

        event_rules.emplace_back(std::make_tuple("CreateDump Process Dump", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, createdump_process_dump));

        event_rules.emplace_back(std::make_tuple("Suspicious Csi.exe Usage", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, suspicious_csi_usage));

        event_rules.emplace_back(std::make_tuple("Potential DLL Sideloading Via DeviceEnroller.EXE", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574/002", "Windows", SeverityLevel::Medium, true, potential_dll_sideloading_deviceenroller));

        event_rules.emplace_back(std::make_tuple("Arbitrary MSI Download Via Devinit.EXE", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218", "Windows", SeverityLevel::Medium, true, arbitrary_msi_download_devinit));

        event_rules.emplace_back(std::make_tuple("DNS ServerLevelPluginDll Installed Via Dnscmd.EXE", "Defence Evasion", "T1574.002", "https://attack.mitre.org/techniques/T1574/002", "Windows", SeverityLevel::Medium, true, dns_serverlevelplugindll_dnscmd));

        event_rules.emplace_back(std::make_tuple("Dism Remove Online Package", "Defence Evasion", "T1562.001", "https://attack.mitre.org/techniques/T1562/001", "Windows", SeverityLevel::Medium, true, dism_remove_online_package));

        event_rules.emplace_back(std::make_tuple("DumpMinitool Execution", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, dumpminitool_execution));

        event_rules.emplace_back(std::make_tuple("Explorer Process Tree Break", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, explorer_process_tree_break));

        event_rules.emplace_back(std::make_tuple("Findstr Launching .lnk File", "Defence Evasion", "T1036", "https://attack.mitre.org/techniques/T1036", "Windows", SeverityLevel::Medium, true, findstr_lnk_file));

        event_rules.emplace_back(std::make_tuple("Fsutil Suspicious Invocation", "Defence Evasion", "T1070", "https://attack.mitre.org/techniques/T1070", "Windows", SeverityLevel::Medium, true, fsutil_sus_invocation));

        event_rules.emplace_back(std::make_tuple("Remote CHM File Download/Execution Via HH.EXE", "Defence Evasion", "T1218.001", "https://attack.mitre.org/techniques/T1218/001", "Windows", SeverityLevel::Medium, true, remote_chm_file_download_hh_exe));

        event_rules.emplace_back(std::make_tuple("HTML Help HH.EXE Suspicious Child Process", "Defence Evasion", "T1218.001", "https://attack.mitre.org/techniques/T1218/001", "Windows", SeverityLevel::Medium, true, html_help_hh_exe_child_process));

        event_rules.emplace_back(std::make_tuple("Suspicious HH.EXE Execution", "Defence Evasion", "T1218.001", "https://attack.mitre.org/techniques/T1218/001", "Windows", SeverityLevel::Medium, true, sus_hh_execution));

        event_rules.emplace_back(std::make_tuple("HackTool - F-Secure C3 Load by Rundll32", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::Critical, true, hacktool_c3_load_rundll32));

        event_rules.emplace_back(std::make_tuple("CobaltStrike Load by Rundll32", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::Medium, true, cobaltstrike_load_rundll32));

        event_rules.emplace_back(std::make_tuple("HackTool - DInjector PowerShell Cradle Execution", "Defence Evasion", "T1055", "https://attack.mitre.org/techniques/T1055", "Windows", SeverityLevel::Critical, true, hacktool_dinjector_powershell_cradle_execution));

        event_rules.emplace_back(std::make_tuple("Failed Login Attempt", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::High, true, failed_login_attempt));

        event_rules.emplace_back(std::make_tuple("Uncommon Ports Opened", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Medium, true, uncommon_ports_opened));

        event_rules.emplace_back(std::make_tuple("SSH Successful Attempt", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, ssh_attempt_successful));

        // event_rules.emplace_back(
        //     std::make_tuple("Agobot Backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, agobot_backdoor));

        // event_rules.emplace_back(
        //     std::make_tuple("Fake SMTP Server Detected", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, fake_smtp_server_detection));

        // event_rules.emplace_back(
        //     std::make_tuple("Finger Backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, finger_backdoor));

        // event_rules.emplace_back(
        //     std::make_tuple("Fluxay Sensor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, fluxay_sensor));

        // event_rules.emplace_back(
        //     std::make_tuple("FsSniffer backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, FsSniffer_backdoor));

        // event_rules.emplace_back(
        //     std::make_tuple("GateCrasher Backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, gatecrasher_backdoor));

        // event_rules.emplace_back(
        //     std::make_tuple("Generic backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, generic_backdoor_detection));

        // event_rules.emplace_back(
        //     std::make_tuple("IRC Bot", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, irc_bot_detection));

        // event_rules.emplace_back(
        //     std::make_tuple("IRC Bot Ident Server", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, irc_bot_ident_server));

        // event_rules.emplace_back(
        //     std::make_tuple("Kibuv worm", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, Kibuv_worm_detection));

        // event_rules.emplace_back(
        //     std::make_tuple("Linux FTP server", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Linux", SeverityLevel::Critical, true, linux_ftp_server_backdoor));

        // event_rules.emplace_back(
        //     std::make_tuple("Netbus Software", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, netbus_software));

        // event_rules.emplace_back(
        //     std::make_tuple("Subseven", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, subseven_detection));

        // event_rules.emplace_back(
        //     std::make_tuple("tftp_backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, tftp_backdoor));

        // event_rules.emplace_back(
        //     std::make_tuple("Unrealirc backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, unrealirc_backdoor_detection));

        // event_rules.emplace_back(
        //     std::make_tuple("winshell trojan", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, winshell_trojan));

        // event_rules.emplace_back(
        //     std::make_tuple("wollf backdoor", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, wollf_backdoor));

        //   event_rules.emplace_back(
        //     std::make_tuple("RDP: AnyDesk Connection", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, anydesk_connection));

        //   event_rules.emplace_back(
        //     std::make_tuple("RDP: TeamViewer Connection", "Initial Access", "TA0001", "https://attack.mitre.org/tactics/TA0001", "Windows", SeverityLevel::Critical, true, teamviewer_connection));

        event_rules.emplace_back(
            std::make_tuple("Pikabot - Defense Evasion Pikabot fake DLL extension execution via rundll32", "Defence Evasion", "TA0005", "https://attack.mitre.org/tactics/TA0005/", "Windows", SeverityLevel::High, true, pikabot_fake_dll));

        event_rules.emplace_back(
            std::make_tuple("Potential Pikabot infection via suspicious cmd command combination", "Defence Evasion", "T1218", "https://attack.mitre.org/techniques/T1218/", "Windows", SeverityLevel::High, true, pikabot_infection_via_sus_cmd_combination));

        event_rules.emplace_back(
            std::make_tuple("Qakbot Execution", "Defence Evasion", "T1218.005", "https://attack.mitre.org/techniques/T1218/005", "Windows", SeverityLevel::High, true, qakbot_execution));

        event_rules.emplace_back(
            std::make_tuple("Qakbot - Process tree execution with wscript and cscript ", "Defence Evasion", "T1218.005", "https://attack.mitre.org/techniques/T1218/005", "Windows", SeverityLevel::High, true, qakbot_process_tree_execution));

        event_rules.emplace_back(
            std::make_tuple("MSI installation from the internet via msiexec ", "Defence Evasion", "T1218.007", "https://attack.mitre.org/techniques/T1218/007", "Windows", SeverityLevel::High, true, raspberry_robin_msi_installation));

        event_rules.emplace_back(
            std::make_tuple("Potential Pikabot discovery activity", "Discovery", "T1087", "https://attack.mitre.org/techniques/T1087", "Windows", SeverityLevel::High, true, potential_pikabot_discovery));

        event_rules.emplace_back(
            std::make_tuple("Qakbot - rundll32 execution of Qakbot in non-standard file extension", "Defence Evasion", "T1218.005", "https://attack.mitre.org/techniques/T1218/005", "Windows", SeverityLevel::High, true, qakbot_rundll32_non_standard));
        // event_rules.emplace_back(
        //     std::make_tuple("RULE_BUILDER", "Rule Builder", "NA", "NA", "NA", SeverityLevel::High, true, rule_builder_rule));

        event_rules.emplace_back(
            std::make_tuple("SOAPHound - SOAPHound commands execution", "Discovery", "T1087", "https://attack.mitre.org/techniques/T1087", "Windows", SeverityLevel::High, true, soaphound_commands_execution));

        event_rules.emplace_back(
            std::make_tuple("Remote Access Tool - NetSupport Execution From Unusual Location", "Defence Evasion", "T1567.022", "https://attack.mitre.org/techniques/T1567/022", "Windows", SeverityLevel::Medium, true, netsupport_execution_from_unusual_location));

        event_rules.emplace_back(
            std::make_tuple("Extension loaded into browser at process start", "Persistence", "T1176", "https://attack.mitre.org/techniques/T1176", "Windows", SeverityLevel::High, true, extension_loaded_into_browser_at_process_start));

        event_rules.emplace_back(
            std::make_tuple("Modification of AppInit DLLs registry for persistence", "Persistence", "T1546.010", "https://attack.mitre.org/techniques/T1546/010", "Windows", SeverityLevel::High, true, modification_of_apinit_dlls_registry_for_persistence));

        event_rules.emplace_back(
            std::make_tuple("Discovery activity from SocGholish malware", "Discovery", "T1003", "https://attack.mitre.org/techniques/T1003", "Windows", SeverityLevel::High, true, discovery_activity_from_socgholish_malware));

        event_rules.emplace_back(
            std::make_tuple("DarkGate - Persistence", "Persistence", "T1136.001", "https://attack.mitre.org/techniques/T1136/001", "Windows", SeverityLevel::High, true, darkgate_persistence));

        event_rules.emplace_back(
            std::make_tuple("Emotet - Parent-Child process tree execution", "Defence Evasion", "T1218.010", "https://attack.mitre.org/techniques/T1218/010", "Windows", SeverityLevel::Medium, true, emotet_parent_child_process_tree_execution));

        event_rules.emplace_back(
            std::make_tuple("Impacket - Execution", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Medium, true, impacket_execution));

        event_rules.emplace_back(
            std::make_tuple("Mimikatz - Execution of common modules", "Credential Access", "TA0006", "https://attack.mitre.org/tactics/TA0006", "Windows", SeverityLevel::Low, true, mimikatz_execution_of_common_modules));

        event_rules.emplace_back(
            std::make_tuple("Pikabot - C2", "Command and Control", "T1573", "https://attack.mitre.org/techniques/T1573", "Windows", SeverityLevel::High, true, pikabot_C2));

        event_rules.emplace_back(
            std::make_tuple("3LOSH, AsyncRAT", "Execution", "T1059.001", "https://attack.mitre.org/techniques/T1059/001", "Windows", SeverityLevel::High, true, asyncrat_3losh_malware));

        event_rules.emplace_back(
            std::make_tuple("Cobalt Strike - Usage of common named pipes", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003", "Windows", SeverityLevel::High, true, cobalt_strike_common_pipes));

        event_rules.emplace_back(
            std::make_tuple("Cobalt Strike - Usage of DLL search order hijacking to spawn SQL Server Client Config utility", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003", "Windows", SeverityLevel::High, true, cobalt_strike_sql_server_client_config));

        event_rules.emplace_back(
            std::make_tuple("Cobalt Strike - Usage of GetSystem feature via SYSTEM token impersonation", "Execution", "T1059.003", "https://attack.mitre.org/techniques/T1059/003", "Windows", SeverityLevel::High, true, cobalt_strike_getsystem));

        event_rules.emplace_back(
            std::make_tuple("Darkgate autoit3.exe suspicious execution tree from uncommon location", "Execution", "T1059", "https://attack.mitre.org/techniques/T1059", "Windows", SeverityLevel::High, true, darkgate_autoit3_uncommon_process));

        event_rules.emplace_back(
            std::make_tuple("Usage Winrar utility for archive creation", "Collection", "T1560", "https://attack.mitre.org/techniques/T1560/001", "Windows", SeverityLevel::Low, true, usage_winrar_utility_archive_creation));

        event_rules.emplace_back(
            std::make_tuple("Dump of lsass from task manager", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, dump_lsass_task_manager));

        event_rules.emplace_back(
            std::make_tuple("Abnormal lsass child process", "Credential Access", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, abnormal_lsass_child_process));

        event_rules.emplace_back(
            std::make_tuple("ADWS connection from unexpected binary SOAPhound like", "Collection", "T1119", "https://attack.mitre.org/techniques/T1119", "Windows", SeverityLevel::High, true, adws_connection_soaphound_binary));

        event_rules.emplace_back(
            std::make_tuple("Usage of winrs", "Defence Evasion", "T1202", "https://attack.mitre.org/techniques/T1202", "Windows", SeverityLevel::High, true, usage_of_winrs));

        event_rules.emplace_back(
            std::make_tuple("MSHTA proxy execution", "Defence Evasion", "T1218.005", "https://attack.mitre.org/techniques/T1218/005", "Windows", SeverityLevel::High, true, mshta_proxy_execution));

        event_rules.emplace_back(
            std::make_tuple("Rundll32 execution with DLLRegisterServer command line", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, rundll32_execution_with_dllregisterserver_command_line));

        event_rules.emplace_back(
            std::make_tuple("Suspicious parent process of rundll32", "Defence Evasion", "T1218.011", "https://attack.mitre.org/techniques/T1218/011", "Windows", SeverityLevel::High, true, suspicious_parent_process_of_rundll32));

        event_rules.emplace_back(
            std::make_tuple("File permissions modification", "Defence Evasion", "T1222.001", "https://attack.mitre.org/techniques/T1222/001", "Windows", SeverityLevel::High, true, file_permissions_modification));

        event_rules.emplace_back(
            std::make_tuple("Hiding local user accounts", "Defence Evasion", "T1564.002", "https://attack.mitre.org/techniques/T1564/002", "Windows", SeverityLevel::High, true, hiding_local_user_accounts));

        event_rules.emplace_back(
            std::make_tuple("Registry export via GUI or CLI utility", "Defence Evasion", "T1564.005", "https://attack.mitre.org/techniques/T1564/005", "Windows", SeverityLevel::High, true, registry_export_via_gui_or_cli_utility));

        event_rules.emplace_back(
            std::make_tuple("Users, groups and shares discovery via Powerview", "Discovery", "T1069", "https://attack.mitre.org/techniques/T1069", "Windows", SeverityLevel::High, true, users_groups_and_shares_discovery_via_powerview));

        // Certin Rules - Rushil
        event_rules.emplace_back(
            std::make_tuple("Searching for passwords in file with CLI and Powersploit", "Credential Access", "T1552.001", "https://attack.mitre.org/techniques/T1552/001", "Windows", SeverityLevel::Medium, true, searching_for_passwords_in_file_with_CLI_and_powersploit));

        event_rules.emplace_back(
            std::make_tuple("Common injected process with empty command line", "Defense Evasion", "T1055", "https://attack.mitre.org/techniques/T1055", "Windows", SeverityLevel::Information, true, common_injected_process_with_empty_command_line));

        event_rules.emplace_back(
            std::make_tuple("Event log cleared via wevtutil", "Defense Evasion", "T1070.001", "https://attack.mitre.org/techniques/T1070/001", "Windows", SeverityLevel::Information, true, event_log_cleared_via_wevtutil));

        event_rules.emplace_back(
            std::make_tuple("Anti-forensic deletion, tampering or size reduction of USN Journal", "Defense Evasion", "T1070.004", "https://attack.mitre.org/techniques/T1070/004", "Windows", SeverityLevel::High, true, anti_forensic_deletion_tampering_or_size_reduction_of_USN_journal));

        event_rules.emplace_back(
            std::make_tuple("Suspcious CertUtil execution", "Defense Evasion", "T1132.001", "https://attack.mitre.org/techniques/T1132/001", "Windows", SeverityLevel::Low, true, suspcious_certUtil_execution));

        event_rules.emplace_back(
            std::make_tuple("Domain trust discovery via nltest", "Discovery", "T1482", "https://attack.mitre.org/techniques/T1482", "Windows", SeverityLevel::Low, true, domain_trust_discovery_via_nltest));

        event_rules.emplace_back(
            std::make_tuple("WinRM usage", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Low, true, winrm_usage));

        event_rules.emplace_back(
            std::make_tuple("Process creation via WMI usage", "Execution", "T1047", "https://attack.mitre.org/techniques/T1047", "Windows", SeverityLevel::Low, true, process_creation_via_wmi_usage));

        event_rules.emplace_back(
            std::make_tuple("Suspicious processes spawned by Office or user application", "Execution", "T1204.002", "https://attack.mitre.org/techniques/T1204/002", "Windows", SeverityLevel::Low, true, suspicious_processes_spawned_by_office_or_user_application));

        // event_rules.emplace_back(
        //     std::make_tuple("Suspcious sc.exe spawned by CLI", "Execution", "T1569.002", "https://attack.mitre.org/techniques/T1569/002", "Windows", SeverityLevel::Low, true, suspicious_sc_exe_spawned_by_cli));

        event_rules.emplace_back(
            std::make_tuple("Deletion of shadowcopy via vssadmin or wmic", "Impact", "T1490", "https://attack.mitre.org/techniques/T1490", "Windows", SeverityLevel::Low, true, deletion_of_shadowcopy_via_vssadmin_or_wmic));
        //Chirag rules 
            // event_rules.emplace_back(
            // std::make_tuple("Mimikatz variations and potential lateral movement activity", "Lateral Movement", "T1003.001", "https://attack.mitre.org/techniques/T1003/001", "Windows", SeverityLevel::High, true, mimikatz_variation_and_potential_lateral_movement_activity));
        
        // event_rules.emplace_back(
        //     std::make_tuple("Unsigned process creating binary in SMB share", "Lateral Movement", "T1021.002", "https://attack.mitre.org/techniques/T1021/002", "Windows", SeverityLevel::High, true, unsigned_process_creating_binary_in_smb_share));
        
        // event_rules.emplace_back(
        //     std::make_tuple("Kerberos network communication from suspicious process", "Lateral Movement", "T1550.003", "https://attack.mitre.org/techniques/T1550/003", "Windows", SeverityLevel::High, true, kerberos_network_communication_from_suspicious_process));
        
        event_rules.emplace_back(
            std::make_tuple("Creation of new service via CLI", "Persistence", "T1543.003", "https://attack.mitre.org/techniques/T1543/003", "Windows", SeverityLevel::High, true, creation_of_new_service_via_cli));
        
        // event_rules.emplace_back(
        //     std::make_tuple("Registry run keys modification", "Persistence", "T1547.001", "https://attack.mitre.org/techniques/T1547/001", "Windows", SeverityLevel::High, true, registry_run_keys_modification));
        
        // event_rules.emplace_back(
        //     std::make_tuple("Creation of local or domain account via net utility", "Persistence", "T1136.002", "https://attack.mitre.org/techniques/T1136/002", "Windows", SeverityLevel::High, true, creation_of_local_or_domain_account));
        
        event_rules.emplace_back(
            std::make_tuple("UAC bypass using wusa.exe", "Privildge Escalation", "T1548.002", "https://attack.mitre.org/techniques/T1548/002", "Windows", SeverityLevel::High, true, uac_bypass_usinf_wusaexe));

          event_rules.emplace_back(
            std::make_tuple("Finfisher keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, finfisher_keylogger));

          event_rules.emplace_back(
            std::make_tuple("Ghost keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, ghost_keylogger));    

         event_rules.emplace_back(
            std::make_tuple("Snake keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, snake_keylogger));    

         event_rules.emplace_back(
            std::make_tuple("DD keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, dd_keylogger));    

        event_rules.emplace_back(
            std::make_tuple("JavaServer Pages Backdoor detected", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, jsprat_backdoor));

         event_rules.emplace_back(
            std::make_tuple("Ispy Keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, ispy_keylogger)); 

        
         event_rules.emplace_back(
            std::make_tuple("Kraken Keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, kraken_keylogger));

           event_rules.emplace_back(
            std::make_tuple("Phoenix Keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, phoenix_keylogger));

         event_rules.emplace_back(
            std::make_tuple("Witchetty Keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, witchetty_keylogger));

         event_rules.emplace_back(
            std::make_tuple("Lookback Backdoor", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, lookback_backdoor));                   

         event_rules.emplace_back(
            std::make_tuple("Polonium Keylogger", "Exfiltration", "TA0010", "https://attack.mitre.org/tactics/TA0010", "Windows", SeverityLevel::High, true, polonium_keylogger));                   

         event_rules.emplace_back(
            std::make_tuple("Manual changes in Registry", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::High, true, registry_changes));

        
        event_rules.emplace_back(
            std::make_tuple("Agobot Backdoor Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, agobot_backdoor));

                event_rules.emplace_back(
            std::make_tuple("Manual File Deletion", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::High, true, delete_test_file));

              event_rules.emplace_back(
            std::make_tuple("Phishing Attachment", "Initial Access", "TA0011", "https://attack.mitre.org/tactics/TA0001/", "Windows", SeverityLevel::High, true, phishing_attachment));

         event_rules.emplace_back(
            std::make_tuple("Bagleworm Backdoor Activity Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, bagleworm_backdoor));

          event_rules.emplace_back(
            std::make_tuple("Bagle.B worm Backdoor Activity Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, baglebworm_backdoor));

           event_rules.emplace_back(
            std::make_tuple("Bugbear.B worm Backdoor Activity Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, bugbearbworm_backdoor));

               
        event_rules.emplace_back(
            std::make_tuple("DeepThroat Backdoor Activity Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, deepthroat_backdoor));

                
        event_rules.emplace_back(
            std::make_tuple("Downloadware Backdoor", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, downloadware_software));

                
        event_rules.emplace_back(
            std::make_tuple("Girlfriend Backdoor Activity Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, girlfriend_backdoor));

                
        event_rules.emplace_back(
            std::make_tuple("Lovgate Virus Activity", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, lovgate_virus));

                
        event_rules.emplace_back(
            std::make_tuple("Sasser Virus Activity", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, sasser_virus));

         event_rules.emplace_back(
            std::make_tuple("Timesink SpyWare", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Critical, true, timesink_spyware));

         event_rules.emplace_back(
            std::make_tuple("Changes in registry via application", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Information, true, registry_changes_application));
        
         event_rules.emplace_back(
            std::make_tuple("File Cut and Paste Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Information, true, cut_file));

         event_rules.emplace_back(
            std::make_tuple("File Copy and Paste Detected", "Command and Control", "TA0011", "https://attack.mitre.org/tactics/TA0011/", "Windows", SeverityLevel::Information, true, copy_file));
        
    }

    ~ProcessEventProcessor() override
    {
        event_rules.clear();
        // win_event_rules.clear();
    }

    int load() override
    {
        return 0;
    }

    int unload() override
    {
        return 0;
    }

    PluginInfo version() override
    {
        PluginInfo info;

        info.name = "Process Event Processor";
        info.version_revision = 0;
        info.version_minor = 1;
        info.version_major = 0;
        info.publisher = "self";
        info.version_string = "-dev";

        return info;
    }

    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, SeverityLevel, bool, std::function<bool(const ProcessEvent &, Event &)>>> process_event_rules() override
    {
        return this->event_rules;
    }
    // std::vector<std::tuple<std::string, std::string, std::string, std::string, SeverityLevel, bool, std::function<bool(const WinProcessEvent &, Event &)>>> win_process_event_rules() override{
    //         return this->win_event_rules;
    // }
};

extern "C"
{
    void *module_init()
    {
        ProcessEventProcessor *obj = new ProcessEventProcessor();
        return reinterpret_cast<void *>(obj);
    }

    void module_exit(void *ptr)
    {
        if (ptr)
            delete reinterpret_cast<ProcessEventProcessor *>(ptr);
    }
}