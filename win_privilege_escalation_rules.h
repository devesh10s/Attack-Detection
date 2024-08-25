#ifndef FLEET_WIN_PRIVILEGE_ESCALATION_RULES_H
#define FLEET_WIN_PRIVILEGE_ESCALATION_RULES_H

#include "../common/EdrDataTypes.h"


bool scheduled_task(const ProcessEvent &process_event, Event &rule_event);
bool create_or_modify_windows_process(const ProcessEvent &process_event, Event &rule_event);
bool application_shimming(const ProcessEvent &process_event, Event &rule_event);
bool netsh_helper_dll(const ProcessEvent &process_event, Event &rule_event);
bool registry_run_keys(const ProcessEvent &process_event, Event &rule_event);
bool sid_history_injection(const ProcessEvent &process_event, Event &rule_event);
bool dll_search_order_hijacking(const ProcessEvent &process_event,Event &rule_event);
bool thread_execution_hijacking(const ProcessEvent &process_event,Event &rule_event);
bool pid_parent_spoofing(const ProcessEvent &process_event,Event &rule_event);
bool cmstp(const ProcessEvent &process_event,Event &rule_event);
bool event_triggered_execution_accessibility_features(const ProcessEvent &process_event,Event &rule_event);
bool security_support_provider(const ProcessEvent &process_event, Event &rule_event);
bool group_policy_modification(const ProcessEvent &process_event, Event &rule_event);
bool image_file_execution_options_injection (const ProcessEvent &process_event, Event &rule_event);
bool winlogon_helper_dll(const ProcessEvent &process_event, Event &rule_event);
//
bool com_hijacking_inprocserver32(const ProcessEvent &process_event, Event &rule_event);
bool winlogon_notify_key_logon(const ProcessEvent &process_event , Event &rule_event);
bool powershell_WMI_persistence(const ProcessEvent &process_event, Event &rule_event);
bool powershell_execute_COM_object(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_child_process_created_as_system(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_impersonate_execution(const ProcessEvent &process_event, Event &rule_event);
bool always_install_elevated_MSI_spawned_cmd_and_powershell(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_via_netsh_helper_dll(const ProcessEvent &process_event, Event &rule_event);
bool potential_meterpreter_cobaltstrikeactivity(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_screensave_change_by_regexe(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_sharpimpersonation_execution(const ProcessEvent &process_event, Event &rule_event);
bool regedit_as_trusted_installer(const ProcessEvent &process_event, Event &rule_event);
bool potential_privilege_escalation_via_service_permissions_weakness(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_sharpup_privesc_tool_execution(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_winpeas_execution(const ProcessEvent &process_event, Event &rule_event);
bool bypass_UAC_via_fodhelper_exe(const ProcessEvent &process_event, Event &rule_event);
bool bypass_UAC_via_fodhelper_exe_powershell(const ProcessEvent &process_event, Event &rule_event);
bool uac_bypass_via_windows_firewall_snap_in_hijack(const ProcessEvent &process_event, Event &rule_event);
bool abuse_of_service_permission_to_hide_services_via_set_service(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_nltm_authentication_on_the_printer_spooler_service(const ProcessEvent &process_event, Event &rule_event);
bool rundll32_registered_com_objects(const ProcessEvent &process_event, Event &rule_event);
bool pua_advancedrun_suspicious_execution(const ProcessEvent &process_event, Event &rule_event);
bool pua_advancedrun_execution(const ProcessEvent &process_event, Event &rule_event);
bool sdclt_child_processes(const ProcessEvent &process_event, Event &rule_event);
bool abused_debug_privilege_by_arbitrary_parent_processes(const ProcessEvent &process_event, Event &rule_event);
bool interactive_at_job(const ProcessEvent &process_event, Event &rule_event);
bool symlink_osk_and_cmd(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_coercedPotato(const ProcessEvent &process_event, Event &rule_event);
bool uac_bypass_usinf_wusaexe(const ProcessEvent &process_event, Event &rule_event);
#endif //FLEET_WIN_PRIVILEGE_ESCALATION_RULES_H