#ifndef WIN_PERSISTENCE_RULES_H
#define WIN_PERSISTENCE_RULES_H

#include "../common/EdrDataTypes.h"

bool append_malicious_start_process_cmdlet(const ProcessEvent &process_event, Event &rule_event);
bool running_chrome_vpn_extensions(const ProcessEvent &process_event, Event &rule_event);
bool active_setup(const ProcessEvent &process_event, Event &rule_event);
bool time_providers_new(const ProcessEvent &process_event, Event &rule_event);
bool persistent_code_evecution_via_excel_vba_addin(const ProcessEvent &process_event, Event &rule_event);
bool persistent_code_execution_via_word_addin(const ProcessEvent &process_event, Event &rule_event);
bool port_monitors(const ProcessEvent &process_event, Event &rule_event);
bool shortcut_modification(const ProcessEvent &process_event, Event &rule_event);
bool search_order_hijacking(const ProcessEvent &process_event, Event &rule_event);
bool server_software_component_web_shell(const ProcessEvent &process_event, Event &rule_event);
bool component_object_model_hijacking(const ProcessEvent &process_event, Event &rule_event);
bool change_default_file_association(const ProcessEvent &process_event, Event &rule_event);
//
bool win_logon_script(const ProcessEvent &process_event, Event &rule_event);
bool event_triggered_exevution_screensaver(const ProcessEvent &process_event, Event &rule_event);
bool registry_run_keys_persistence_via_recycle_bin(const ProcessEvent &process_event, Event &rule_event);
bool security_support_provider_ssp(const ProcessEvent &process_event, Event &rule_event);
bool bypass_uac_sdclt_delegate_execute(const ProcessEvent &process_event, Event &rule_event);
bool bypass_uac_eventviewer(const ProcessEvent &process_event, Event &rule_event);
bool bypass_uac_disable_reg(const ProcessEvent &process_event, Event &rule_event);
bool office_applicatoin_startup(const ProcessEvent &process_event, Event &rule_event);
bool boot_logon_autostart_execution_run_runonce(const ProcessEvent &process_event, Event &rule_event);
bool registry_free_process_scope_COR_PROFILER(const ProcessEvent &process_event, Event &rule_event);
bool service_registry_permissions_weakness_check(const ProcessEvent &process_event, Event &rule_event);
bool powershell_localAccount_manipulation(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_GetTypeFromCLSID_shellexecute(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_via_powershell_user_profile_using_add_content(const ProcessEvent &process_event, Event &rule_event);
// bool winlogon_helper_DLL(const ProcessEvent &process_event, Event &rule_event);
bool manipulation_of_user_computer_or_group_security_principals_across_AD(const ProcessEvent &process_event, Event &rule_event);
bool code_executed_via_office_add_in_XLL_file(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_add_user_to_remote_desktop_users_group(const ProcessEvent &process_event, Event &rule_event);
bool persistence_attempt_via_runkeys(const ProcessEvent &process_event, Event &rule_event);
bool new_user_created_via_net_exe_with_never_expire_option(const ProcessEvent &process_event, Event &rule_event);
bool new_user_created_via_net_exe(const ProcessEvent &process_event, Event &rule_event);
bool direct_autorun_keys_modification(const ProcessEvent &process_event, Event &rule_event);
bool changing_existing_service_imagepath_value_via_regexe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_process_execution_from_fake_recycle_bin_folder(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_new_service_creation(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_sharpersist_execution(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_debugger_registration_cmdline(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_via_logon_scripts_commandline(const ProcessEvent &process_event, Event &rule_event);
bool persistence_via_typedpaths_commandline(const ProcessEvent &process_event, Event &rule_event);
bool uncommon_userinit_child_process(const ProcessEvent &process_event, Event &rule_event);
bool iis_native_code_module_commandline_installation(const ProcessEvent &process_event, Event &rule_event);
bool new_service_creation_using_powershell(const ProcessEvent &process_event, Event &rule_event);
bool chopper_webshell_process_pattern(const ProcessEvent &process_event, Event &rule_event);
bool webshell_detection_with_command_line_keywords(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_iis_module_registration(const ProcessEvent &process_event, Event &rule_event);
bool unsigned_appx_installation_attempt_using_add_appxpackage(const ProcessEvent &process_event, Event &rule_event);
bool msexchange_transport_agent_installation(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_service_dacl_modification_via_set_service_cmdlet(const ProcessEvent &process_event, Event &rule_event);
bool possible_privilege_escalation_via_weak_service_permissions(const ProcessEvent &process_event, Event &rule_event);
bool new_service_creation_using_scexe(const ProcessEvent &process_event, Event &rule_event);
bool new_kernel_driver_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool allow_service_access_using_security_descriptor_tampering_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool deny_service_access_using_security_descriptor_tampering_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool service_dacl_abuse_to_hide_services_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool service_security_descriptor_tampering_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_service_path_modification(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_attempt_via_existing_service_tampering(const ProcessEvent &process_event, Event &rule_event);
bool new_activeScriptEventConsumer_created_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event);
bool pua_process_hacker_execution(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_driver_install_by_pnputilexe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_grpconv_execution(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_via_microsoft_compatibility_appraiser(const ProcessEvent &process_event, Event &rule_event);
bool potential_shim_database_persistence_via_sdbinstexe(const ProcessEvent &process_event, Event &rule_event);
bool add_user_to_local_administrators_group(const ProcessEvent &process_event, Event &rule_event);
bool wmi_persistence_script_event_consumer(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_shim_database_installation_via_sdbinstexe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_chromium_custom_extensions(const ProcessEvent &process_event, Event &rule_event);
bool sticky_key_backdoor_execution(const ProcessEvent &process_event, Event &rule_event);
bool sticky_key_backdoor_persistence(const ProcessEvent &process_event, Event &rule_event);
bool extension_loaded_into_browser_at_process_start(const ProcessEvent &process_event, Event &rule_event);
bool modification_of_apinit_dlls_registry_for_persistence(const ProcessEvent &process_event, Event &rule_event);
bool creation_of_new_service_via_cli(const ProcessEvent &process_event, Event &rule_event);
bool registry_run_keys_modification(const ProcessEvent &process_event, Event &rule_event);
bool creation_of_local_or_domain_account(const ProcessEvent &process_event, Event &rule_event);

#endif
