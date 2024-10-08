#ifndef FLEET_WIN_EXECUTION_RULES_H
#define FLEET_WIN_EXECUTION_RULES_H

#include "../common/EdrDataTypes.h"

bool scheduled_task_job(const ProcessEvent &win_process_event, Event &rule_event);
bool native_api(const ProcessEvent &win_process_event, Event &rule_event);
bool command_and_scripting_interpreter(const ProcessEvent &win_process_event, Event &rule_event);
bool service_execution(const ProcessEvent &win_process_event, Event &rule_event);
bool command_scripting_interpreter_javascript(const ProcessEvent &process_event, Event &rule_event);
bool command_scripting_interpreter_powershell(const ProcessEvent &process_event, Event &rule_event);
bool command_scripting_interpreter_win_command_shell(const ProcessEvent &process_event, Event &rule_event);
bool command_scripting_interpreter_visual_basic(const ProcessEvent &process_event, Event &rule_event);
bool malicious_file_user_execution(const ProcessEvent &process_event, Event &rule_event);
bool abuse_nslookup(const ProcessEvent &process_event, Event &rule_event);
bool delete_volume_shadow_copies_via_WMI_with_powershell(const ProcessEvent &process_event, Event &rule_event);
bool remote_powershell_session(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_non_powerShell_WSMAN_COM_provider(const ProcessEvent &process_event, Event &rule_event);
bool powershell_create_local_user(const ProcessEvent &process_event, Event &rule_event);
bool powershell_MsXml_COM_object(const ProcessEvent &process_event, Event &rule_event);
bool powershell_remote_session_creation(const ProcessEvent &process_event, Event &rule_event);
bool use_remove_item_to_delete_file(const ProcessEvent &process_event, Event &rule_event);
bool powershell_execute_batch_script(const ProcessEvent &process_event, Event &rule_event);
bool powershell_XML_execute_command(const ProcessEvent &process_event, Event &rule_event);
bool powershell_scripts_run_by_services(const ProcessEvent &process_event, Event &rule_event);
bool alternate_powershell_hosts(const ProcessEvent &process_event, Event &rule_event);
// bool powershell_called_from_an_executable_version_mismatch(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_powershell_download(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_XOR_encoded_powershell_command_line_powershell(const ProcessEvent &process_event, Event &rule_event);
bool remote_powershell_session_ps_module(const ProcessEvent &process_event, Event &rule_event);
bool powershell_ADRecon_execution(const ProcessEvent &process_event, Event &rule_event);
bool PSAsyncShell_synchronous_TCP_reverse_shell(const ProcessEvent &process_event, Event &rule_event);
bool malicious_shellIntel_powershell_commandlet(const ProcessEvent &process_event, Event &rule_event);
bool Dfsvc_EXE_network_connection_to_uncommon_ports(const ProcessEvent &process_event, Event &rule_event);
bool equation_editor_network_connection(const ProcessEvent &process_event, Event &rule_event);
bool arbitrary_shell_command_execution_via_settingcontent_Ms(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_impact_tools_execution(const ProcessEvent &process_event, Event &rule_event);
bool start_windows_service_via_net_exe(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_jlaive_inmemory_assembly_execution(const ProcessEvent &process_event, Event &rule_event);
bool wsudo_suspicious_execution(const ProcessEvent &process_event, Event &rule_event);
bool python_inline_command_execution(const ProcessEvent &process_event, Event &rule_event);
bool python_spawn_pretty_tty(const ProcessEvent &process_event, Event &rule_event);
bool query_usage_to_exfil_data(const ProcessEvent &process_event, Event &rule_event);
bool potential_data_exfiltration_activity_via_commandLine_tools(const ProcessEvent &process_event, Event &rule_event);
bool elevated_system_shell_spawned(const ProcessEvent &process_event, Event &rule_event);
bool hidden_powershell_in_link_file_pattern(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_file_characteristics_due_to_missing_fields(const ProcessEvent &process_event, Event &rule_event);
bool base64_MZ_header_in_CommandLine(const ProcessEvent &process_event, Event &rule_event);
bool potential_winAPI_calls_via_commandLine(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_koadic_execution(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_pchunter_execution(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_default_powersploit_or_empire_scheduled_task_creation(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_redmimicry_winnti_playbook_execution(const ProcessEvent &process_event, Event &rule_event);
bool usage_of_web_request_commands_and_cmdlets(const ProcessEvent &process_event, Event &rule_event);
bool potential_smb_relay_attack_tool_execution(const ProcessEvent &process_event, Event &rule_event);
bool ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli(const ProcessEvent &process_event, Event &rule_event);
bool sysprep_on_appData_folder(const ProcessEvent &process_event, Event &rule_event);
bool new_virtual_smart_card_created_via_TpmVscMgr_EXE(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_silverc2_implant_activity_pattern(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_zipexec_execution(const ProcessEvent &process_event, Event &rule_event);
bool remote_access_tool_screenconnect_remote_command_execution(const ProcessEvent &process_event, Event &rule_event);
bool outlook_enableunsafeclientmailrules_setting_enabled(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_remote_child_process_from_outlook(const ProcessEvent &process_event, Event &rule_event);
bool renamed_curlexe_execution(const ProcessEvent &process_event, Event &rule_event);
bool renamed_ftpexe_execution(const ProcessEvent &process_event, Event &rule_event);
bool renamed_juschedexe_execution(const ProcessEvent &process_event, Event &rule_event);
bool visual_studio_nodejstools_pressanykey_renamed_execution(const ProcessEvent &process_event, Event &rule_event);
bool potential_renamed_rundll32_execution(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_via_VMwareToolBoxCmd_EXE_VM_state_change_script(const ProcessEvent &process_event, Event &rule_event);
bool vmtoolsd_suspicious_child_process(const ProcessEvent &process_event, Event &rule_event);
bool wab_execution_from_non_default_location(const ProcessEvent &process_event, Event &rule_event);
bool potentially_suspicious_webDAV_LNK_execution(const ProcessEvent &process_event, Event &rule_event);
// bool suspicious_execution_of_pdqdeployrunner(const ProcessEvent &process_event, Event &rule_event);
bool perl_inline_command_execution(const ProcessEvent &process_event, Event &rule_event);
bool php_inline_command_execution(const ProcessEvent &process_event, Event &rule_event);
bool aadinternals_powershell_cmdlets_execution(const ProcessEvent &process_event, Event &rule_event);
bool add_windows_capability_via_powershell_cmdlet(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_encoded_powershell_command_line(const ProcessEvent &process_event, Event &rule_event);
bool powershell_base64_encoded_iex_cmdlet(const ProcessEvent &process_event, Event &rule_event);
bool powershell_base64_encoded_invoke_keyword(const ProcessEvent &process_event, Event &rule_event);
bool potential_powershell_command_line_obfuscation(const ProcessEvent &process_event, Event &rule_event);
bool powershell_execution_with_potential_decryption_capabilities(const ProcessEvent &process_event, Event &rule_event);
bool renamed_psexec_service_execution(const ProcessEvent &process_event, Event &rule_event);
bool ruby_inline_command_execution(const ProcessEvent &process_event, Event &rule_event);
// bool powershell_download_and_execution_cradles(const ProcessEvent &process_event, Event &rule_event);
bool powershell_download_pattern(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_execution_of_powershell_with_base64(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_powershell_encoded_command_patterns(const ProcessEvent &process_event, Event &rule_event);
bool java_running_with_remote_debugging(const ProcessEvent &process_event, Event &rule_event);
bool powershell_inline_execution_from_a_file(const ProcessEvent &process_event, Event &rule_event);
bool malicious_base64_encoded_powershell_keywords_in_command_lines(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_powershell_iex_execution_patterns(const ProcessEvent &process_event, Event &rule_event);
bool import_powershell_modules_from_suspicious_directories(const ProcessEvent &process_event, Event &rule_event);
bool non_interactive_powershell_process_spawned(const ProcessEvent &process_event, Event &rule_event);
bool potential_powershell_obfuscation_via_wchar(const ProcessEvent &process_event, Event &rule_event);
bool execution_of_powershell_script_in_public_folder(const ProcessEvent &process_event, Event &rule_event);
bool potential_powershell_reverseshell_connection(const ProcessEvent &process_event, Event &rule_event);
bool computer_password_change_via_ksetupexe(const ProcessEvent &process_event, Event &rule_event);
bool loggedon_user_password_change_via_ksetupexe(const ProcessEvent &process_event, Event &rule_event);
bool rebuilt_performance_counter_values_via_lodctrexe(const ProcessEvent &process_event, Event &rule_event);
bool windbg_cdb_lolbin_usage(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_cmdl32_execution(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_execution_location_of_wermgr_EXE(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_file_download_from_IP_via_wget_EXE(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_file_download_from_file_sharing_domain_via_wget_EXE(const ProcessEvent &process_event, Event &rule_event);
bool dotnetexe_exec_dll_and_execute_unsigned_code_lolbin(const ProcessEvent &process_event, Event &rule_event);
bool use_of_forfiles_for_execution(const ProcessEvent &process_event, Event &rule_event);
bool use_of_fsharp_interpreters(const ProcessEvent &process_event, Event &rule_event);
bool change_powershell_policies_to_an_insecure_level(const ProcessEvent &process_event, Event &rule_event);
bool potentially_suspicious_powershell_child_processes(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_powershell_download_and_execute_pattern(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_powershell_parent_process(const ProcessEvent &process_event, Event &rule_event);
bool powershell_script_run_in_appdata(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_xor_encoded_powershell_command(const ProcessEvent &process_event, Event &rule_event);
bool potential_shelldispatchdll_functionality_abuse(const ProcessEvent &process_event, Event &rule_event);
bool service_startuptype_change_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool add_new_download_source_to_winget(const ProcessEvent &process_event, Event &rule_event);
bool add_insecure_download_source_to_winget(const ProcessEvent &process_event, Event &rule_event);
bool add_potential_suspicious_new_download_source_to_winget(const ProcessEvent &process_event, Event &rule_event);
bool potentially_suspicious_child_process_of_winRAR_EXE(const ProcessEvent &process_event, Event &rule_event);
bool new_process_created_via_Wmic_EXE(const ProcessEvent &process_event, Event &rule_event);
bool computer_system_reconnaissance_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event);
bool hardware_model_reconnaissance_via_wmic_EXE(const ProcessEvent &process_event, Event &rule_event);
bool pua_nircmd_execution_as_local_system(const ProcessEvent &process_event, Event &rule_event);
bool pua_nircmd_execution(const ProcessEvent &process_event, Event &rule_event);
bool pua_nsudo_execution(const ProcessEvent &process_event, Event &rule_event);
bool pua_runxcmd_execution(const ProcessEvent &process_event, Event &rule_event);
bool potential_unquoted_service_path_reconnaissance_via_wmicexe(const ProcessEvent &process_event, Event &rule_event);
bool wmic_remote_command_execution(const ProcessEvent &process_event, Event &rule_event);
bool service_started_stopped_via_wmicexe(const ProcessEvent &process_event, Event &rule_event);
bool potential_squiblytwo_technique_execution(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_wmic_execution_via_office_process(const ProcessEvent &process_event, Event &rule_event);
bool lolbin_execution_of_the_ftpexe(const ProcessEvent &process_event, Event &rule_event);
bool mpiexec_lolbin(const ProcessEvent &process_event, Event &rule_event);
bool execute_files_with_msdeployexe(const ProcessEvent &process_event, Event &rule_event);
bool use_of_openconsole(const ProcessEvent &process_event, Event &rule_event);
bool use_of_pcalua_for_execution(const ProcessEvent &process_event, Event &rule_event);
bool execute_code_with_pesterbat(const ProcessEvent &process_event, Event &rule_event);
bool execute_code_with_pesterbat_as_parent(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_lolbin_acccheckconsole(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_schtasks_execution_appdata_folder(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_modification_of_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_scheduled_task_creation_involving_temp_folder(const ProcessEvent &process_event, Event &rule_event);
bool scheduled_task_creation(const ProcessEvent &process_event, Event &rule_event);
bool schtasks_from_suspicious_folders(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_scheduled_task_name_as_guid(const ProcessEvent &process_event, Event &rule_event);
bool uncommon_one_time_only_scheduled_task_at_0000(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_add_scheduled_task_parent(const ProcessEvent &process_event, Event &rule_event);
bool potential_persistence_via_powershell_search_order_hijacking_task(const ProcessEvent &process_event, Event &rule_event);
bool scheduled_task_executing_encoded_payload_from_registry(const ProcessEvent &process_event, Event &rule_event);
bool scheduled_task_executing_payload_from_registry(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_schtasks_schedule_type_with_high_privileges(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_schtasks_schedule_types(const ProcessEvent &process_event, Event &rule_event);
bool script_event_consumer_spawning_process(const ProcessEvent &process_event, Event &rule_event);
bool uncommon_child_processes_of_sndvolexe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_spool_service_child_process(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_process_created_via_wmicexe(const ProcessEvent &process_event, Event &rule_event);
bool application_terminated_via_wmicexe(const ProcessEvent &process_event, Event &rule_event);
bool application_removed_via_wmicexe(const ProcessEvent &process_event, Event &rule_event);
bool potential_wmi_lateral_movement_wmiprvse_spawned_powershell(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_wmiprvse_child_process(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_greedy_compression_using_rarexe(const ProcessEvent &process_event, Event &rule_event);
bool wscript_or_cscript_dropper(const ProcessEvent &process_event, Event &rule_event);
bool mmc20_lateral_movement(const ProcessEvent &process_event, Event &rule_event);
// bool potential_suspicious_mofcomp_execution(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_command_patterns_in_scheduled_task_creation(const ProcessEvent &process_event, Event &rule_event);
bool schtasks_creation_or_modification_with_system_privileges(const ProcessEvent &process_event, Event &rule_event);
bool potential_powershell_reverseShell_connection(const ProcessEvent &process_event, Event &rule_event);
bool file_execution_internet_hosted_webdav_share(const ProcessEvent	&process_event, Event &rule_event);
bool cmd_shell_output_redirect(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_parent_process_cmd(const ProcessEvent &process_event, Event &rule_event);
 bool suspicious_csharp_interactive_console(const ProcessEvent &process_event, Event &rule_event);
  bool cookies_session_hijacking(const ProcessEvent &process_event, Event &rule_event);
   bool curl_web_req_custom_user_agent(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_child_diskshadow(const ProcessEvent &process_event, Event &rule_event);
bool diskshadow_script_mode_suspicious_location(const ProcessEvent &process_event, Event &rule_event);
bool discovery_activity_dnscmd(const ProcessEvent &process_event, Event &rule_event);
bool permissive_permissions_granted_dsacls(const ProcessEvent &process_event, Event &rule_event);
bool potential_password_spraying_attempt_dsacls(const ProcessEvent &process_event, Event &rule_event);
bool fsutil_behaviour_set_symlinkevaluation(const ProcessEvent &process_event, Event &rule_event);
bool file_decryption_gpg4win(const ProcessEvent &process_event, Event &rule_event);
bool file_encryption_gpg4win(const ProcessEvent &process_event, Event &rule_event);
bool file_encryption_decryption_gpg4win_locations(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_bloodhound_sharphound(const ProcessEvent &process_event, Event &rule_event);
bool operator_bloopers_cobalt_strike_commands(const ProcessEvent &process_event, Event &rule_event);
bool operator_bloopers_cobalt_strike_modules(const ProcessEvent &process_event, Event &rule_event);
bool cobaltstrike_process_pattern(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_convenant_powershell_launcher(const ProcessEvent &process_event, Event &rule_event);
bool wsl_child_process_anomaly(const ProcessEvent &process_event, Event &rule_event);
bool qakbot_rundll32_non_standard(const ProcessEvent &process_event, Event &rule_event);
bool darkgate_persistence(const ProcessEvent &process_event, Event &rule_event);

bool emotet_parent_child_process_tree_execution(const ProcessEvent &process_event, Event &rule_event);

bool impacket_execution(const ProcessEvent &process_event, Event &rule_event);

bool mimikatz_execution_of_common_modules(const ProcessEvent &process_event, Event &rule_event);

bool pikabot_C2(const ProcessEvent &process_event, Event &rule_event);

bool asyncrat_3losh_malware(const ProcessEvent &process_event, Event &rule_event);
bool cobalt_strike_common_pipes(const ProcessEvent &process_event, Event &rule_event);
bool cobalt_strike_sql_server_client_config(const ProcessEvent &process_event, Event &rule_event);
bool cobalt_strike_getsystem(const ProcessEvent &process_event, Event &rule_event);
bool darkgate_autoit3_uncommon_process(const ProcessEvent &process_event, Event &rule_event);
bool winrm_usage(const ProcessEvent &process_event, Event &rule_event);
bool process_creation_via_wmi_usage(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_processes_spawned_by_office_or_user_application(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_sc_exe_spawned_by_cli(const ProcessEvent &process_event, Event &rule_event);
#endif // FLEET_WIN_EXECUTION_RULES_H


