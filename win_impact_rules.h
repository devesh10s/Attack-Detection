#ifndef FLEET_WIN_IMPACT_RULES_H
#define FLEET_WIN_IMPACT_RULES_H

#include "../common/EdrDataTypes.h"

bool service_stop_one(const ProcessEvent &win_process_event, Event &rule_event);
bool service_stop_two(const ProcessEvent &win_process_event, Event &rule_event);
bool service_stop_three(const ProcessEvent &win_process_event, Event &rule_event);
bool internal_defacement_one(const ProcessEvent &win_process_event, Event &rule_event);
bool internal_defacement_two(const ProcessEvent &win_process_event, Event &rule_event);
bool data_encrypted_impact(const ProcessEvent &process_event, Event &rule_event);
bool remove_account_from_domain_admin_group(const ProcessEvent &process_event, Event &rule_event);
bool replace_desktop_wallpaper_by_powershell(const ProcessEvent &process_event, Event &rule_event);
bool powershell_add_name_resolution_policy_table_rule(const ProcessEvent &win_process_event, Event &rule_event);
bool potential_crypto_mining_activity(const ProcessEvent &win_process_event, Event &rule_event);
bool potential_crypto_monero_mining(const ProcessEvent &win_process_event, Event &rule_event);
bool stop_windows_service_via_net_exe(const ProcessEvent &win_process_event, Event &rule_event);
bool suspicious_reg_add_bitlocker(const ProcessEvent &win_process_event, Event &rule_event);
bool potential_file_overwrite_via_sysinternals_sDelete(const ProcessEvent &win_process_event, Event &rule_event);
bool renamed_gpgexe_execution(const ProcessEvent &process_event, Event &rule_event);
bool systemStateBackup_deleted_using_wbadmin_EXE(const ProcessEvent &win_process_event, Event &rule_event);
bool renamed_sysinternals_sdelete_execution(const ProcessEvent &process_event, Event &rule_event);
bool deletion_of_volume_shadow_copies_via_wmi_with_powershell(const ProcessEvent &process_event, Event &rule_event);
bool stop_windows_service_via_powershell_stop_service(const ProcessEvent &process_event, Event &rule_event);
bool stop_windows_service_via_powershell_stop_service(const ProcessEvent &process_event, Event &rule_event);
bool stop_windows_service_via_scexe(const ProcessEvent &process_event, Event &rule_event);
bool delete_all_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event);
bool delete_important_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event);
bool disable_important_scheduled_tasks(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_execution_of_shutdown(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_execution_of_shutdown_to_log_out(const ProcessEvent &process_event, Event &rule_event);
bool sensitivity_registry_access_via_volume_shadow_copy(const ProcessEvent &process_event, Event &rule_event);
bool boot_configuration_tampering_bcdedit(const ProcessEvent &process_event, Event &rule_event);
bool deleted_data_overwritten_cipher(const ProcessEvent &process_event, Event &rule);
bool copy_volumeshadowcopy(const ProcessEvent &process_event, Event &rule_event);
bool deletion_of_shadowcopy_via_vssadmin_or_wmic(const ProcessEvent &process_event, Event &rule_event);
#endif // FLEET_WIN_IMPACT_RULES_H