
#ifndef FLEET_WIN_COLLECTION_RULES_H
#define FLEET_WIN_COLLECTION_RULES_H

#include "../common/EdrDataTypes.h"

bool screen_capture(const ProcessEvent &process_event, Event &rule_event);
bool data_staged(const ProcessEvent &process_event, Event &rule_event);
bool automated_collection(const ProcessEvent &process_event, Event &rule_event);
bool clipboard_data(const ProcessEvent &process_event, Event &rule_event);
bool archive_collected_data(const ProcessEvent &process_event, Event &rule_event);
bool video_capture(const ProcessEvent &process_event, Event &rule_event);
bool network_shared_drive_data(const ProcessEvent &process_event, Event &rule_event);
bool audio_capture(const ProcessEvent &process_event, Event &rule_event);
bool gui_input_capture(const ProcessEvent &process_event, Event &rule_event);
bool powershell_keylogging(const ProcessEvent &process_event, Event &rule_event);
bool powershell_local_email_collection(const ProcessEvent &process_event, Event &rule_event);
bool recon_information_for_export_with_powershell(const ProcessEvent &process_event, Event &rule_event);
bool powershell_get_clipboard(const ProcessEvent &process_event, Event &rule_event);
bool automated_collection_command_prompt(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_manipulation_of_default_accounts_via_net_exe(const ProcessEvent &process_event, Event &rule_event);
// bool recon_information_for_export_with_powershell(const ProcessEvent &process_event, Event &rule_event);
bool files_added_to_archive_using_rar(const ProcessEvent &process_event, Event &rule_event);
bool rar_usage_with_password_and_compression_level(const ProcessEvent &process_event, Event &rule_event);
bool copy_from_admin_share(const ProcessEvent &process_event, Event &rule_event);
bool recon_information_for_export_with_command_prompt(const ProcessEvent &process_event, Event &rule_event);
bool audio_capture_via_powershell(const ProcessEvent &process_event, Event &rule_event);
bool powershell_get_clipboard_cmdlet_via_cli(const ProcessEvent &process_event, Event &rule_event);
bool exchange_powershell_snapins_usage(const ProcessEvent &process_event, Event &rule_event);
bool winrar_compressing_dump_files(const ProcessEvent &process_event, Event &rule_event);
bool compress_data_and_lock_with_password_for_exfiltration_with_WINZIP(const ProcessEvent &process_event, Event &rule_event);
bool zip_a_folder_with_powershell_for_staging_in_temp(const ProcessEvent &process_event, Event &rule_event);
bool psr_exe_capture_screenshot(const ProcessEvent &process_event, Event &rule_event);
bool audio_capture_via_soundrecorder(const ProcessEvent &process_event, Event &rule_event);
bool veeam_backup_database_suspicious_query(const ProcessEvent &process_event, Event &rule_event);
bool veeambackup_database_credentials_dump_via_sqlcmdexe(const ProcessEvent &process_event, Event &rule_event);
bool compress_and_exfiltrate_dump_files(const ProcessEvent &process_event, Event &rule_event);
bool compress_data_and_lock_with_password_for_exfiltration_with_7zip(const ProcessEvent &process_event, Event &rule_event);
bool password_protected_compressed_file_7zip(const ProcessEvent &process_event, Event &rule_event);
bool esentutl_steals_browser_information(const ProcessEvent &process_event, Event &rule_event);
bool usage_winrar_utility_archive_creation(const ProcessEvent &process_event, Event &rule_event);
bool dump_lsass_task_manager(const ProcessEvent &process_event, Event &rule_event);
bool abnormal_lsass_child_process(const ProcessEvent &process_event, Event &rule_event);
bool adws_connection_soaphound_binary(const ProcessEvent &process_event, Event &rule_event);
bool delete_test_file(const ProcessEvent &process_event, Event &rule_event);
bool cut_file(const ProcessEvent &process_event, Event &rule_event);
bool copy_file(const ProcessEvent &process_event, Event &rule_event);
#endif // FLEET_WIN_COLLECTION_RULES_H