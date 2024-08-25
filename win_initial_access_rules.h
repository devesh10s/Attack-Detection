#ifndef FLEET_WIN_INITIAL_ACCESS_RULES_H
#define FLEET_WIN_INITIAL_ACCESS_RULES_H

#include "../common/EdrDataTypes.h"

bool scheduled_tasks(const ProcessEvent &process_event, Event &rule_event);
bool win_hardware_additions(const ProcessEvent &process_event, Event &rule_event);
bool spearphishing_attack(const ProcessEvent &process_event, Event &rule_event);
bool external_remote_services(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_computer_machine_password_by_powershell(const ProcessEvent &process_event, Event &rule_event);
bool phishing_pattern_ISO_in_archive(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_child_process_of_sql_server(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_child_process_of_veeam_database(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_double_extension_file_execution(const ProcessEvent &process_event, Event &rule_event);
bool remote_access_tool_screenconnect_suspicious_execution(const ProcessEvent &process_event, Event &rule_event);
// bool suspicious_microsoft_onenote_clid_process(const ProcessEvent &process_event, Event &rule_event);
bool execution_in_outlook_temp_folder(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_shells_spawn_by_java_utility_keytool(const ProcessEvent &process_event, Event &rule_event);
bool shells_spawned_by_java(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_shells_spawned_by_java(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_processes_spawned_by_winRM(const ProcessEvent &process_event, Event &rule_event);
bool failed_login_attempt(const ProcessEvent &process_event, Event &rule_event);
bool uncommon_ports_opened(const ProcessEvent &process_event, Event &rule_event);
bool ssh_attempt_successful(const ProcessEvent &process_event, Event &rule_event);

bool agobot_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool fake_smtp_server_detection(const ProcessEvent &process_event, Event &rule_event);
bool finger_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool fluxay_sensor(const ProcessEvent &process_event, Event &rule_event);
bool FsSniffer_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool gatecrasher_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool generic_backdoor_detection(const ProcessEvent &process_event, Event &rule_event);
bool irc_bot_detection(const ProcessEvent &process_event, Event &rule_event);
bool irc_bot_ident_server(const ProcessEvent &process_event, Event &rule_event);
bool Kibuv_worm_detection(const ProcessEvent &process_event, Event &rule_event);
bool linux_ftp_server_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool netbus_software(const ProcessEvent &process_event, Event &rule_event);
bool subseven_detection(const ProcessEvent &process_event, Event &rule_event);
bool tftp_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool unrealirc_backdoor_detection(const ProcessEvent &process_event, Event &rule_event);
bool winshell_trojan(const ProcessEvent &process_event, Event &rule_event);
bool wollf_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool anydesk_connection(const ProcessEvent &process_event, Event &rule_event);
bool teamviewer_connection(const ProcessEvent &process_event, Event &rule_event);
bool phishing_attachment(const ProcessEvent &process_event, Event &rule_event);

#endif