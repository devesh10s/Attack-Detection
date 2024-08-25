#ifndef FLEET_WIN_EXFILTERATION_RULES_H
#define FLEET_WIN_EXFILTERATION_RULES_H

#include "../common/EdrDataTypes.h"

bool automated_exfiltration(const ProcessEvent &win_process_event, Event &rule_event);
bool exfiltration_over_encrypted_protocol(const ProcessEvent &win_process_event, Event &rule_event);
bool exfiltration_over_web_service(const ProcessEvent &win_process_event, Event &rule_event);
bool powershell_ICMP_exfiltration(const ProcessEvent &process_event, Event &rule_event);
bool powershell_DNSExfiltration(const ProcessEvent &process_event, Event &rule_event);
bool powershell_exfiltration_over_SMTP(const ProcessEvent &process_event, Event &rule_event);
bool exfiltration_over_web_service(const ProcessEvent &process_event, Event &rule_event);
bool exfiltration_over_web_service(const ProcessEvent &process_event, Event &rule_event);
bool communication_to_mega_nz(const ProcessEvent &process_event, Event &rule_event);
bool communication_to_ngrok_io(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_redirection_to_local_admin_share(const ProcessEvent &process_event, Event &rule_event);
bool exports_critical_registry_keys_to_a_file(const ProcessEvent &process_event, Event &rule_event);
bool exports_registry_key_to_a_file(const ProcessEvent &process_event, Event &rule_event);
bool tap_installer_execution(const ProcessEvent &process_event, Event &rule_event);
bool email_exfiltration_via_powershell(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_powershell_mailbox_export_to_share(const ProcessEvent &process_event, Event &rule_event);
bool active_directory_structure_export_via_ldifdeexe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_configsecuritypolicy_execution(const ProcessEvent &process_event, Event &rule_event);
bool lolbas_data_exfiltration_by_datasvcutilexe(const ProcessEvent &process_event, Event &rule_event);
bool webdav_client_execution_via_rundll32exe(const ProcessEvent &process_event, Event &rule_event);
bool pua_rclone_execution(const ProcessEvent &process_event, Event &rule_event);
bool dns_exfiltration_tunneling_execution(const ProcessEvent &process_event, Event &rule_event);
bool exfiltration_tunneling_tools_execution(const ProcessEvent &process_event, Event &rule_event);
bool finfisher_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool ghost_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool snake_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool dd_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool jsprat_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool ispy_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool kraken_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool phoenix_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool witchetty_keylogger(const ProcessEvent &process_event, Event &rule_event);
bool lookback_backdoor(const ProcessEvent &process_event, Event &rule_event);
bool polonium_keylogger(const ProcessEvent &process_event, Event &rule_event);
#endif // FLEET_WIN_EXFILTERATION_RULES_H