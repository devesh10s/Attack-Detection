#ifndef FLEET_WIN_LATERAL_MOVEMENT_RULES_H
#define FLEET_WIN_LATERAL_MOVEMENT_RULES_H

#include "../common/EdrDataTypes.h"

bool enable_windows_remote_management(const ProcessEvent &process_event, Event &rule_event);
bool execute_invoke_command_on_remote_host(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_new_PSDrive_to_admin_share(const ProcessEvent &process_event, Event &rule_event);
bool potential_mstsc_shadowing_activity(const ProcessEvent &process_event, Event &rule_event);
bool new_remote_desktop_connection_initiated_via_mstsc_exe(const ProcessEvent &process_event, Event &rule_event);
bool windows_admin_share_mount_via_net_exe(const ProcessEvent &process_event, Event &rule_event);
bool windows_internet_hosted_webdav_share_mount_via_net_exe(const ProcessEvent &process_event, Event &rule_event);
bool windows_share_mount_via_net_exe(const ProcessEvent &process_event, Event &rule_event);
bool password_provided_in_command_line_of_net_exe(const ProcessEvent &process_event, Event &rule_event);
bool privilege_escalation_via_named_pipe_impersonation(const ProcessEvent &process_event, Event &rule_event);
bool potential_remote_desktop_tunneling(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_RDP_redirect_using_TSCON(const ProcessEvent &process_event, Event &rule_event);
bool changing_RDP_port_to_non_standard_port_via_powershell(const ProcessEvent &process_event, Event &rule_event);
bool rdp_port_forwarding_rule_added_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event);
bool new_port_forwarding_rule_added_via_netsh_exe(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_ultraVNC_execution(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_sysaidserver_child(const ProcessEvent &process_event, Event &rule_event);
bool mmc_spawning_windows_shell(const ProcessEvent &process_event, Event &rule_event);
bool mimikatz_variation_and_potential_lateral_movement_activity(const ProcessEvent &process_event, Event &rule_event);
bool unsigned_process_creating_binary_in_smb_share(const ProcessEvent &process_event, Event &rule_event);
bool kerberos_network_communication_from_suspicious_process(const ProcessEvent &process_event, Event &rule_event);
#endif
