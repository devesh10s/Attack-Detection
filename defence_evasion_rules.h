#ifndef FLEET_DEFENCE_EVASION_RULES_H
#define FLEET_DEFENCE_EVASION_RULES_H

#include "../common/EdrDataTypes.h"

bool potential_linux_process_code_injection_via_DD_utility(const ProcessEvent& process_event, Event& rule_event);
bool ufw_force_stop_using_ufw_init(const ProcessEvent& process_event, Event& rule_event);
bool ESXi_syslog_configuration_change_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool file_deletion(const ProcessEvent& process_event, Event& rule_event);
bool linux_install_root_certificate(const ProcessEvent& process_event, Event& rule_event);
bool linux_shell_pipe_to_shell(const ProcessEvent &process_event, Event &rule_event);
bool touch_suspicious_service_file(const ProcessEvent &process_event, Event &rule_event);
bool triple_cross_ebpf_rootkit_execve_hijack(const ProcessEvent &process_event, Event &rule_event);
bool triple_cross_ebpf_rootkit_install_commands(const ProcessEvent &process_event, Event &rule_event);
bool linux_package_uninstall(const ProcessEvent &process_event, Event &rule_event);
bool disabling_security_tools(const ProcessEvent &process_event, Event &rule_event);
bool disable_or_stop_services(const ProcessEvent &process_event, Event &rule_event);
bool disable_or_stop_services(const ProcessEvent &process_event, Event &rule_event);
bool chmod_suspicious_directory(const ProcessEvent &process_event, Event &rule_event);
bool potentially_suspicious_execution_from_tmp_folder(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_package_installed_linux(const ProcessEvent &process_event, Event &rule_event);
bool flush_iptables_ufw_chain(const ProcessEvent &process_event, Event &rule_event);
bool terminate_linux_process_via_kill(const ProcessEvent &process_event, Event &rule_event);
bool connection_proxy(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_DEFENSE_EVASION_RULES_H