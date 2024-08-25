#ifndef FLEET_EXECUTION_RULES_H
#define FLEET_EXECUTION_RULES_H

#include "../common/EdrDataTypes.h"

bool ESXi_admin_permission_assigned_to_account_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool ESXi_VM_kill_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool linux_hacktool_execution(const ProcessEvent &process_event, Event &rule_event);
bool interactive_bash_suspicious_children(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_java_children_processes(const ProcessEvent &process_event, Event &rule_event);
bool shell_execution_of_process_located_in_tmp_directory(const ProcessEvent &process_event, Event &rule_event);
bool execution_of_script_located_in_potentially_suspicious_directory(const ProcessEvent &process_event, Event &rule_event);
bool potential_xterm_reverse_shell(const ProcessEvent &process_event, Event &rule_event);
bool potential_netcat_reverse_shell_execution(const ProcessEvent &process_event, Event &rule_event);
bool potential_perl_reverse_shell_execution(const ProcessEvent &process_event, Event &rule_event);
bool potential_php_reverse_shell(const ProcessEvent &process_event, Event &rule_event);
bool potential_python_reverse_shell(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_reverse_shell_command_line(const ProcessEvent &process_event, Event &rule_event);
bool potential_ruby_reverse_shell(const ProcessEvent &process_event, Event &rule_event);
bool potentially_suspicious_named_pipe_created_via_mkfifo(const ProcessEvent &process_event, Event &rule_event);
bool named_pipe_created_via_mkfifo(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_nohup_execution(const ProcessEvent &process_event, Event &rule_event);
bool nohup_execution(const ProcessEvent &process_event, Event &rule_event);
bool python_spawning_pretty_tty(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_EXECUTION_RULES_H