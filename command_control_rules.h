#ifndef FLEET_COMMAND_CONTROL_RULES_H
#define FLEET_COMMAND_CONTROL_RULES_H

#include "../common/EdrDataTypes.h"

bool non_standard_port_command_control(const ProcessEvent& process_event, Event& rule_event);
bool download_file_to_potentially_suspicious_directory_via_wget(const ProcessEvent &process_event, Event &rule_event);
bool potential_linux_amazon_ssm_agent_hijacking(const ProcessEvent &process_event, Event &rule_event);
bool suspicious_curl_change_user_agents(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_COMMAND_CONTROL_RULES_H