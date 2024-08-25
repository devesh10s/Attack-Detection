#ifndef PRIVILEGE_ESCALATION_RULES_H
#define PRIVILEGE_ESCALATION_RULES_H

#include "../common/EdrDataTypes.h"

bool linux_doas_tool_execution(const ProcessEvent& process_event, Event& rule_event);
bool user_added_to_root_sudoers_group_using_usermod(const ProcessEvent &process_event, Event &rule_event);
bool scheduled_cron_task_job(const ProcessEvent &process_event, Event &rule_event);
bool sudo_privilege_escalation(const ProcessEvent &process_event, Event &rule_event);
bool omigod_scx_runasprovider_executescript(const ProcessEvent &process_event, Event &rule_event);
bool omigod_scx_runasprovider_executeshellcommand(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_PRIVILEGE_ESCALATION_H