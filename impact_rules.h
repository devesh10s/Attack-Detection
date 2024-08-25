#ifndef FLEET_IMPACT_RULES_H
#define FLEET_IMPACT_RULES_H

#include "../common/EdrDataTypes.h"

bool dd_file_overwrite(const ProcessEvent& process_event, Event& rule_event);
bool group_has_been_deleted_via_groupdel(const ProcessEvent& process_event, Event& rule_event);
bool potential_suspicious_change_to_sensitive_critical_files(const ProcessEvent &process_event, Event &rule_event);
bool user_has_been_deleted_via_userdel(const ProcessEvent &process_event, Event &rule_event);
bool history_file_deletion(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_IMPACT_RULES_H