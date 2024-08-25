#ifndef FLEET_WIN_RESOURCE_DEVELOPMENT_RULES_H
#define FLEET_WIN_RESOURCE_DEVELOPMENT_RULES_H

#include "../common/EdrDataTypes.h"


bool potential_execution_of_sysinternals_tools(const ProcessEvent &process_event, Event &rule_event);
bool psExec_PAExec_escalation_to_LOCAL_SYSTEM(const ProcessEvent &process_event, Event &rule_event);
bool potential_PsExec_remote_execution(const ProcessEvent &process_event, Event &rule_event);
bool renamed_sysinternals_debugview_execution(const ProcessEvent &process_event, Event &rule_event);
bool hacktool_purplesharp_execution(const ProcessEvent &process_event, Event &rule_event);
#endif // FLEET_WIN_RESOURCE_DEVELOPMENT_RULES_H


