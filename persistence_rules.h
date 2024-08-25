#ifndef PERSISTENCE_RULES_H
#define PERSISTENCE_RULES_H

#include "../common/EdrDataTypes.h"

bool ESXi_account_creation_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool setuid_and_setgid(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_PERSISTENCE_H