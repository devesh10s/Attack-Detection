#ifndef DISCOVERY_RULES_H
#define DISCOVERY_RULES_H

#include "../common/EdrDataTypes.h"

bool ESXi_network_configuration_discovery_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool ESXi_storage_information_discovery_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool ESXi_system_information_discovery_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool ESXi_VM_list_discovery_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool ESXi_VSAN_information_discovery_via_ESXCLI(const ProcessEvent& process_event, Event& rule_event);
bool OS_architecture_discovery_via_grep(const ProcessEvent& process_event, Event& rule_event);
bool apt_GTFOBin_abuse_linux(const ProcessEvent& process_event, Event& rule_event);
bool vim_GTFOBin_abuse_linux(const ProcessEvent& process_event, Event& rule_event);
bool potential_container_discovery_via_inodes_listing(const ProcessEvent &process_event, Event &rule_event);
bool linux_network_service_scanning_tools_execution(const ProcessEvent &process_event, Event &rule_event);
bool linux_system_information_discovery(const ProcessEvent &process_event, Event &rule_event);
bool system_network_connections_discovery_linux(const ProcessEvent &process_event, Event &rule_event);
bool system_network_discovery_linux(const ProcessEvent &process_event, Event &rule_event);
bool linux_remote_system_discovery(const ProcessEvent &process_event, Event &rule_event);
bool security_software_dicovery(const ProcessEvent &process_event, Event &rule_event);
bool container_residence_discovery_via_proc_virtual_fs(const ProcessEvent &process_event, Event &rule_event);
bool docker_container_discovery_via_dockerenv_listing(const ProcessEvent &process_event, Event &rule_event);
bool potential_discovery_activity_using_find(const ProcessEvent &process_event, Event &rule_event);
bool local_system_accounts_discovery_linux(const ProcessEvent &process_event, Event &rule_event);
bool local_group_discovery_linux(const ProcessEvent &process_event, Event &rule_event);
bool potential_gobrat_file_discovery_via_grep(const ProcessEvent &process_event, Event &rule_event);
// bool process_discovery(const ProcessEvent &process_event, Event &rule_event);

#endif // FLEET_DISCOVERY_H