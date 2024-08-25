#include <iostream>
#include <pqxx/pqxx>
#include <sqlite3.h>
#include "../3rdparty/json.hpp"
#include "rule_builder.h"

#include <thread>
#include <utility>
#include "../common/hostinfo.h"
#include "../common/logger.h"
#include "../common/ConfigurationParser.h"

#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <boost/algorithm/string.hpp>

Rule_Builder::Rule_Builder(std::shared_ptr<ConnectionPool> pool)
{
    this->pool = std::move(pool);
}

[[noreturn]] void Rule_Builder::run_rule_builder()
{
    while (true)
    {
        auto connection = pool->GetConnection();
        std::string rule_builder, tactics, alerters, platform, table_name;
        std::string name, technique_id, type, link, description, rule_written_by;
        nlohmann::json rule_json;
        int id, severity, created, last_modified;
        connection->prepare("rule_builder_rule", "select * from rule_builder_rules");
        pqxx::work transaction{*connection};
        pqxx::result result = transaction.exec_prepared("rule_builder_rule");
        transaction.commit();
        connection->unprepare("rule_builder_rule");
        int no_affected_rows = result.affected_rows();
        if (no_affected_rows > 0)
        {
            for (int i = 0; i < no_affected_rows; i++)
            {
                for (pqxx::result::const_iterator c = result.begin(); c != result.end(); ++c)
                {
                    id = c["id"].as<long>();
                    name = c["name"].as<std::string>();
                    description = c["description"].as<std::string>();
                    link = c["link"].as<std::string>();
                    platform = c["platform"].as<std::string>();
                    severity = c["severity"].as<long>();
                    // nlohmann::json j = nlohmann::json::parse(c["tactics"].as<std::string>());
                    // tactics = j[0]["value"];
                    tactics = "Testing";
                    technique_id = c["technique_id"].as<std::string>();
                    type = c["type"].as<std::string>();
                    rule_written_by = c["rule_written_by"].as<std::string>();
                    alerters = c["alerters"].as<std::string>();
                    rule_builder = c["rule_builder"].as<std::string>();
                    created = c["created"].as<long>();
                    last_modified = c["last_modified"].as<long>();
                    std::string _operator, table, match_case;
                    rule_json = nlohmann::json::parse(rule_builder);
                    int no_of_conditions = rule_json["queries"].size();
                    int no_of_tables = 1;
                    for (int n = 1; n < no_of_conditions; n++)
                    {
                        for (int p = 0; p < n; p++)
                        {
                            if (rule_json["queries"][n]["tableName"] == rule_json["queries"][p]["tableName"])
                            {
                                break;
                            }
                            no_of_tables++;
                        }
                    }
                    // else{
                    std::string operator_rule = rule_json["operator"];
                    table_name = rule_json["queries"][0]["tableName"];
                    std::string column_name = rule_json["queries"][0]["columnName"];

                    std::string conditionType = rule_json["queries"][0]["conditionType"];
                    std::string value = rule_json["queries"][0]["value"];
                    std::string query;

                    if (no_of_conditions == 1)
                    {
                        std::string next_part = ")and is_processed_rule_builder = 'f'";
                        // change < to >
                        query = "select * from " + table_name + " where(";
                        for (int i = 0; i < no_of_conditions; i++)
                        {
                            std::string table_name = rule_json["queries"][i]["tableName"];
                            // std::string table_name_2 = rule_json["queries"][i+1]["tableName"];
                            std::string column_name = rule_json["queries"][i]["columnName"];
                            // std::string column_name_2 = rule_json["queries"][i+1]["columnName"];
                            std::string conditionType = rule_json["queries"][i]["conditionType"];
                            std::string data_type = rule_json["queries"][i]["dataType"];
                            std::string value = rule_json["queries"][i]["value"];
                            if (data_type == "string" and conditionType == "contains")
                            {
                                query += table_name + "." + column_name + " like '%" + value + "%' ";
                            }
                            else if (data_type == "string" and conditionType == "equal")
                            {
                                query += table_name + "." + column_name + " = '" + value + "' ";
                            }
                            else if (data_type == "int" and conditionType == "equal")
                            {
                                query += table_name + "." + column_name + " = " + value;
                            }
                            if (i < no_of_conditions - 1)
                            {
                                query += operator_rule + " ";
                            }
                            // + " "+table_name+"."+column_name+" like '%"+value+"%' "+operator_rule+ " "+table_name+"."+column_name+" like '%"+value+"%'";
                        }
                        query += next_part;
                    }

                    else
                    {
                        std::string commonColumn1, commonColumn2;
                        std::string table_name_2 = rule_json["queries"][1]["tableName"];
                        std::string column_name_2 = rule_json["queries"][1]["columnName"];

                        std::string conditionType_2 = rule_json["queries"][1]["conditionType"];
                        std::string value_2 = rule_json["queries"][1]["value"];
                        std::string next_part = ")and " + table_name + ".is_processed_rule_builder = 'f'";
                        // change < to >

                        if (no_of_tables == 1)
                        {
                            query = "select * from " + table_name + " where (";
                        }
                        else if (rule_json["queries"][0].contains("commonColumn"))
                        {
                            std::string commonColumn1 = rule_json["queries"][0]["commonColumn"];
                            std::string commonColumn2 = rule_json["queries"][0]["commonColumn"];

                            query = "select * from " + table_name + " join " + table_name_2 + " on " + table_name + "." + commonColumn1 + "=" + table_name_2 + "." + commonColumn2 + " where( " + table_name + ".host_identifier = " + table_name_2 + ".host_identifier and ";
                        }
                        // else
                        // {
                        //     query = "select * from " + table_name + " join " + table_name_2 + " on " + table_name + "." + column_name_2 + "=" + table_name_2 + "." + column_name_2 + " where(";
                        // }

                        for (int i = 0; i < no_of_conditions; i++)
                        {
                            std::string table_name = rule_json["queries"][i]["tableName"];
                            // std::string table_name_2 = rule_json["queries"][i+1]["tableName"];
                            std::string column_name = rule_json["queries"][i]["columnName"];
                            // std::string column_name_2 = rule_json["queries"][i+1]["columnName"];
                            std::string conditionType = rule_json["queries"][i]["conditionType"];
                            std::string value = rule_json["queries"][i]["value"];
                            std::string data_type = rule_json["queries"][i]["dataType"];

                            // for (int m = 0; m < i; m++) {
                            // if(table_name == rule_json["queries"][m]["tableName"]){
                            //     query+= table_name+"."+column_name+" like '%"+value+ "%' ";
                            // }
                            // }

                            if (data_type == "string" and conditionType == "contains")
                            {
                                query += table_name + "." + column_name + " like '%" + value + "%' ";
                            }
                            else if (data_type == "string" and conditionType == "equal")
                            {
                                query += table_name + "." + column_name + " = '" + value + "' ";
                            }
                            else if (data_type == "int" and conditionType == "equal")
                            {
                                query += table_name + "." + column_name + " = " + value;
                            }

                            // query+= table_name+"."+column_name+" like '%"+value+ "%' ";
                            if (i < no_of_conditions - 1)
                            {
                                query += operator_rule + " ";
                            }
                            // + " "+table_name+"."+column_name+" like '%"+value+"%' "+operator_rule+ " "+table_name+"."+column_name+" like '%"+value+"%'";
                        }
                        query += next_part;
                    }
                    std::cout << query << std::endl;
                    connection->prepare("rule_builder_query", query);
                    pqxx::result result_count = transaction.exec_prepared("rule_builder_query");
                    int no_detection = result_count.affected_rows();
                    connection->unprepare("rule_builder_query");
                    if (no_detection > 0)
                    {

                        for (int k = 0; k < no_detection; k++)
                        {
                            nlohmann::json event_metadata;
                            long unixtime = result_count.at(k)["unixTime"].as<long>();
                            long start_time = unixtime - 60;
                            long end_time = unixtime + 60;
                            bool isAlert = true;

                            try
                            {
                                for (const auto &column : result_count.at(k))
                                {
                                    std::string column_name = column.name();

                                    // Check for null before conversion (optional, but recommended)
                                    if (column.is_null())
                                    {
                                        // Handle null value (more on this later)
                                        continue; // Or throw a specific null value exception if needed
                                    }
                                    // Dynamically populate event_metadata with column name and value
                                    event_metadata[column_name] = column.as<std::string>();
                                }
                            }
                            catch (const pqxx::conversion_error &e)
                            {
                                continue;
                            }

                            //  ProcessEvent process_event;

                            // process_event.entry.pid = result_count.at(k)["pid"].as<long>();
                            // process_event.entry.path = result_count.at(k)["path"].as<std::string>();
                            // process_event.entry.cmdline = result_count.at(k)["cmdline"].as<std::string>();
                            // process_event.entry.cwd = result_count.at(k)["cwd"].as<std::string>();
                            // process_event.entry.parent = result_count.at(k)["parent"].as<long>();
                            // process_event.entry.syscall = result_count.at(k)["syscall"].as<std::string>();
                            // process_event.entry.action = result_count.at(k)["action"].as<std::string>();
                            // process_event.entry.process_guid = result_count.at(k)["process_guid"].as<std::string>();
                            // process_event.entry.parent_process_guid = result_count.at(k)["parent_process_guid"].as<std::string>();
                            // process_event.entry.process_name = result_count.at(k)["process_name"].as<std::string>();
                            // process_event.entry.local_address = result_count.at(k)["local_address"].as<std::string>();
                            // process_event.entry.remote_address = result_count.at(k)["remote_address"].as<std::string>();
                            // process_event.entry.local_port = result_count.at(k)["local_port"].as<int>();
                            // process_event.entry.remote_port = result_count.at(k)["remote_port"].as<int>();
                            // process_event.entry.target_path = result_count.at(k)["target_path"].as<std::string>();
                            // process_event.entry.md5 = result_count.at(k)["md5"].as<std::string>();
                            // process_event.entry.sha256 = result_count.at(k)["sha256"].as<std::string>();
                            // process_event.entry.hashed = result_count.at(k)["hashed"].as<int>();
                            // // event_metadata["user_id"] = result_count.at(k)["user_id"].as<long long>();
                            // process_event.entry.pid = result_count.at(k)["pid"].as<long>();

                            // event_metadata["pid"] = process_event.entry.pid;
                            // event_metadata["path"] = process_event.entry.path;
                            // event_metadata["action"] = process_event.entry.action;
                            // event_metadata["process_name"] = process_event.entry.process_name;
                            // event_metadata["parent_pid"] = process_event.entry.parent;
                            // event_metadata["family"] = process_event.entry.family;
                            // event_metadata["local_address"] = process_event.entry.local_address;
                            // event_metadata["remote_address"] = process_event.entry.remote_address;
                            // event_metadata["local_port"] = process_event.entry.local_port;
                            // event_metadata["remote_port"] = process_event.entry.remote_port;
                            // event_metadata["target_path"] = process_event.entry.target_path;
                            // event_metadata["md5"] = process_event.entry.md5;
                            // event_metadata["sha256"] = process_event.entry.sha256;
                            // event_metadata["hashed"] = process_event.entry.hashed;

                            if (isAlert)
                            {
                                std::cout << "CODE: " << name << " (" << severity << ")\n";
                                std::cout << "METADATA: " << event_metadata["path"].get<std::string>() << ", " << event_metadata["cmdline"].get<std::string>() << std::endl;
                            }
                            connection->prepare("insert_alerts", "insert into alerts (host_identifier, hostname, unixtime,event_code, metadata, is_alert,severity,is_open, alert_type, technique, technique_id, link, pid, action, os_name) values ($1, $2, $3, $4, $5, $6, $7, true, 'Process Alert', $8, $9, $10, $11, 'None', $12)");

                            // transaction.exec_prepared("insert_events", result_count.at(0)["host_identifier"], result_count.at(0)["hostname"], result_count.at(0)["context_list"], result_count.at(0)["unixtime"], name, "event_metadata.dump()", true, severity, tactics, technique_id, link, result_count.at(0)["event_pid"]);
                            pqxx::result insert_events = transaction.exec_prepared("insert_alerts", result_count.at(k)["host_identifier"].as<std::string>(), result_count.at(k)["hostname"].as<std::string>(), result_count.at(k)["unixtime"].as<long long>(), name, event_metadata.dump(), isAlert, severity, tactics, technique_id, link, result_count.at(k)["pid"].as<long>(), platform);
                            int aff = insert_events.affected_rows();
                            // transaction.commit();
                            connection->unprepare("insert_alerts");
                            // std::time_t t = std::time(0);
                            // int created = t;
                            // std::string query = "update " + table_name + " set is_processed_rule_builder = 't' where unixTime < " + std::to_string(created) + " and is_processed_rule_builder is not true";
                            // connection->prepare("update_is_processed", query);
                            // pqxx::result update_count = transaction.exec_prepared("update_is_processed");
                            // connection->unprepare("update_is_processed");
                            // int no_affected_rows = update_count.affected_rows();
                        }
                    }
                    // }
                }
            }
            std::time_t t = std::time(0);
            int created = t;
            std::string query = "update " + table_name + " set is_processed_rule_builder = 't' where unixTime < " + std::to_string(created) + " and is_processed_rule_builder is not true";
            connection->prepare("update_is_processed", query);
            pqxx::result update_count = transaction.exec_prepared("update_is_processed");
            connection->unprepare("update_is_processed");
            int no_affected_rows = update_count.affected_rows();
        }
    }
}

void Rule_Builder::run()
{
    std::thread run_rule_builder_thread(&Rule_Builder::run_rule_builder, this);

    run_rule_builder_thread.join();
}
