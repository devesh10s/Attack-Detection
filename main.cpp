#include "../3rdparty/json.hpp"
#include "../common/ConnectionPool.h"
#include "../common/ConfigurationParser.h"
#include "../common/logger.h"
#include <chrono>
#include <ctime>
#include <boost/algorithm/string.hpp>

#include "rule_builder.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <pqxx/pqxx>

int main(int argc, char **argv)
{
    ConfigurationParser config_parser("config.json");
    if (!config_parser.parse())
    {
        return -1;
    }

    FleetServerConfiguration fleet = config_parser.GetFleetConfiguration();
    std::shared_ptr<ConnectionPool> connection_pool(new ConnectionPool(fleet.database.ConnectionString(), fleet.database_pool.maximum_connections));
    
    Rule_Builder engine(connection_pool);
    //engine.run_bpf();
    //engine.run_bpf_file(); 
    engine.run();

    return 0;
}