#pragma once 

#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <functional>

#include "loop.h"
#include "socket.h"

class server_init_kit;

void server_loop();
void process_server_protocol(server_init_kit& input_proto);

class server_init_kit {
    public:
        std::unique_ptr<IDataSocket> clientA;
        std::unique_ptr<IDataSocket> clientB;

        std::unique_ptr<readable_ip_info> privA;
        std::unique_ptr<readable_ip_info> privB;

        IDataSocket* cA;
        IDataSocket* cB;

        std::unique_ptr<IListenSocket> server_socket;

        std::vector<char> recv_data;

        EXECUTION_STATUS status;
        protocol proto;

        server_init_kit(protocol proto);
        server_init_kit(server_init_kit&& other);

        server_init_kit& operator=(server_init_kit&& other);

        ~server_init_kit();
};