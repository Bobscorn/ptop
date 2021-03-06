#pragma once 

#include "loop.h"
#include "ptop_socket.h"
#include "platform.h"
#include "error.h"

#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <functional>



class server_init_kit;

void server_loop();
void process_server_protocol(server_init_kit& input_proto);

class server_init_kit {
    public:
        std::unique_ptr<IDataSocketWrapper> clientA;
        std::unique_ptr<IDataSocketWrapper> clientB;

        std::unique_ptr<readable_ip_info> privA;
        std::unique_ptr<readable_ip_info> privB;

        IDataSocketWrapper* cA;
        IDataSocketWrapper* cB;

        std::unique_ptr<IListenSocketWrapper> server_socket;

        std::vector<char> recv_data;

        EXECUTION_STATUS status;
        Protocol proto;

        server_init_kit(Protocol proto);
        server_init_kit(server_init_kit&& other);

        server_init_kit& operator=(server_init_kit&& other);

        ~server_init_kit();
};