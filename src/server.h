#pragma once 

#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <functional>

#include "loop.h"
#include "socket.h"


void server_loop();

class server_init_kit {
    public:
        std::unique_ptr<IDataSocket> clientA;
        std::unique_ptr<IDataSocket> clientB;

        IDataSocket* cA;
        IDataSocket* cB;

        std::unique_ptr<IListenSocket> server_socket;

        std::vector<char> recv_data;

        thread_queue message_queue;

        std::thread input_thread;

        std::unique_lock<std::shared_mutex> take_message_lock;

        EXECUTION_STATUS status;

        server_init_kit(std::function<void(thread_queue&)> thread_func);
        server_init_kit(server_init_kit&& other);

        ~server_init_kit();

        server_init_kit& operator=(server_init_kit&& other);
};