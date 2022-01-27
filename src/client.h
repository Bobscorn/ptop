#pragma once

#include <string>
#include <chrono>
#include <memory>

#include "loop.h"
#include "protocol.h"
#include "interfaces.h"
#include "platform.h"

void client_loop(std::string server_address_pair, protocol input_protocol);

class client_init_kit {
    public:
    client_init_kit(std::string server_address_pair, ::protocol input_protocol);
    std::chrono::system_clock::time_point server_last_send;
    EXECUTION_STATUS status;
    ::protocol protocol;

    std::unique_ptr<IDataSocketWrapper>& get_server_socket();
    void set_server_socket(std::unique_ptr<IDataSocketWrapper>&& input);

    protected:
    std::unique_ptr<IDataSocketWrapper> _server_socket;
};

class client_peer_kit {
    public:
    client_peer_kit();
    void set_peer_data(client_init_kit& init_kit, const char* data, int message_data_index, MESSAGE_LENGTH_T data_len);

    std::unique_ptr<NonBlockingConnector> public_connector;
    std::unique_ptr<NonBlockingConnector> private_connector;
    std::unique_ptr<NonBlockListener> listen_sock;
    readable_ip_info public_info;
    readable_ip_info private_info;
    raw_name_data old_privatename;

    std::chrono::system_clock::time_point peer_connect_start_time;
    std::unique_ptr<IDataSocketWrapper> peer_socket;
};
