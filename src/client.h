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
    std::chrono::system_clock::time_point last_send;
    int auth_key;
    EXECUTION_STATUS status;
    ::protocol protocol;
    bool is_leader;

    std::unique_ptr<IDataSocketWrapper>& get_server_socket();
    void set_server_socket(std::unique_ptr<IDataSocketWrapper>&& input);

    protected:
    std::unique_ptr<IDataSocketWrapper> _server_socket;
};

class client_auth_kit {
    public:
    client_auth_kit(client_init_kit& init_kit, const char* data, int i, MESSAGE_LENGTH_T data_len);
    std::vector<std::unique_ptr<IDataSocketWrapper>> unauthed_sockets;
    std::unique_ptr<ReusableListener> listen_sock;
    int auth_key_out;
    std::unique_ptr<ReusableConnector> public_connector;
    std::unique_ptr<ReusableConnector> private_connector;
    readable_ip_info peer_public;
    readable_ip_info peer_private;
    raw_name_data old_privatename;
};
