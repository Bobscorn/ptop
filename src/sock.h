#pragma once

#ifdef WIN32
#include <WinSock2.h>

#elif defined(__linux__)
#include <sys/types.h>
using SOCKET = int;
#endif

constexpr SOCKET REALLY_INVALID_SOCKET = -1;

#include <string>

#include "socket.h"
#include "protocol.h"

void throw_if_socket_error(int n, std::string message);
//void throw_if_non_block_error(int n, std::string message);
std::string socket_error_to_string(int err);
std::string get_last_error();

enum select_for
{
    READ,
    WRITE,
    EXCEPT
};

class epic_socket
{
    private:
    SOCKET _handle;
    protocol _protocol;
    raw_name_data _endpoint;
    epic_socket(SOCKET handle, protocol proto) : _handle(handle), _protocol(proto), _endpoint() {}
    epic_socket(SOCKET handle, protocol proto, raw_name_data endpoint) : _handle(handle), _protocol(proto), _endpoint(endpoint) {}

    public:

    explicit epic_socket(protocol proto);

    epic_socket(epic_socket&& other) : _handle(other._handle), _protocol(other._protocol) { 
        other._handle = REALLY_INVALID_SOCKET;
    };
    ~epic_socket();

    template<class OptT>
    epic_socket& set_socket_option(int option_name, OptT optionVal, std::string error_message)
    {
        int result = setsockopt(_handle, SOL_SOCKET, option_name, (char*)&optionVal, sizeof(OptT));
        throw_if_socket_error(result, error_message);
        return *this;
    }

    template<class OptT>
    epic_socket& set_socket_option(int option_name, OptT optionVal)
    {
        return set_socket_option<OptT>(option_name, optionVal, "Failed to set socket option: " + std::to_string(option_name));
    }

    template<class OptT>
    OptT get_socket_option(int option_name)
    {
        OptT opt;
        socklen_t optSize = sizeof(OptT);
        int result = getsockopt(_handle, SOL_SOCKET, option_name, (char*)&opt, &optSize);
        throw_if_socket_error(result, "Failed to get socket option");
        return opt;
    }
    
#ifdef __linux__
    inline epic_socket& set_socket_reuse() { set_socket_option(SO_REUSEPORT, (int)1, "Failed to set socket (port) reusability"); return set_socket_option(SO_REUSEADDR, (int)1, "Failed to set socket reusability"); }
    inline epic_socket& set_socket_no_reuse() { set_socket_option(SO_REUSEPORT, (int)0, "Failed to set socket (port) un-reusability"); return set_socket_option(SO_REUSEADDR, (int)0, "Failed to set socket un-reusability"); }
#elif defined(WIN32)
    inline epic_socket& set_socket_reuse() { return set_socket_option(SO_REUSEADDR, (int)1, "Failed to set socket reusability"); }
    inline epic_socket& set_socket_no_reuse() { return set_socket_option(SO_REUSEADDR, (int)0, "Failed to set socket un-reusability"); }
#endif

    epic_socket& set_non_blocking(bool value);

    epic_socket& bind_socket(const raw_name_data& name, std::string error_mess = "Failed to bind");
    epic_socket& start_listening();

    epic_socket&& accept_data_socket();

    epic_socket& connect(sockaddr* addr, socklen_t len);
    bool try_connect(sockaddr* addr, socklen_t len);

    void listen(int max_conns);

    bool has_connection() const;

    bool poll_for(int poll_flag) const;
    bool select_for(select_for s_for) const;

    bool has_message() const;
    bool has_died() const;

    raw_name_data get_peer_raw() const;
    raw_name_data get_name_raw() const;

    inline bool is_invalid() const { return _handle == REALLY_INVALID_SOCKET; }
    inline bool is_valid() const { return _handle != REALLY_INVALID_SOCKET; }
    inline bool is_tcp() const { return _protocol.is_tcp(); }
    inline bool is_udp() const { return _protocol.is_udp(); }

    inline SOCKET get_handle() const { return _handle; }
    inline const protocol& get_protocol() const { return _protocol; }

    bool send_bytes(std::vector<char> bytes);
    std::vector<char> recv_bytes();
};