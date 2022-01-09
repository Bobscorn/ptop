#pragma once

#ifdef WIN32
#include <WinSock2.h>

#elif defined(__linux__)
#include <sys/types.h>


using SOCKET = int; 

constexpr SOCKET REALLY_INVALID_SOCKET = -1;
#endif

#include <string>

#include "socket.h"
#include "protocol.h"

void throw_if_socket_error(int n, std::string message);
//void throw_if_non_block_error(int n, std::string message);

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
    epic_socket(SOCKET handle, protocol proto) : _handle(handle), _protocol(proto) {}

    public:

    explicit epic_socket(protocol proto) : _protocol(proto) {

    };

    epic_socket(epic_socket&& other) : _handle(other._handle), _protocol(other._protocol) { 
        other._handle = REALLY_INVALID_SOCKET;
    };
    ~epic_socket();

    template<class OptT>
    epic_socket& set_socket_option(int option_name, OptT optionVal, std::string error_message)
    {
        int result = setsockopt(_handle, SOL_SOCKET, option_name, &optionVal, sizeof(OptT));
        throw_if_socket_error(result, error_message);
        return *this;
    }

    template<class OptT>
    epic_socket& set_socket_option(int option_name, OptT optionVal)
    {
        return set_socket_option<OptT>(option_name, optionVal, "Failed to set socket option: " + std::to_string(option_name));
    }
    
#ifdef __linux__
    inline epic_socket& set_socket_reuse() { set_socket_option(SO_REUSEPORT, (int)1); return set_socket_option(SO_REUSEADDR, (int)1); }
    inline epic_socket& set_socket_no_reuse() { set_socket_option(SO_REUSEPORT, (int)0); return set_socket_option(SO_REUSEADDR, (int)0); }
#elif defined(WIN32)
    inline epic_socket& set_socket_reuse() { return set_socket_option(SO_REUSEADDR, (int)1); }
    inline epic_socket& set_socket_no_reuse() { return set_socket_option(SO_REUSEADDR, (int)0); }
#endif

    epic_socket& set_non_blocking(bool value);

    epic_socket& bind_socket(const raw_name_data& name, std::string error_mess = "Failed to bind");
    epic_socket& start_listening();

    epic_socket&& accept_data_socket();

    epic_socket& connect(sockaddr* addr, socklen_t len);
    bool try_connect(sockaddr* addr, socklen_t len);

    bool poll_for(int poll_flag) const;
    bool select_for(select_for s_for) const;

    bool has_message() const;

    std::vector<char> recv();

    raw_name_data get_peer_raw() const;
    raw_name_data get_name_raw() const;

    inline bool is_invalid() const { return _handle == REALLY_INVALID_SOCKET; }
    inline bool is_valid() const { return _handle != REALLY_INVALID_SOCKET; }

    inline SOCKET get_handle() const { return _handle; }
};