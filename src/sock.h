#pragma once

#ifdef WIN32
#include <WinSock2.h>

typedef SOCKET epic_sock_type_t;
constexpr epic_sock_type_t Invalid_Socket = INVALID_SOCKET;
#elif defined(__linux__)
#include <sys/types.h>

typedef int epic_sock_type_t;
constexpr epic_sock_type_t Invalid_Socket = -1;
#endif

#include <string>

#include "socket.h"

void throw_if_socket_error(int n, std::string message);
//void throw_if_non_block_error(int n, std::string message);

enum select_for
{
    READ,
    WRITE,
    EXCEPT
};

struct epic_socket
{
    epic_socket() : handle(Invalid_Socket) {}
    explicit epic_socket(epic_sock_type_t handle) : handle(handle) {}
    epic_socket(int family, int type, int protocol);
    epic_socket(epic_socket&& other) : handle(other.handle) { other.handle = Invalid_Socket; }
    ~epic_socket();

    template<class OptT>
    epic_socket& set_socket_option(int option_name, OptT optionVal, std::string error_message)
    {
        int result = setsockopt(handle, SOL_SOCKET, option_name, &optionVal, sizeof(OptT));
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

    epic_socket& connect(sockaddr* addr, socklen_t len);
    bool try_connect(sockaddr* addr, socklen_t len);

    bool poll_for(int poll_flag) const;
    bool select_for(select_for s_for) const;

    bool has_message() const;

    inline bool is_invalid() const { return handle == Invalid_Socket; }
    inline bool is_valid() const { return handle != Invalid_Socket; }


    epic_sock_type_t handle;
};