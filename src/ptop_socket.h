#pragma once

#include "socket.h"
#include "name_data.h"
#include "protocol.h"
#include "error.h"
#include "message.h"

#include <string>

constexpr SOCKET REALLY_INVALID_SOCKET = -1;
constexpr int READ_BYTE_BUFFER = 2 * 64 * KILOBYTE;

void throw_if_socket_error(int n, std::string message, std::string line_context);
std::string socket_error_to_string(int err);
std::string get_last_error();

enum class select_for
{
    READ,
    WRITE,
    EXCEPT
};

// UDP CRAP

struct udp_bytes
{
    std::vector<char> bytes;
    raw_name_data endpoint;
};

// END UDP CRAP

class PtopSocket
{
    private:
    SOCKET _handle;
    Protocol _protocol;
    raw_name_data _endpoint;
    std::string _name;
    PtopSocket(SOCKET handle, Protocol proto, std::string name = "") : _handle(handle), _protocol(proto), _endpoint(), _name(name) {}
    PtopSocket(SOCKET handle, Protocol proto, raw_name_data endpoint, std::string name = "") : _handle(handle), _protocol(proto), _endpoint(endpoint), _name(name) {}

    public:

    explicit PtopSocket(Protocol proto, std::string name = "");

    PtopSocket(PtopSocket&& other) : _handle(other._handle), _protocol(other._protocol), _endpoint(other._endpoint), _name(std::move(other._name)) { 
        other._handle = REALLY_INVALID_SOCKET;
    };
    ~PtopSocket();

    inline void set_name(std::string name)
    {
        _name = std::move(name);
    }

    inline const std::string& get_name() const
    {
        return _name;
    }

    template<class OptT>
    PtopSocket& set_socket_option(int option_name, OptT optionVal, std::string error_message)
    {
        int result = setsockopt(_handle, SOL_SOCKET, option_name, (char*)&optionVal, sizeof(OptT));
        throw_if_socket_error(result, error_message, LINE_CONTEXT);
        return *this;
    }

    template<class OptT>
    PtopSocket& set_socket_option(int option_name, OptT optionVal)
    {
        return set_socket_option<OptT>(option_name, optionVal, "Failed to set socket option: " + std::to_string(option_name));
    }

    template<class OptT>
    OptT get_socket_option(int option_name) const
    {
        OptT opt;
        socklen_t optSize = sizeof(OptT);
        int result = getsockopt(_handle, SOL_SOCKET, option_name, (char*)&opt, &optSize);
        throw_if_socket_error(result, "Failed to get socket option", LINE_CONTEXT);
        return opt;
    }
    
#ifdef SO_REUSEPORT
    inline PtopSocket& set_socket_reuse() { set_socket_option(SO_REUSEPORT, (int)1, "Failed to set socket (port) reusability"); return set_socket_option(SO_REUSEADDR, (int)1, "Failed to set socket reusability"); }
    inline PtopSocket& set_socket_no_reuse() { set_socket_option(SO_REUSEPORT, (int)0, "Failed to set socket (port) un-reusability"); return set_socket_option(SO_REUSEADDR, (int)0, "Failed to set socket un-reusability"); }
#else
    inline PtopSocket& set_socket_reuse() { return set_socket_option(SO_REUSEADDR, (int)1, "Failed to set socket reusability"); }
    inline PtopSocket& set_socket_no_reuse() { return set_socket_option(SO_REUSEADDR, (int)0, "Failed to set socket un-reusability"); }
#endif

    PtopSocket& set_non_blocking(bool value);

    PtopSocket& bind_socket(const raw_name_data& name, std::string error_mess = "Failed to bind");
    PtopSocket& start_listening();

    PtopSocket accept_data_socket();

    PtopSocket& connect(sockaddr* addr, socklen_t len);
    bool try_connect(sockaddr* addr, socklen_t len);

    void listen(int max_conns);

    bool has_connection() const;

    bool poll_for(int poll_flag) const;
    bool select_for(select_for s_for) const;

    bool has_message() const;
    bool has_died();

    raw_name_data get_peer_raw() const;
    raw_name_data get_name_raw() const;

    inline bool is_invalid() const { return _handle == REALLY_INVALID_SOCKET; }
    inline bool is_valid() const { return _handle != REALLY_INVALID_SOCKET; }
    inline bool is_tcp() const { return _protocol.is_tcp(); }
    inline bool is_udp() const { return _protocol.is_udp(); }
    inline bool is_listen() const { return get_socket_option<int>(SO_ACCEPTCONN); }

    inline SOCKET get_handle() const { return _handle; }
    inline const Protocol& get_protocol() const { return _protocol; }

    bool send_bytes(std::vector<char> bytes);
    std::vector<char> receive_bytes();

    bool send_udp_bytes(udp_bytes bytes);
    udp_bytes receive_udp_bytes();
};