#pragma once

#include "socket.h"
#include <string>
#include "name_data.h"

class Protocol {
public:
    Protocol(std::string possible_protocol);

private:
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    int ai_flags;

public:
    inline int get_ai_family() const { return ai_family; }
    inline int get_ai_socktype() const { return ai_socktype; }
    inline int get_ai_protocol() const { return ai_protocol; }
    inline int get_ai_flags() const { return ai_flags; }
    
    bool is_tcp() const;
    bool is_udp() const;

    bool send_bytes(SOCKET handle, raw_name_data endpoint, std::vector<char> bytes);
    std::vector<char> receive_bytes(SOCKET handle, raw_name_data& expected_endpoint);
    bool has_died(SOCKET handle, bool has_message);
};