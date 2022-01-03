#pragma once

#include <string>

class protocol {
    protocol(string possible_protocol);

    private:
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    int ai_flags;

    public:
    inline int get_ai_family() const { return ai_family; }
    inline int get_ai_socktype() const { return ai_sockettype; }
    inline int get_ai_protocol() const { return ai_protocol; }
    inline int get_ai_flags() const { return ai_flags; }

    bool is_tcp() const;
    bool is_udp() const;
}