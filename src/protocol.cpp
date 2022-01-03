#include "protocol.h"

#ifdef WIN32
#include <winsock2.h>
#elif __linux__
#include <sys/types.h>
#endif
#include <iostream>
#include <algorithm>

using namespace std;


protocol::protocol(string possible_protocol) {
    auto lowered = transform(possible_protocol.begin(), possible_protocol.end(), possible_protocol.begin(), ::tolower);

    if(lowered == "tcp") {
        ai_family = AF_INET;
        ai_sockettype = SOCK_STREAM;
        ai_protocol = IPPROTO_TCP;
        ai_flags = AI_PASSIVE;
    }

    elif(lowered == "udp") {
        ai_family = AF_INET;
        ai_sockettype = SOCK_DGRAM;
        ai_protocol = IPPROTO_UDP;
        ai_flags = AI_PASSIVE;
    }

    else {
        throw new std::Exception("Error: possible_protocol '" + lowered + "' is not valid.");
    }
}

bool protocol::is_tcp() const {
    return ai_protocol == IPPROTO_TCP;
}

bool protocol::is_udp() const { 
    return ai_protocol == IPPROTO_UDP; 
}