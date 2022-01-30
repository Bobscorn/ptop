#include "protocol.h"
#include "error.h"
#include "ptop_socket.h"
#include "socket.h"

#if defined(WIN32) | defined(_WIN64)
#include <winsock2.h>
#elif __linux__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif
#include <iostream>
#include <algorithm>
#include <stdexcept>

using namespace std;

protocol::protocol(string possible_protocol) {
    transform(possible_protocol.begin(), possible_protocol.end(), possible_protocol.begin(), ::tolower);

    if (possible_protocol == "tcp") {
        ai_family = AF_INET;
        ai_socktype = SOCK_STREAM;
        ai_protocol = IPPROTO_TCP;
    }

    else if (possible_protocol == "udp") {
        ai_family = AF_INET;
        ai_socktype = SOCK_DGRAM;
        ai_protocol = IPPROTO_UDP;
    }

    else {
        throw std::runtime_error(string("Error: possible_protocol '") + possible_protocol + "' is not valid. (not 'tcp' or 'udp')");
    }
}

bool protocol::is_tcp() const {
    return ai_protocol == IPPROTO_TCP;
}

bool protocol::is_udp() const { 
    return ai_protocol == IPPROTO_UDP; 
}