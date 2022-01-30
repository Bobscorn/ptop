#include "protocol.h"
#include "error.h"
#include "ptop_socket.h"
#include "socket.h"
#include "platform.h"

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

bool protocol::send_bytes(SOCKET handle, raw_name_data endpoint, std::vector<char> bytes) {
    if (is_tcp())
	{
		int result = send(handle, bytes.data(), (int)bytes.size(), 0);
		if (result == SOCKET_ERROR)
			return false;
		return true;
	}
	else if (is_udp())
	{
		int result = sendto(handle, bytes.data(), (int)bytes.size(), 0, &endpoint.name, endpoint.name_len);
		if (result == SOCKET_ERROR)
			return false;
		return true;
	}
    return false;
}

std::vector<char> protocol::receive_bytes(SOCKET handle, raw_name_data expected_endpoint)
{
    if (is_tcp())
	{
		std::vector<char> data(500, (char)0, std::allocator<char>());
		int result = ::recv(handle, data.data(), (int)data.size(), 0);
		if (result == SOCKET_ERROR)
		{
			std::cout << "Receiving data failed" << std::endl;
			return std::vector<char>();
		}
		data.resize(result);
		return data;
	}
	if (is_udp())
	{
		sockaddr addr;
		socklen_t addr_len;
		std::vector<char> data(500, (char)0, std::allocator<char>());
		int result = ::recvfrom(handle, data.data(), (int)data.size(), 0, &addr, &addr_len);
		raw_name_data incoming{ addr, addr_len };
		
		if (incoming != expected_endpoint)
		{
			auto readable = convert_to_readable(incoming);
			auto message = "Receiving UDP data from an undesired endpoint (" + readable.ip_address + ":" + readable.port + ")";
			throw_new_exception(message, LINE_CONTEXT);
		}
		if (result == SOCKET_ERROR)
		{
			auto message = "Receiving (UDP) data failed: " + socket_error_to_string(result);
			throw_new_exception(message, LINE_CONTEXT);
		}
		data.resize(result);
		return data;
	}
	throw_new_exception("Invalid protocol", LINE_CONTEXT);
}