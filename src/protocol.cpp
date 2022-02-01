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

Protocol::Protocol(string possible_protocol) {
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

bool Protocol::is_tcp() const {
    return ai_protocol == IPPROTO_TCP;
}

bool Protocol::is_udp() const { 
    return ai_protocol == IPPROTO_UDP; 
}

bool Protocol::send_bytes(SOCKET handle, raw_name_data endpoint, std::vector<char> bytes) {
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

std::vector<char> Protocol::receive_bytes(SOCKET handle, raw_name_data& expected_endpoint)
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
		if (expected_endpoint.initialized == false){
			expected_endpoint.name_len = sizeof(raw_name_data);
		}
		sockaddr addr;
		socklen_t addr_len = sizeof(sockaddr_in);
		std::vector<char> data(500, (char)0, std::allocator<char>());
		int result = ::recvfrom(handle, data.data(), (int)data.size(), 0, &expected_endpoint.name, &expected_endpoint.name_len);
		throw_if_socket_error(result, "Failed to receive UDP bytes with: " + get_last_error(), LINE_CONTEXT);

		raw_name_data incoming{ addr, addr_len };
		if (incoming != expected_endpoint && expected_endpoint.initialized == false)
		{
			auto readable = convert_to_readable(incoming);
			auto message = "Receiving UDP data from an undesired endpoint (" + readable.ip_address + ":" + readable.port + ")";
			throw_new_exception(message, LINE_CONTEXT);
		}
		if (result == SOCKET_ERROR)
		{
			auto message = "Receiving (UDP) data failed: " + get_last_error();
			throw_new_exception(message, LINE_CONTEXT);
		}
		expected_endpoint.initialized = true;
		data.resize(result);
		return data;
	}
	throw_new_exception("Invalid protocol", LINE_CONTEXT);
}

bool Protocol::has_died(SOCKET handle, bool has_message) {
	if (is_tcp())
	{
		if (has_message)
		{
			std::vector<char> recv_data{ 100, '0', std::allocator<char>() };
			int n = recv(handle, recv_data.data(), (int)recv_data.size(), MSG_PEEK);
			if (n == SOCKET_ERROR)
			{
				std::cerr << "[Data] Failed to peek data from linux socket (trying to determine if closed): " << get_last_error() << std::endl;
				return true;
			}
			return n == 0;
		}
		return false;
	}
	if (is_udp())
		return false;
	throw_new_exception("Invalid protocol", LINE_CONTEXT);
	return true;
}
