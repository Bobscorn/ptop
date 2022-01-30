#include "platform.h"
#include "error.h"

#if defined(__linux__)
#include <arpa/inet.h>
#endif

#include <string>

std::string Platform::get_identifier_str() {
	std::string name_str = "Unnamed";
	if (_socket.get_name().size())
		name_str = _socket.get_name();
	if (_socket.is_tcp() && _socket.is_listen())
		return std::string("(") + name_str + " is a listen on: " + _address + ":" + _port + ")";

	if (_endpoint_assigned == false)
		try_update_endpoint_info();

	if (_endpoint_assigned == false)
        return std::string("(") + name_str + " priv: " + _address + ":" + _port + ", pub : N / A)";
    
    return std::string("(") + name_str + " pub: " + _address + ":" + _port + ")"; 
}

readable_ip_info convert_to_readable(raw_name_data data)
{
	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &data.ipv4_addr().sin_addr, buf.data(), buf.size());

	if (!str) {
		throw_new_exception("Failed to convert sockaddr to string: " + get_last_error(), LINE_CONTEXT);
	}

	std::string address = str;

	std::string port = std::to_string(ntohs(data.ipv4_addr().sin_port));
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

Platform::~Platform()
{
	if (_socket.is_valid())
		std::cout << "Closing socket: " << get_identifier_str() << std::endl;
	else
		std::cout << "Closing Dead socket" << std::endl;
}
