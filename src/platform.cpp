#include "platform.h"
#include "error.h"

#if defined(__linux__)
#include <arpa/inet.h>
#endif

#include <string>

std::string Platform::get_identifier_str() const { 
    if (_endpoint_assigned == false) 
        return std::string("(priv: ") + _address + ":" + _port + ", pub: N/A)";
    
    return std::string("(pub: ") + _address + ":" + _port + ")"; 
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
	std::cout << (_socket.is_valid() ? "Closing socket: " : "Closing dead socket that had: ") << _endpoint_address << ":" << _endpoint_port << std::endl;
}
