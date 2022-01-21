#include "platform.h"
#include <string>

std::string Platform::get_identifier_str() const { 
    if (_endpoint_assigned == false) 
        return std::string("(priv: ") + _address + ":" + _port + ", pub: N/A)";
    
    return std::string("(pub: ") + _address + ":" + _port + ")"; 
}

Platform::~Platform()
{
	std::cout << (_socket.is_valid() ? "Closing socket: " : "Closing dead socket that had: ") << _endpoint_address << ":" << _endpoint_port << std::endl;
}
