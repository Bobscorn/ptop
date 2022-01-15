#pragma once

#include <string>
#include <vector>
#include <iostream>

std::string get_external_ip();

struct readable_ip_info
{
	std::string ip_address;
	std::string port;

	std::vector<char> to_bytes() const;
};

inline std::ostream& operator<<(std::ostream& os, const readable_ip_info& ip_info)
{
	os << ip_info.ip_address << ":" << ip_info.port;
	return os;
}

readable_ip_info read_peer_data(const char* data, int& index, size_t data_len);