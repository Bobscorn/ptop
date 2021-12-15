#pragma once

#include <string>
#include <vector>

std::string get_external_ip();

struct readable_ip_info
{
	std::string ip_address;
	std::string port;

	std::vector<char> to_bytes();
};

readable_ip_info read_peer_data(char* data, int& index, int data_len);