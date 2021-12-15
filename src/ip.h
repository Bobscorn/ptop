#pragma once

#include <string>
#include <vector>

std::string get_external_ip();

struct peer_data
{
	std::string ip_address;
	std::string port;

	std::vector<char> to_bytes();
};

peer_data read_peer_data(char* data, int& index, int data_len);