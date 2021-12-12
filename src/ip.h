#pragma once

#include <string>
#include <vector>

using namespace std;

string get_external_ip();

struct peer_data
{
	string ip_address;
	string port;

	vector<char> to_bytes();
};

peer_data read_peer_data(char* data, int& index, int data_len);