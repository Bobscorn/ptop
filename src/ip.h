#pragma once

#include <string>

using namespace std;

string get_external_ip();

enum class MESSAGE_TYPE
{
	NONE = 0,
	PEER_DATA,
	MSG,
	FILE,
	SET_NAME,
	CONNECT_PEER,
};

struct peer_data
{
	int ip_address;
	int port;
};

peer_data read_peer_data(char* data, int& index, int data_len);