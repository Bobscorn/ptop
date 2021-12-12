#pragma once

#include <vector>
#include <memory>

using namespace std;

enum class MESSAGE_TYPE
{
	NONE = 0,
	PEER_DATA,
	MSG,
	FILE,
	SET_NAME,
	CONNECT_PEER,
	HELLO,
};

template<class T, typename = std::enable_if_t<std::is_pod_v<T>>>
vector<char> create_message(MESSAGE_TYPE type, T other_data)
{
	vector<char> out(sizeof(type) + sizeof(other_data), '0');
	std::memcpy(out.data(), &type, sizeof(type));
	std::memcpy(out.data() + sizeof(type), &other_data, sizeof(other_data));
	return out;
}

inline vector<char> create_message(MESSAGE_TYPE type, vector<char> data)
{
	data.insert(data.begin(), sizeof(type), '0');
	memcpy(data.data(), &type, sizeof(type));
	return data;
}