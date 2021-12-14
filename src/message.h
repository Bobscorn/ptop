#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstring>

using namespace std;

enum class MESSAGE_TYPE
{
	NONE = 0,
	PEER_DATA,
	MSG,
	FILE,
	SET_NAME,
	CONNECT_PEER,
	READY_FOR_P2P,
};

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
vector<char> create_message(MESSAGE_TYPE type, T other_data)
{
	vector<char> out(sizeof(type) + sizeof(other_data), '0');
	std::memcpy(out.data(), &type, sizeof(type));
	std::memcpy(out.data() + sizeof(type), &other_data, sizeof(other_data));
	return out;
}

inline vector<char> create_message(MESSAGE_TYPE type)
{
	vector<char> out(sizeof(type), '0');
	memcpy(out.data(), &type, sizeof(type));
	return out;
}

inline vector<char> create_message(MESSAGE_TYPE type, vector<char> data)
{
	data.insert(data.begin(), sizeof(type), '0');
	memcpy(data.data(), &type, sizeof(type));
	return data;
}

inline vector<char> create_message(MESSAGE_TYPE type, string data)
{
	std::vector<char> out_data(sizeof(type) + sizeof(int), '0');
	int len = data.length();
	memcpy(out_data.data(), &type, sizeof(type));
	memcpy(out_data.data() + sizeof(type), &len, sizeof(int));
	out_data.reserve(sizeof(type) + sizeof(size_t) + data.length());
	out_data.insert(out_data.end(), data.begin(), data.end());
	return out_data;
}