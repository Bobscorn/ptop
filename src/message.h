#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstring>

enum class MESSAGE_TYPE
{
	NONE = 0,
	MSG,
	FILE,
	SET_NAME,
	CONNECT_PEER,
	READY_FOR_P2P,
};

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
std::vector<char> create_message(MESSAGE_TYPE type, T other_data)
{
	std::vector<char> out(sizeof(type) + sizeof(other_data), '0');
	std::memcpy(out.data(), &type, sizeof(type));
	std::memcpy(out.data() + sizeof(type), &other_data, sizeof(other_data));
	return out;
}

inline std::vector<char> create_message(MESSAGE_TYPE type)
{
	std::vector<char> out(sizeof(type), '0');
	std::memcpy(out.data(), &type, sizeof(type));
	return out;
}

inline std::vector<char> create_message(MESSAGE_TYPE type, std::vector<char> data)
{
	data.insert(data.begin(), sizeof(type), '0');
	std::memcpy(data.data(), &type, sizeof(type));
	return data;
}

inline std::vector<char> create_message(MESSAGE_TYPE type, std::string data)
{
	std::vector<char> out_data(sizeof(type) + sizeof(int), '0');
	int len = data.length();
	std::memcpy(out_data.data(), &type, sizeof(type));
	std::memcpy(out_data.data() + sizeof(type), &len, sizeof(int));
	out_data.reserve(sizeof(type) + sizeof(size_t) + data.length());
	out_data.insert(out_data.end(), data.begin(), data.end());
	return out_data;
}