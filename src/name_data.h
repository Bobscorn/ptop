#pragma once

#include <string>

#include "ip.h"

#if defined(WIN32) | defined(_WIN64)

#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__linux__)
#include <netinet/in.h>

struct raw_name_data;
extern readable_ip_info convert_to_readable(const raw_name_data& data);
struct raw_name_data
{
	raw_name_data() = default;
	raw_name_data(sockaddr addr) : name(addr), name_len(sizeof(addr)) {}
	raw_name_data(sockaddr addr, socklen_t len) : name(addr), name_len(len) {}
	raw_name_data(sockaddr_in addr) : name(*(sockaddr*)&addr), name_len(sizeof(addr)) {}

	sockaddr name;
	socklen_t name_len;

	sockaddr_in& ipv4_addr() { return *(sockaddr_in*)&name; }

	inline bool operator==(const raw_name_data& other) const
	{
		if (name_len != other.name_len)
			return false;
		return !std::memcmp(&name, &other.name, name_len);
	}
	inline bool operator!=(const raw_name_data& other) const
	{
		return !(*this == other);
	}

	inline readable_ip_info as_readable() const { return convert_to_readable(*this); }
};
#endif