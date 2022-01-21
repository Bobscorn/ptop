#pragma once

#include <vector>
#include <memory>
#include <string>

#include "ip.h"
#include "message.h"
#include "protocol.h"

#if defined(WIN32) | defined(_WIN64)

#include <winsock2.h>
#include <ws2tcpip.h>

struct windows_name_data
{
	windows_name_data() = default;
	windows_name_data(sockaddr addr) : name(addr), name_len(sizeof(addr)) {}
	windows_name_data(sockaddr addr, socklen_t len) : name(addr), name_len(len) {}
	windows_name_data(sockaddr_in addr) : name(*(sockaddr*)&addr), name_len(sizeof(addr)) {}

	sockaddr name;
	socklen_t name_len;

	sockaddr_in& ipv4_addr() { return *(sockaddr_in*)&name; }

	inline bool operator==(const windows_name_data& other) const
	{
		if (name_len != other.name_len)
			return false;
		return !std::memcmp(&name, &other.name, name_len);
	}
	inline bool operator!=(const windows_name_data& other) const
	{
		return !(*this == other);
	}

	readable_ip_info as_readable() const;
};

typedef windows_name_data raw_name_data;
#elif __linux__

#include <netinet/in.h>

struct linux_name_data
{
	linux_name_data() { bzero(this, sizeof(linux_name_data)); }
	linux_name_data(sockaddr addr, socklen_t len) : name(addr), name_len(len) {}
	linux_name_data(sockaddr_in addr) : name(*(sockaddr*)&addr), name_len(sizeof(addr)) {}

	sockaddr name;
	socklen_t name_len;

	sockaddr_in& ipv4_addr() { return *(sockaddr_in*)&name; }

	inline bool operator==(const linux_name_data& other) const 
	{ 
		if (name_len != other.name_len)
			return false;
		return !std::memcmp(&name, &other.name, name_len);
	}
	inline bool operator!=(const linux_name_data& other) const
	{
		return !(*this == other);
	}

	readable_ip_info as_readable() const;
};

typedef linux_name_data raw_name_data;

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif // SOCKET_ERROR

#endif



enum class ConnectionStatus
{
	PENDING = 0,
	SUCCESS = 1,
	FAILED = 2,
};

class ISocketWrapper
{
	public:
	virtual ~ISocketWrapper() {}

	virtual void shutdown() = 0;

	virtual readable_ip_info get_peer_data() const = 0;

	virtual raw_name_data get_peername_raw() const = 0;
	virtual raw_name_data get_myname_raw() const = 0;
	virtual readable_ip_info get_peername_readable() const = 0;
	virtual readable_ip_info get_myname_readable() const = 0;

	virtual std::string get_my_ip() const = 0;
	virtual std::string get_my_port() const = 0;
	virtual std::string get_endpoint_ip() const = 0;
	virtual std::string get_endpoint_port() const = 0;

	virtual std::string get_identifier_str() const = 0;
};

class IDataSocketWrapper : virtual public ISocketWrapper
{
protected:
	size_t _seen_data = 0;
	size_t _sent_bytes = 0;
public:
	virtual ~IDataSocketWrapper() {}


	virtual Message receive_message() = 0;
	virtual bool has_message() = 0;

	virtual bool send_data(const Message& message) = 0;

	inline size_t bytes_seen() { return _seen_data; }
	inline size_t bytes_sent() { return _sent_bytes; }
};

class IListenSocketWrapper
{
	public:
	virtual ~IListenSocketWrapper() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual std::unique_ptr<IDataSocketWrapper> accept_connection() = 0;
};

class IReuseableSocketWrapper : virtual public ISocketWrapper
{
	protected:
	IReuseableSocketWrapper() {}

	public:
	virtual ~IReuseableSocketWrapper() {}
};

class INonBlockingConnector : public IReuseableSocketWrapper
{
	public:
	virtual ~INonBlockingConnector() {}

	virtual void connect(std::string ip_address, std::string port) = 0;
	virtual ConnectionStatus has_connected() = 0;
};

class INonBlockingListener : public IReuseableSocketWrapper
{
	public:
	virtual ~INonBlockingListener() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual std::unique_ptr<IDataSocketWrapper> accept_connection() = 0;
};

class Sockets
{
	public:
	static const std::string ServerListenPort;
	static const std::string ClientListenPort;

	static std::unique_ptr<IListenSocketWrapper> CreateListenSocket(std::string port, protocol proto);
	static std::unique_ptr<IDataSocketWrapper> CreateConnectionSocket(std::string peer_ip, std::string port, protocol proto);
	static std::unique_ptr<INonBlockingListener> CreateReusableNonBlockingListenSocket(raw_name_data data, protocol proto);
	static std::unique_ptr<INonBlockingConnector> CreateReusableConnectSocket(raw_name_data name, std::string ip_address, std::string port, protocol proto);
	static std::unique_ptr<IDataSocketWrapper> ConvertToDataSocket(std::unique_ptr<INonBlockingConnector>&& old);
};
