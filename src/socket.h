#pragma once

#include <vector>
#include <memory>
#include <string>

#include "ip.h"

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

struct windows_name_data
{
	windows_name_data() = default;
	windows_name_data(sockaddr addr) : name(addr), name_len(sizeof(addr)) {}
	windows_name_data(sockaddr addr, socklen_t len) : name(addr), name_len(len) {}

	sockaddr name;
	int name_len;

	sockaddr_in& ipv4_addr() { return *(sockaddr_in*)&name; }
};

typedef windows_name_data raw_name_data;
#elif defined(__linux__)

#include <netinet/in.h>

struct linux_name_data
{
	linux_name_data() = default;
	linux_name_data(sockaddr addr, socklen_t len) : name(addr), name_len(len) {}

	sockaddr name;
	socklen_t name_len;

	sockaddr_in& ipv4_addr() { return *(sockaddr_in*)&name; }
};

typedef linux_name_data raw_name_data;
#endif

enum class ConnectionStatus
{
	PENDING = 0,
	SUCCESS = 1,
	FAILED = 2,
};

class ISocket
{
	public:
	virtual ~ISocket() {}

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
};

class IDataSocket : virtual public ISocket
{
protected:
	size_t _seen_data = 0;
	size_t _sent_bytes = 0;
public:
	virtual ~IDataSocket() {}


	virtual std::vector<char> receive_data() = 0;
	virtual bool has_data() = 0;

	virtual bool send_data(const std::vector<char>& data) = 0;

	inline size_t bytes_seen() { return _seen_data; }
	inline size_t bytes_sent() { return _sent_bytes; }
};

class IListenSocket
{
	public:
	virtual ~IListenSocket() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual std::unique_ptr<IDataSocket> accept_connection() = 0;
};

class IReusableSocket : virtual public ISocket
{
	protected:
	IReusableSocket() {}

	public:
	virtual ~IReusableSocket() {}
};

class IReusableNonBlockingConnectSocket : public IReusableSocket
{
	public:
	virtual ~IReusableNonBlockingConnectSocket() {}

	virtual void connect(std::string ip_address, std::string port) = 0;
	virtual ConnectionStatus has_connected() = 0;
};

class IReusableNonBlockingListenSocket : public IReusableSocket
{
	public:
	virtual ~IReusableNonBlockingListenSocket() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual std::unique_ptr<IDataSocket> accept_connection() = 0;
};

class Sockets
{
	public:
	static const std::string ServerListenPort;
	static const std::string ClientListenPort;

	static std::unique_ptr<IListenSocket> CreateListenSocket(std::string port);
	static std::unique_ptr<IDataSocket> CreateConnectionSocket(std::string peer_ip, std::string port);
	static std::unique_ptr<IReusableNonBlockingListenSocket> CreateReusableNonBlockingListenSocket(std::string port);
	static std::unique_ptr<IReusableNonBlockingConnectSocket> CreateReusableConnectSocket(raw_name_data name);
	static std::unique_ptr<IDataSocket> ConvertToDataSocket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old);
};

void log_msg(const std::vector<char>& data, bool sending, ISocket& sock);