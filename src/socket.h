#pragma once

#include <vector>
#include <memory>
#include <string>

#include "ip.h"

using namespace std;

#ifdef WIN32

#include <winsock2.h>

struct windows_name_data
{
	sockaddr name;
	int name_len;
};

typedef windows_name_data name_data;
#elif defined(__linux__)

struct linux_name_data
{
	pee pee poo poo
};

typedef linux_name_data name_data;
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

	virtual peer_data get_peer_data() = 0;
	virtual name_data get_sock_data() = 0;
};

class IDataSocket : virtual public ISocket
{
public:
	virtual ~IDataSocket() {}


	virtual vector<char> receive_data() = 0;
	virtual bool has_data() = 0;

	virtual bool send_data(const vector<char>& data) = 0;
};

class IListenSocket
{
	public:
	virtual ~IListenSocket() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual unique_ptr<IDataSocket> accept_connection() = 0;
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

	virtual void connect(string ip_address, string port) = 0;
	virtual ConnectionStatus has_connected() = 0;

	virtual unique_ptr<IDataSocket> convert_to_datasocket() = 0;
};

class IReusableNonBlockingListenSocket : public IReusableSocket
{
	public:
	virtual ~IReusableNonBlockingListenSocket() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual unique_ptr<IDataSocket> accept_connection() = 0;
};

class Sockets
{
	public:
	static const std::string DefaultPort;

	static unique_ptr<IListenSocket> CreateListenSocket(string port);
	static unique_ptr<IDataSocket> CreateConnectionSocket(string peer_ip, string port);
	static unique_ptr<IReusableNonBlockingListenSocket> CreateReusableNonBlockingListenSocket(string port);
	static unique_ptr<IReusableNonBlockingConnectSocket> CreateReusableConnectSocket(name_data name);
};