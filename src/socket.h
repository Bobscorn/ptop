#pragma once

#include <vector>
#include <memory>
#include <string>

using namespace std;

#define DEFAULT_PORT "27015"

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
};

class IDataSocket
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

class IReusableSocket
{
	protected:
	IReusableSocket() {}

	public:
	virtual ~IReusableSocket() {}

	virtual bool send_data(const std::vector<char>& data) = 0;

	virtual bool has_data() = 0;
	virtual vector<char> receive_data() = 0;
};

class IReusableNonBlockingListenSocket : public IReusableSocket
{
	public:
	virtual ~IReusableNonBlockingListenSocket() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual unique_ptr<IReusableNonBlockingConnectSocket> accept_connection() = 0;
};

class IReusableNonBlockingConnectSocket : public IReusableSocket
{
	public:
	virtual ~IReusableNonBlockingConnectSocket() {}

	virtual void connect(string ip_address, string port) = 0;
	virtual ConnectionStatus has_connected() = 0;
};

class Sockets
{
	public:
	static unique_ptr<IListenSocket> CreateListenSocket(string port);
	static unique_ptr<IDataSocket> CreateConnectionSocket(string peer_ip, string port);
	static unique_ptr<IReusableNonBlockingListenSocket> CreateReusableNonBlockingListenSocket(string port);
	static unique_ptr<IReusableNonBlockingConnectSocket> CreateReusableConnectSocket(string peer_ip, string port);
};