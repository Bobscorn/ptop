#pragma once

#include <vector>
#include <memory>
#include <string>

using namespace std;

#define DEFAULT_PORT "27015"

class ISocket
{
	public:
	virtual ~ISocket() {}

	virtual void shutdown() = 0;
};

class IReceiverSocket
{
	public:
		
	virtual ~IReceiverSocket() {}

	virtual vector<char> receive_data() = 0;
	virtual bool has_data() = 0;
};

class IListenSocket
{
	public:
	virtual ~IListenSocket() {}

	virtual unique_ptr<IReceiverSocket> accept_connection() = 0;
};

class ISenderSocket
{
	public:

	virtual ~ISenderSocket() {}

	virtual bool send_data(const vector<char>& data) = 0;
};

class Sockets
{
	public:
	static unique_ptr<IListenSocket> CreateListenSocket();
	static unique_ptr<ISenderSocket> CreateSenderSocket(string peer_ip);
};