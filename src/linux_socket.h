#pragma once

#include <sys/types.h>
#include <sys/socket.h>

#include <string>

#include "socket.h"

using namespace std;

class ILinuxSocket : virtual public ISocket
{
protected:
	ILinuxSocket() : _socket(-1) {}
	ILinuxSocket(int socket) : _socket(socket) {}
	int _socket;

public:
	void shutdown() override;
	peer_data get_peer_data() override;
	name_data get_sock_data() override;
};

class linux_listen_socket : public ILinuxSocket, public IListenSocket
{
public:
	linux_listen_socket(string port);

	void listen() override;
	bool has_connection() override;
	unique_ptr<IDataSocket> accept_connection() override;
};

class linux_data_socket : public ILinuxSocket, public IDataSocket
{
public:
	linux_data_socket(int socket);
	linux_data_socket(string peer_address, string peer_port);

	vector<char> receive_data() override;
	bool has_data() override;

	bool send_data(const vector<char>& data) override;
};

class linux_reuse_nonblock_listen_socket : public ILinuxSocket, public IReusableNonBlockingListenSocket
{
public:
	linux_reuse_nonblock_listen_socket(string port);

	void listen() override;
	bool has_connection() override;
	unique_ptr<IDataSocket> accept_connection() override;
};

class linux_reuse_nonblock_connection_socket : public ILinuxSocket, public IReusableNonBlockingConnectSocket
{
public:
	linux_reuse_nonblock_connection_socket(name_data data);

	void connect(string ip_address, string port) override;
	ConnectionStatus has_connected() override;

	unique_ptr<IDataSocket> convert_to_datasocket() override;
};