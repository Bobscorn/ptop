#pragma once

#include <sys/types.h>
#include <sys/socket.h>

#include <string>

#include "socket.h"

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
	linux_listen_socket(std::string port);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocket> accept_connection() override;
};

class linux_data_socket : public ILinuxSocket, public IDataSocket
{
public:
	linux_data_socket(int socket);
	linux_data_socket(std::string peer_address, std::string peer_port);

	std::vector<char> receive_data() override;
	bool has_data() override;

	bool send_data(const std::vector<char>& data) override;
};

class linux_reuse_nonblock_listen_socket : public ILinuxSocket, public IReusableNonBlockingListenSocket
{
public:
	linux_reuse_nonblock_listen_socket(std::string port);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocket> accept_connection() override;
};

class linux_reuse_nonblock_connection_socket : public ILinuxSocket, public IReusableNonBlockingConnectSocket
{
public:
	linux_reuse_nonblock_connection_socket(name_data data);

	void connect(std::string ip_address, std::string port) override;
	ConnectionStatus has_connected() override;

	std::unique_ptr<IDataSocket> convert_to_datasocket() override;
};