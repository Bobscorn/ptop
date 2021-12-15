#pragma once

#include <sys/types.h>
#include <sys/socket.h>

#include <string>

#include "socket.h"

readable_ip_info convert_to_readable(raw_name_data data);

class ILinuxSocket : virtual public ISocket
{
protected:
	ILinuxSocket() : _socket(-1), _address("Unassigned"), _port("Unassigned") {}
	ILinuxSocket(ILinuxSocket&& socket) : _socket(std::move(socket._socket)) { socket._socket = -1; }
	ILinuxSocket(int socket, raw_name_data name) : _socket(socket) { auto readable = convert_to_readable(name); _endpoint_address = readable.ip_address; _endpoint_port = readable.port; }
	int _socket;
	std::string _address;
	std::string _port;
	std::string _endpoint_address;
	std::string _endpoint_port;

	void update_name_info();
	void update_endpoint_info();

	virtual ~ILinuxSocket() {}

public:
	void shutdown() override;
	readable_ip_info get_peer_data() override;
	raw_name_data get_sock_data() override;
	raw_name_data get_peername_raw() override;
	raw_name_data get_myname_raw() override;
	readable_ip_info get_peername_readable() override;
	readable_ip_info get_myname_readable() override;
	std::string get_my_ip() override;
	std::string get_my_port() override;
	std::string get_endpoint_ip() override;
	std::string get_endpoint_port() override;
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
	linux_data_socket(int socket, raw_name_data name);
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
	linux_reuse_nonblock_connection_socket(raw_name_data data);

	void connect(std::string ip_address, std::string port) override;
	ConnectionStatus has_connected() override;

	std::unique_ptr<IDataSocket> convert_to_datasocket() override;
};