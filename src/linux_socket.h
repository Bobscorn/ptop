#pragma once

#include <sys/types.h>
#include <sys/socket.h>

#include <string>

#include "socket.h"

readable_ip_info convert_to_readable(raw_name_data data);

class LinuxSocket : virtual public ISocket
{
protected:
	LinuxSocket(int socket);
	int _socket;
	std::string _address;
	std::string _port;
	std::string _endpoint_address;
	std::string _endpoint_port;
	bool _endpoint_assigned = false;

	void update_name_info();
	void update_endpoint_info();
	void update_endpoint_if_needed();

	virtual ~LinuxSocket();

public:
	void shutdown() override;
	readable_ip_info get_peer_data() const override;
	raw_name_data get_peername_raw() const override;
	raw_name_data get_myname_raw() const override;
	readable_ip_info get_peername_readable() const override;
	readable_ip_info get_myname_readable() const override;

	inline std::string get_my_ip() const override { return _address; }
	inline std::string get_my_port() const override { return _port; }
	inline std::string get_endpoint_ip() const override { return _endpoint_address; }
	inline std::string get_endpoint_port() const override { return _endpoint_port; }

	inline std::string get_identifier_str() const override { if (!_endpoint_assigned) return std::string("(priv: ") + _address + ":" + _port + ", pub: N/A)"; return std::string("(pub: ") + _endpoint_address + ":" + _endpoint_port + ")"; }

	inline int get_socket() const { return _socket; }
	inline void clear_socket() { _socket = -1; }
};

class linux_listen_socket : public LinuxSocket, public IListenSocket
{
public:
	linux_listen_socket(std::string port);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocket> accept_connection() override;
};

class linux_data_socket : public LinuxSocket, public IDataSocket
{
public:
	linux_data_socket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old);
	linux_data_socket(int socket);
	linux_data_socket(std::string peer_address, std::string peer_port);

	std::vector<char> receive_data() override;
	bool has_data() override;

	bool send_data(const std::vector<char>& data) override;

	bool has_died();
};

class linux_reuse_nonblock_listen_socket : public LinuxSocket, public IReusableNonBlockingListenSocket
{
public:
	linux_reuse_nonblock_listen_socket(std::string port);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocket> accept_connection() override;
};

class linux_reuse_nonblock_connection_socket : public LinuxSocket, public IReusableNonBlockingConnectSocket
{
public:
	linux_reuse_nonblock_connection_socket(raw_name_data data, std::string ip_address, std::string port);

	void connect(std::string ip_address, std::string port);
	ConnectionStatus has_connected() override;
};