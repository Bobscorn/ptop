#include "linux_socket.h"

#include <exception>
#include <stdexcept>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>

std::string linux_error()
{
	std::string error = "Err code: 8 (";
	error += strerror(errno);
	return error + ")";
}

void ILinuxSocket::shutdown()
{
}

peer_data ILinuxSocket::get_peer_data()
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(_socket, (sockaddr*)&peer_name, &peer_size);

	vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &peer_name.sin_addr, buf.data(), buf.size());
	if (!str)
		throw std::runtime_error(string("Failed to convert sockaddr to string: ") + linux_error());

	string address = str;

	string port = to_string(peer_name.sin_port);
	peer_data out;
	out.ip_address = address;
	out.port = port;
	return out;
}

name_data ILinuxSocket::get_sock_data()
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getsockname(_socket, (sockaddr*)&peer_name, &peer_size);

	name_data out;
	out.addr = peer_name;
	return out;
}

linux_listen_socket::linux_listen_socket(std::string port)
{
	_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	socklen_t cli_len;
	if (_socket < 0)
		throw std::runtime_error(string("Failed to create linux socket: ") + linux_error());

	struct sockaddr_in serv_addr, cli_addr;

	int portno = atoi(port.c_str());
	bzero((char*)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	if (bind(_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
		throw std::runtime_error(string("Failed to bind linux socket: ") + linux_error());
}

void linux_listen_socket::listen()
{
	if (::listen(_socket, 5) < 0)
		throw std::runtime_error(string("Error when listening: ") + linux_error());
}

bool linux_listen_socket::has_connection()
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(_socket, &poll_read_set);

	int n = select(1, &poll_read_set, 0, 0, &timeout);
	if (n < 0)
		throw std::runtime_error(string("Failed to poll linux socket readability: ") + linux_error());

	return n > 0;
}

unique_ptr<IDataSocket> linux_listen_socket::accept_connection()
{
	sockaddr_in client_addr;
	socklen_t client_len;
	int new_socket = accept(_socket, (struct sockaddr*)&client_addr, &client_len);
	if (new_socket < 0)
		return nullptr;

	return make_unique<linux_data_socket>(new_socket);
}

linux_data_socket::linux_data_socket(int socket) : ILinuxSocket(socket)
{
}

linux_data_socket::linux_data_socket(std::string peer_address, std::string peer_port)
{
	struct sockaddr_in serv_addr;
	struct hostent* serv_ent;
	int portno = atoi(peer_port.c_str());

	serv_ent = gethostbyname(peer_address.c_str());

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, &serv_ent->h_addr, serv_ent->h_length);
	serv_addr.sin_port = htons(portno);

	_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (connect(_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
		throw std::runtime_error(string("Socket failed to connect with: ") + linux_error());
}

std::vector<char> linux_data_socket::receive_data()
{
	std::vector<char> recv_data{ 500, '0', std::allocator<char>() };
	int n = read(_socket, recv_data.data(), 500);
	if (n < -1)
	{
		cerr << "Failed to read data from linux socket: " << linux_error() << std::endl;
		return std::vector<char>();
	}
	recv_data.resize(n);
	return recv_data;
}

bool linux_data_socket::has_data()
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(_socket, &poll_read_set);

	int n = select(1, &poll_read_set, 0, 0, &timeout);
	if (n < 0)
		throw std::runtime_error(string("Failed to poll linux socket readability: ") + linux_error());

	return n > 0;
}

bool linux_data_socket::send_data(const std::vector<char>& data)
{
	int n = write(_socket, data.data(), data.size());
	if (n < 0)
	{
		cerr << "Error sending data: " << linux_error() << std::endl;
		return false;
	}

	return true;
}

linux_reuse_nonblock_listen_socket::linux_reuse_nonblock_listen_socket(std::string port)
{
	cout << "Attempting to bind on port " << port << std::endl;

	int portno = atoi(port.c_str());

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (_socket < 0)
		throw std::runtime_error(string("Failed to create reusable nonblocking listen socket: ") + linux_error());

	int reuseVal = 1;
	int n = setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, &reuseVal, sizeof(reuseVal));
	if (n < 0)
	{
		auto err = linux_error();
		close(_socket);
		throw std::runtime_error(string("Failed to set socket SO_REUSEADDR: ") + err);
	}

	n = ::bind(_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (n < 0)
	{
		auto err = linux_error();
		close(_socket);
		throw std::runtime_error(string("Failed to bind reuseable nonblocking socket: ") + err);
	}
}

void linux_reuse_nonblock_listen_socket::listen()
{
	auto n = ::listen(_socket, 4);
	if (n < 1 && n != EINPROGRESS)
		throw std::runtime_error(string("Failed to listen with: ") + linux_error());
}

bool linux_reuse_nonblock_listen_socket::has_connection()
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(_socket, &poll_read_set);

	int n = select(1, &poll_read_set, 0, 0, &timeout);
	if (n < 0)
		throw std::runtime_error(string("Failed to poll linux socket readability (has connection): ") + linux_error());

	return n > 0;
}

unique_ptr<IDataSocket> linux_reuse_nonblock_listen_socket::accept_connection()
{
	int accepted_socket = accept(_socket, 0, 0);

	if (accepted_socket < 0)
		return nullptr;
	return make_unique<linux_data_socket>(accepted_socket);
}

linux_reuse_nonblock_connection_socket::linux_reuse_nonblock_connection_socket(name_data data)
{
	_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (_socket < 0)
	{
		auto err = linux_error();
		close(_socket);
		throw std::runtime_error(string("Failed to create nonblocking socket: ") + err);
	}

	int reuseVal = 1;
	int n = setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, &reuseVal, sizeof(reuseVal));
	if (n < 0)
	{
		auto err = linux_error();
		close(_socket);
		throw std::runtime_error(string("Failed to set socket SO_REUSEADDR with: ") + err);
	}

	n = ::bind(_socket, (struct sockaddr*)&data.addr, sizeof(data.addr));
	if (n < 0)
	{
		auto err = linux_error();
		close(_socket);
		throw std::runtime_error(string("Failed to bind connect socket with: ") + err);
	}
}

void linux_reuse_nonblock_connection_socket::connect(std::string ip_address, std::string port)
{
	struct sockaddr_in serv_addr;
	struct hostent* serv_ent;
	int portno = atoi(port.c_str());

	serv_ent = gethostbyname(ip_address.c_str());

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, &serv_ent->h_addr, serv_ent->h_length);
	serv_addr.sin_port = htons(portno);

	int n = ::connect(_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (n < 0 && n != EINPROGRESS)
		throw std::runtime_error(string("Unexpected error attempting to connect on nonblocking socket: ") + linux_error());
}

ConnectionStatus linux_reuse_nonblock_connection_socket::has_connected()
{
	fd_set write_set;
	FD_ZERO(&write_set);
	FD_SET(_socket, &write_set);

	struct timeval timeout;
	timeout.tv_sec = timeout.tv_usec = 0;

	int n = select(1, NULL, &write_set, NULL, &timeout);

	if (n < 0)
		throw std::runtime_error(string("Failed to select nonblock connect socket write-ability (whether it has connected): ") + linux_error());

	if (n < 1)
	{
		fd_set except_set;
		FD_ZERO(&except_set);
		FD_SET(_socket, &except_set);
		n = select(1, NULL, NULL, &except_set, &timeout);
		if (n < 0)
			throw std::runtime_error(string("Failed to select socket error status with: ") + linux_error());
		if (n < 1)
			return ConnectionStatus::PENDING;

		int sock_error = 0;
		socklen_t sock_error_size = sizeof(sock_error);
		if (getsockopt(_socket, SOL_SOCKET, SO_ERROR, (char*)&sock_error, &sock_error_size) < 0)
			throw std::runtime_error(string("Failed to get socket error code with: ") + linux_error());

		std::cerr << "Socket has error code: " << sock_error << std::endl;

		return ConnectionStatus::FAILED;
	}

	return ConnectionStatus::SUCCESS;
}

unique_ptr<IDataSocket> linux_reuse_nonblock_connection_socket::convert_to_datasocket()
{
	int flags = fcntl(_socket, F_GETFL);
	if (flags < 0)
		throw std::runtime_error(string("Failed to query socket's flags: ") + linux_error());
	int n = fcntl(_socket, F_SETFL, flags & (~O_NONBLOCK));
	if (n < 0)
		throw std::runtime_error(string("Failed to set socket as blocking again: ") + linux_error());

	std::unique_ptr<IDataSocket> out = std::make_unique<linux_data_socket>(_socket);
	_socket = -1;
	return out;
}
