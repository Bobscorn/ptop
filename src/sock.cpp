#include "sock.h"

#include <iostream>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#elif defined(__linux__)
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#endif



epic_socket::epic_socket(protocol input_proto) : _protocol(input_proto)
{
	auto family = input_proto.get_ai_family();
	auto aitype = input_proto.get_ai_socktype();
	auto aiproto = input_proto.get_ai_protocol();
	_handle = socket(family, aitype, aiproto);
}

epic_socket& epic_socket::bind_socket(const raw_name_data& name, std::string error_message)
{
	int result = bind(_handle, &name.name, name.name_len);
	throw_if_socket_error(result, error_message);
	return *this;
}

epic_socket& epic_socket::connect(sockaddr* addr, socklen_t len)
{
	int n = ::connect(_handle, addr, len);
	throw_if_socket_error(n, "Failed to connect");
	return *this;
}

epic_socket& epic_socket::start_listening()
{
	if(_protocol.is_udp()) {
        std::cout << "UDP doesn't need a listen socket" << std::endl;
        return;
    }
	int n = ::listen(_handle, 4);
	throw_if_socket_error(n, "Failed to listen");
	return *this;
}

///returns a data socket using the listen socket
epic_socket&& epic_socket::accept_data_socket()
{
	sockaddr_in client_addr;
	socklen_t client_len;
	SOCKET new_socket = accept(_handle, (struct sockaddr*)&client_addr, &client_len);
	return epic_socket(new_socket, _protocol);
}

bool epic_socket::try_connect(sockaddr* addr, socklen_t len)
{
	int n = ::connect(_handle, addr, len);
	return n != SOCKET_ERROR;
}

bool epic_socket::poll_for(int poll_flag) const
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(_handle, &poll_read_set);

	pollfd poll_thing;
	poll_thing.fd = _handle;
	poll_thing.events = poll_flag;
	poll_thing.revents = 0;

	int num_polled = poll(&poll_thing, 1, 0);
	throw_if_socket_error(num_polled, std::string("Failed to poll linux socket readability"));
	if (num_polled > 0)
		return poll_thing.revents | poll_flag;
	return false;
}

bool epic_socket::select_for(::select_for epic_for) const
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

	fd_set set;
	FD_ZERO(&set);
	FD_SET(_handle, &set);
	int n;
	switch (epic_for)
	{
	default:
	case select_for::READ:
		n = select(_handle + 1, &set, NULL, NULL, &timeout);
		break;
	case select_for::WRITE:
		n = select(_handle + 1, NULL, &set, NULL, &timeout);
		break;
	case select_for::EXCEPT:
		n = select(_handle + 1, NULL, NULL, &set, &timeout);
		break;
	}
	throw_if_socket_error(n, "Failed to select");
	return FD_ISSET(_handle, &set);
}

bool epic_socket::has_message() const
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(_handle, &poll_read_set);

	int n = select(_handle + 1, &poll_read_set, 0, 0, &timeout);
	throw_if_socket_error(n, "Failed to poll linux socket readability");

	return n > 0;
}

std::vector<char> epic_socket::recv()
{
	std::vector<char> data(500, (char)0, std::allocator<char>());
	int result = ::recv(_handle, data.data(), (int)data.size(), 0);
	if (result == SOCKET_ERROR)
	{
		std::cout << "Receiving data failed" << std::endl;
		return std::vector<char>();
	}
	data.resize(result);
	return data;
}

raw_name_data epic_socket::get_peer_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(_handle, (sockaddr*)&peer_name, &peer_size);
	throw_if_socket_error(n, "Failed to getpeername");

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
}

raw_name_data epic_socket::get_name_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getsockname(_handle, (sockaddr*)&peer_name, &peer_size);
	throw_if_socket_error(n, "Failed to getpeername");

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
}