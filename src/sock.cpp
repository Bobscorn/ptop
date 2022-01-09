#include "sock.h"

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



epic_socket::epic_socket(int family, int type, int protocol)
{
	handle = socket(family, type, protocol);
}

epic_socket& epic_socket::bind_socket(const raw_name_data& name, std::string error_message)
{
	int result = bind(handle, &name.name, name.name_len);
	throw_if_socket_error(result, error_message);
	return *this;
}

epic_socket& epic_socket::connect(sockaddr* addr, socklen_t len)
{
	int n = ::connect(handle, addr, len);
	throw_if_socket_error(n, "Failed to connect");
}

bool epic_socket::try_connect(sockaddr* addr, socklen_t len)
{
	int n = ::connect(handle, addr, len);
	return n != SOCKET_ERROR;
}

bool epic_socket::poll_for(int poll_flag) const
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(handle, &poll_read_set);

	pollfd poll_thing;
	poll_thing.fd = handle;
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
	FD_SET(handle, &set);
	int n;
	switch (epic_for)
	{
	default:
	case select_for::READ:
		n = select(handle + 1, &set, NULL, NULL, &timeout);
		break;
	case select_for::WRITE:
		n = select(handle + 1, NULL, &set, NULL, &timeout);
		break;
	case select_for::EXCEPT:
		n = select(handle + 1, NULL, NULL, &set, &timeout);
		break;
	}
	throw_if_socket_error(n, "Failed to select");
	return FD_ISSET(handle, &set);
}

bool epic_socket::has_message() const
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(handle, &poll_read_set);

	int n = select(handle + 1, &poll_read_set, 0, 0, &timeout);
	throw_if_socket_error(n, "Failed to poll linux socket readability");

	return n > 0;
}