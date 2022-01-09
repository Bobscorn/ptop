#include "sock.h"

#include <exception>
#include <stdexcept>
#include <iostream>
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
#include <poll.h>
#include <errno.h>

#include "message.h"
#include "loop.h"

extern std::string linux_error();
extern std::string linux_error(int err);
//
//void throw_if_socket_error(int val, std::string error_message)
//{
//	if (val == SOCKET_ERROR)
//		throw std::runtime_error(error_message + " with: " + linux_error());
//}

void throw_if_socket_error(int val, std::string error_message)
{
	if (val == SOCKET_ERROR)
	{
		auto last_err = errno;
		if (last_err != EAGAIN || last_err != EINPROGRESS)
			throw std::runtime_error(error_message + " with: " + linux_error(last_err));
	}
}

epic_socket::~epic_socket()
{
	if (_handle != REALLY_INVALID_SOCKET)
	{
		close(_handle);
		_handle = REALLY_INVALID_SOCKET;
	}
}

epic_socket& epic_socket::set_non_blocking(bool value)
{
	int flags = fcntl(_handle, F_GETFL);
	throw_if_socket_error(flags, "Failed to retrieve socket flags");
	int n = fcntl(_handle, F_SETFL, (value ? flags | O_NONBLOCK : flags & (~O_NONBLOCK)));
	throw_if_socket_error(n, "Failed to set blocking value");
}

