#include "ptop_socket.h"
#include "message.h"
#include "loop.h"
#include "platform.h"
#include "error.h"

#ifdef __linux__
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

extern std::string linux_error();
extern std::string linux_error(int err);

void throw_if_socket_error(int val, std::string error_message, std::string line_context)
{
	if (val == SOCKET_ERROR)
	{
		auto last_err = errno;
		if (last_err != EAGAIN && last_err != EINPROGRESS)
		{
			throw_new_exception(error_message, line_context);
		}
	}
}

std::string socket_error_to_string(int err)
{
	return linux_error(err);
}

std::string get_last_error()
{
	return linux_error();
}

PtopSocket::~PtopSocket()
{
	if (_handle != REALLY_INVALID_SOCKET)
	{
		std::cout << "Closing socket" << std::endl;
		close(_handle);
		_handle = REALLY_INVALID_SOCKET;
	}
	else
		std::cout << "Dead socket" << std::endl;
}

PtopSocket& PtopSocket::set_non_blocking(bool value)
{
	try {		
		int flags = fcntl(_handle, F_GETFL);
		throw_if_socket_error(flags, "Failed to retrieve socket flags", LINE_CONTEXT);
		int n = fcntl(_handle, F_SETFL, (value ? flags | O_NONBLOCK : flags & (~O_NONBLOCK)));
		throw_if_socket_error(n, "Failed to set blocking value", LINE_CONTEXT);
	}

	catch(...) {
		
	} 
}

#endif