#include "ptop_socket.h"
#include "error.h"
#include "message.h"
#include "platform.h"

#if defined(WIN32)
#ifndef WIN32_LEAN_AND_MEAN
	#define WIN32_LEAN_AND_MEAN
#endif
	#include <windows.h>
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <iphlpapi.h>
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

#include <iostream>
#include <chrono>

using namespace std::chrono;

PtopSocket::PtopSocket(Protocol proto, std::string name) : _protocol(proto), _name(std::move(name))
{
	int domain = _protocol.get_ai_family();
	int type = _protocol.get_ai_socktype();
	int protocol = _protocol.get_ai_protocol();
	_handle = socket(domain, type, protocol);
}

PtopSocket& PtopSocket::bind_socket(const raw_name_data& name, std::string error_message)
{
	int result = bind(_handle, &name.name, name.name_len);
	throw_if_socket_error(result, error_message + " " + get_last_error(), LINE_CONTEXT);
	return *this;
}

PtopSocket& PtopSocket::connect(sockaddr* addr, socklen_t len)
{
	if (_protocol.is_tcp())
	{
		// cheeky little hack
		set_socket_option(SO_KEEPALIVE, (int)1);
		int n = ::connect(_handle, addr, len);
		throw_if_socket_error(n, "Failed to connect " + get_last_error(), LINE_CONTEXT);
	}
	else if (_protocol.is_udp())
	{
		int n = ::connect(_handle, addr, len);
		throw_if_socket_error(n, "Failed to connect " + get_last_error(), LINE_CONTEXT);
		_endpoint = raw_name_data(*addr, len);
	}
	return *this;
}

PtopSocket& PtopSocket::start_listening()
{
	if(_protocol.is_udp()) {
        std::cout << "UDP doesn't need a listen socket" << std::endl;
        return *this;
    }
	int n = ::listen(_handle, 4);
	throw_if_socket_error(n, "Failed to listen " + get_last_error(), LINE_CONTEXT);
	return *this;
}

///returns a data socket using the listen socket
PtopSocket PtopSocket::accept_data_socket()
{
	try {
		sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		SOCKET new_socket = accept(_handle, (struct sockaddr*)&client_addr, &client_len);
		if (new_socket == REALLY_INVALID_SOCKET)
		{
			throw_new_exception("Failed to accept incoming connection: " + get_last_error(), LINE_CONTEXT);
		}
		auto new_sock = PtopSocket(new_socket, _protocol, raw_name_data(client_addr));
		new_sock.set_socket_option(SO_KEEPALIVE, (int)1);
		return new_sock;
	}

	catch(std::exception& e) {
		throw_with_context(e, LINE_CONTEXT);
	}
}

bool PtopSocket::try_connect(sockaddr* addr, socklen_t len)
{
	int n = ::connect(_handle, addr, len);
	return n != SOCKET_ERROR;
}

void PtopSocket::listen(int max_conns)
{
	if (is_tcp())
	{
		auto n = ::listen(_handle, max_conns);
		throw_if_socket_error(n, "Failed to listen on socket. " + get_last_error(), LINE_CONTEXT);
	}
}

bool PtopSocket::has_connection() const
{
	try
	{
		if (is_udp())
			return false;
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;

		fd_set poll_read_set;
		FD_ZERO(&poll_read_set);
		FD_SET(_handle, &poll_read_set);

		int n = select((int)_handle + 1, &poll_read_set, 0, 0, &timeout);
		throw_if_socket_error(n, "Failed to poll socket readability. " + get_last_error(), LINE_CONTEXT);

		return n > 0;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

bool PtopSocket::poll_for(int poll_flag) const
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

	#if defined(WIN32) | defined(_WIN64)
	int num_polled = WSAPoll(&poll_thing, 1, 0);
	#elif defined(__linux__)
	int num_polled = poll(&poll_thing, 1, 0);
	#endif
	if (num_polled > 0)
		return poll_thing.revents | poll_flag;
	
	throw_if_socket_error(num_polled, std::string("Failed to poll linux socket readability ") + get_last_error(), LINE_CONTEXT);
	return false;
}

bool PtopSocket::select_for(::select_for epic_for) const
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
		n = select((int)_handle + 1, &set, NULL, NULL, &timeout);
		break;
	case select_for::WRITE:
		n = select((int)_handle + 1, NULL, &set, NULL, &timeout);
		break;
	case select_for::EXCEPT:
		n = select((int)_handle + 1, NULL, NULL, &set, &timeout);
		break;
	}
	throw_if_socket_error(n, "Failed to select " + get_last_error(), LINE_CONTEXT);
	return FD_ISSET(_handle, &set);
}

bool PtopSocket::has_message() const
{
	return select_for(select_for::READ);
}

bool PtopSocket::has_died()
{
	return _protocol.has_died(_handle, has_message());
}

raw_name_data PtopSocket::get_peer_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(_handle, (sockaddr*)&peer_name, &peer_size);
	throw_if_socket_error(n, "Failed to getpeername " + get_last_error(), LINE_CONTEXT);

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
}

raw_name_data PtopSocket::get_name_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getsockname(_handle, (sockaddr*)&peer_name, &peer_size);
	throw_if_socket_error(n, "Failed to getsockname " + get_last_error(), LINE_CONTEXT);

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
}

bool PtopSocket::send_bytes(std::vector<char> bytes)
{
	return _protocol.send_bytes(_handle, _endpoint, bytes);
}

std::vector<char> PtopSocket::receive_bytes()
{
	return _protocol.receive_bytes(_handle, _endpoint);
}

bool PtopSocket::send_udp_bytes(udp_bytes bytes)
{	
	return _protocol.send_bytes(_handle, bytes.endpoint, bytes.bytes);
}

udp_bytes PtopSocket::receive_udp_bytes(){
	raw_name_data new_name{};
	auto result = _protocol.receive_bytes(_handle, new_name);
	udp_bytes output = udp_bytes{
		result, new_name
	};
	return output;
}