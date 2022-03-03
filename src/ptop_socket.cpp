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

bool socket_has_data(SOCKET handle)
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

	fd_set set;
	FD_ZERO(&set);
	FD_SET(handle, &set);
	int n = select((int)handle + 1, &set, NULL, NULL, &timeout);
	throw_if_socket_error(n, "Failed to select " + get_last_error(), LINE_CONTEXT);
	return FD_ISSET(handle, &set);
}

void poll_thread_func(std::shared_ptr<SOCKET> handle, std::shared_ptr<std::shared_mutex> handle_mutex, std::shared_ptr<std::vector<udp_bytes>> msgs, std::shared_ptr<std::shared_mutex> mutex, Protocol proto, std::shared_ptr<bool> thread_die)
{
	try
	{
		while (!*thread_die)
		{
			raw_name_data endpoint{};
			std::vector<char> data{};
			{
				auto handle_lock = std::shared_lock<std::shared_mutex>(*handle_mutex);
				if (*handle == REALLY_INVALID_SOCKET)
					break;

				if (socket_has_data(*handle))
				{
					data = proto.receive_bytes(*handle, endpoint);
				}
			}

			if (endpoint.name_len > 0)
			{
				{
					auto lock = std::unique_lock<std::shared_mutex>(*mutex);

					msgs->push_back(udp_bytes{ std::move(data), endpoint });
				}
			}
		}
	}
	catch (std::exception& e)
	{
		std::cout << "Polling thread caught exception: " << e.what() << std::endl;
	}
}

PtopSocket::PtopSocket(SOCKET handle, Protocol proto, std::string name) 
	: _handle(std::make_shared<SOCKET>(handle)), _protocol(proto)
	, _handle_mutex(std::make_shared<std::shared_mutex>())
	, _name(name)
	, _message_obj_mutex(std::make_shared<std::shared_mutex>())
	, _shared_message_obj(std::make_shared<std::vector<udp_bytes>>())
{
	_polling_thread = std::thread(poll_thread_func, _handle, _handle_mutex, _shared_message_obj, _message_obj_mutex,  _protocol, _thread_die);
}

PtopSocket::PtopSocket(SOCKET handle, Protocol proto, raw_name_data endpoint, std::string name) 
	: _handle(std::make_shared<SOCKET>(handle))
	, _handle_mutex(std::make_shared<std::shared_mutex>())
	, _protocol(proto)
	, _endpoint(endpoint)
	, _name(name)
	, _message_obj_mutex(std::make_shared<std::shared_mutex>())
	, _shared_message_obj(std::make_shared<std::vector<udp_bytes>>())
{
	_polling_thread = std::thread(poll_thread_func, _handle, _handle_mutex, _shared_message_obj, _message_obj_mutex, _protocol, _thread_die);
}

PtopSocket::PtopSocket(Protocol proto, std::string name) 
	: _protocol(proto)
	, _handle_mutex(std::make_shared<std::shared_mutex>())
	, _name(std::move(name))
	, _message_obj_mutex(std::make_shared<std::shared_mutex>())
	, _shared_message_obj(std::make_shared<std::vector<udp_bytes>>())
{
	int domain = _protocol.get_ai_family();
	int type = _protocol.get_ai_socktype();
	int protocol = _protocol.get_ai_protocol();
	_handle = std::make_shared<SOCKET>(socket(domain, type, protocol));
	_polling_thread = std::thread(poll_thread_func, _handle, _handle_mutex, _shared_message_obj, _message_obj_mutex, _protocol, _thread_die);
}

PtopSocket::PtopSocket(PtopSocket&& other) 
	: _handle(std::move(other._handle))
	, _handle_mutex(std::move(other._handle_mutex))
	, _protocol(other._protocol)
	, _endpoint(other._endpoint)
	, _name(std::move(other._name))
	, _polling_thread(std::move(other._polling_thread))
	, _thread_die(std::move(other._thread_die))
	, _message_obj_mutex(std::move(other._message_obj_mutex))
	, _shared_message_obj(std::move(other._shared_message_obj))
{
	other._handle = nullptr;
};

PtopSocket& PtopSocket::bind_socket(const raw_name_data& name, std::string error_message)
{
	int result = bind(*_handle, &name.name, name.name_len);
	throw_if_socket_error(result, error_message + " " + get_last_error(), LINE_CONTEXT);
	return *this;
}

PtopSocket& PtopSocket::connect(sockaddr* addr, socklen_t len)
{
	if (_protocol.is_tcp())
	{
		// cheeky little hack
		set_socket_option(SO_KEEPALIVE, (int)1);
		int n = ::connect(*_handle, addr, len);
		throw_if_socket_error(n, "Failed to connect " + get_last_error(), LINE_CONTEXT);
	}
	else if (_protocol.is_udp())
	{
		int n = ::connect(*_handle, addr, len);
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
	int n = ::listen(*_handle, 4);
	throw_if_socket_error(n, "Failed to listen " + get_last_error(), LINE_CONTEXT);
	return *this;
}

///returns a data socket using the listen socket
PtopSocket PtopSocket::accept_data_socket()
{
	try {
		sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		SOCKET new_socket = accept(*_handle, (struct sockaddr*)&client_addr, &client_len);
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
	int n = ::connect(*_handle, addr, len);
	return n != SOCKET_ERROR;
}

void PtopSocket::listen(int max_conns)
{
	if (is_tcp())
	{
		auto n = ::listen(*_handle, max_conns);
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
		FD_SET(*_handle, &poll_read_set);

		int n = select((int)*_handle + 1, &poll_read_set, 0, 0, &timeout);
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
	FD_SET(*_handle, &poll_read_set);

	pollfd poll_thing;
	poll_thing.fd = *_handle;
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

bool PtopSocket::select_for(::select_for epic_for)
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

	fd_set set;
	FD_ZERO(&set);
	FD_SET(*_handle, &set);
	int n;
	switch (epic_for)
	{
	default:
	case select_for::READ:
	{
		auto lock = std::shared_lock<std::shared_mutex>(*_message_obj_mutex);

		return _shared_message_obj->size();
	}
	case select_for::WRITE:
		n = select((int)*_handle + 1, NULL, &set, NULL, &timeout);
		break;
	case select_for::EXCEPT:
		n = select((int)*_handle + 1, NULL, NULL, &set, &timeout);
		break;
	}
	throw_if_socket_error(n, "Failed to select " + get_last_error(), LINE_CONTEXT);
	return FD_ISSET(*_handle, &set);
}

bool PtopSocket::has_message()
{
	return select_for(select_for::READ);
}

bool PtopSocket::has_died()
{
	return _protocol.has_died(*_handle, has_message());
}

raw_name_data PtopSocket::get_peer_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(*_handle, (sockaddr*)&peer_name, &peer_size);
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
	int n = getsockname(*_handle, (sockaddr*)&peer_name, &peer_size);
	throw_if_socket_error(n, "Failed to getsockname " + get_last_error(), LINE_CONTEXT);

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
}

bool PtopSocket::send_bytes(std::vector<char> bytes)
{
	return _protocol.send_bytes(*_handle, _endpoint, bytes);
}

std::vector<char> PtopSocket::receive_bytes()
{
	return receive_udp_bytes().bytes;
}

bool PtopSocket::send_udp_bytes(udp_bytes bytes)
{	
	return _protocol.send_bytes(*_handle, bytes.endpoint, bytes.bytes);
}

udp_bytes PtopSocket::receive_udp_bytes(){
	auto lock = std::shared_lock<std::shared_mutex>(*_message_obj_mutex);

	if (_shared_message_obj->empty())
		throw_new_exception("Trying to receive bytes when none are available", LINE_CONTEXT);

	auto first_msg = std::move(_shared_message_obj->front());
	_shared_message_obj->erase(_shared_message_obj->begin());

	return first_msg;
}