#if defined(__linux__)
#include "platform.h"
#include "message.h"
#include "loop.h"
#include "error.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <sys/types.h> 

#include <exception>
#include <stdexcept>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

std::string linux_error()
{
	auto err_code = errno;
	std::string error = "Err code: " + std::to_string(err_code) + " (";
	error += strerror(err_code);
	return error + ")";
}

std::string linux_error(int err_code)
{
	std::string error = "Err code: " + std::to_string(err_code) + " (";
	error += strerror(err_code);
	return error + ")";
}

Platform::Platform(PtopSocket&& socket) 
	: _socket(std::move(socket))
{
	try_update_name_info();

	if (_address == "Unassigned" || _address.empty() ||
		_port == "Unassigned" || _port.empty()) {
		throw_new_exception("failed to update name info", LINE_CONTEXT);
	}
}

void Platform::try_update_name_info()
{
	try
	{
		update_name_info();
	}
	catch (const std::exception& e)
	{
	}
}

void Platform::try_update_endpoint_info()
{
	try
	{
		update_endpoint_info();
	}
	catch (const std::exception& e)
	{
	}
}

void Platform::update_name_info()
{
	auto name = get_myname_readable();
	_address = name.ip_address;
	_port = name.port;
}

void Platform::update_endpoint_info()
{
	try
	{
		if (_socket.is_tcp() && _socket.is_listen())
		{
			std::cout << "[Socket] Not updating endpoint as this socket " << get_identifier_str() << " is a listen socket" << std::endl;
			return;
		}
		auto name = get_peername_readable();
		_endpoint_address = name.ip_address;
		_endpoint_port = name.port;
		_endpoint_assigned = true;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

void Platform::update_endpoint_if_needed()
{
	try
	{
		if (!_endpoint_assigned)
		{
			update_endpoint_info();
		}
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

readable_ip_info Platform::get_peer_data() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);
	if (n != 0)
		throw_new_exception("Failed to getpeername: " + linux_error(), LINE_CONTEXT);

	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &peer_name.sin_addr, buf.data(), buf.size());
	if (!str)
		throw_new_exception(std::string("Failed to convert sockaddr to string: ") + linux_error(), LINE_CONTEXT);

	std::string address = str;

	std::string port = std::to_string(peer_name.sin_port);
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

PtopSocket listen_construct(std::string port, Protocol input_proto, std::string name)
{
	std::cout << "[Listen] Creating new Socket on port (with localhost, named: " << name << "): " << port << std::endl;
	auto listen_socket = PtopSocket(input_proto, name);

	socklen_t cli_len;
	if (listen_socket.is_invalid())
		throw std::runtime_error(std::string("[Listen] ") + name + " Failed to create linux socket : " + linux_error());

	listen_socket.set_socket_reuse();

	struct sockaddr_in serv_addr, cli_addr;

	int portno = atoi(port.c_str());
	bzero((char*)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	std::cout << name << " Binding..." << std::endl;
	listen_socket.bind_socket(raw_name_data{ *(sockaddr*)&serv_addr, sizeof(serv_addr) });

	return listen_socket;
}

PlatformListener::PlatformListener(std::string port, Protocol input_proto, std::string name) : Platform(listen_construct(port, input_proto, name))
{
}

void PlatformListener::listen()
{	
	std::cout << "[Listen] Socket " << get_name() << " now Listening(" << get_my_ip() << ":" << get_my_port() << ")" << std::endl;
	_socket.start_listening();
}

bool PlatformListener::has_connection()
{
	return _socket.poll_for(POLLRDNORM);
}

std::unique_ptr<IDataSocketWrapper> PlatformListener::accept_connection()
{
	std::cout << "[Listen] " << get_identifier_str() << " Attempting to accept a connection" << std::endl;

	try {
		auto tmp = _socket.accept_data_socket();
		auto whatever = std::make_unique<PlatformAnalyser>(std::move(tmp));	
		return whatever;
	}

	catch(std::exception& e) {
		throw_with_context(e, LINE_CONTEXT);
	}
}

PtopSocket steal_construct(std::unique_ptr<INonBlockingConnector>&& old)
{
	try
	{
		std::cout << "[Data] Moving INonBlockingConnector " << old->get_identifier_str() << " to a data_socket" << std::endl;
		NonBlockingConnector& real_old = *dynamic_cast<NonBlockingConnector*>(old.get());
		PtopSocket sup = real_old.release_socket();
		sup.set_non_blocking(false);
		sup.set_socket_no_reuse();
		return sup;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

void PlatformAnalyser::process_socket_data()
{
#ifdef DATA_COUT
	std::cout << "[Data] Trying to receive new data from Socket: " << get_identifier_str() << std::endl;
#endif
	std::vector<char> recv_data = _socket.receive_bytes();
	if (recv_data.size() > 0)
	{
#ifdef DATA_COUT
		std::cout << "Received " << recv_data.size() << " bytes" << std::endl;
#endif
		_seen_data += recv_data.size();

		int data_read = 0;

		while ((recv_data.size() - data_read) > 0)
		{
			MESSAGE_TYPE type;
			MESSAGE_LENGTH_T length;
			std::vector<char> data;

			if (!try_read_data(recv_data.data(), data_read, recv_data.size(), type))
			{
				std::cerr << "Socket " << get_identifier_str() << " Failed to process socket data into a message" << std::endl;
				recv_data.clear();
				return;
			}
			if (!try_read_data(recv_data.data(), data_read, recv_data.size(), length))
			{
				std::cerr << "Socket " << get_identifier_str() << " Failed to process socket data into a message" << std::endl;
				recv_data.clear();
				return;
			}
			if (data_read + length > recv_data.size())
			{
				std::cerr << "Socket " << get_identifier_str() << " Read an invalid Length for a message" << std::endl;
				recv_data.clear();
				return;
			}
			data = std::vector<char>(recv_data.data() + data_read, recv_data.data() + data_read + length);
			data_read += length;
			auto new_message = Message{ type, length, std::move(data) };
			_stored_messages.push(new_message);
#ifdef DATA_COUT
			std::cout << "Socket " << get_identifier_str() << " Received " << "a Message of type: " << mt_to_string(new_message.Type) << " with length: " << new_message.Length << " bytes (+ " << sizeof(type) + sizeof(length) << " type/length bytes)" << std::endl;
#endif
		}
	}
	else
	{
		std::cout << "Received empty data from: " << get_identifier_str() << std::endl;
		recv_data.clear();
	}
}

PlatformAnalyser::PlatformAnalyser(std::unique_ptr<INonBlockingConnector>&& old) 
: Platform(steal_construct(std::move(old)))
{
	try
	{
		try_update_endpoint_info();
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

PlatformAnalyser::PlatformAnalyser(PtopSocket&& socket) : Platform(std::move(socket))
{
	std::cout << "[Data] Copy Constructor Data socket" << std::endl;
	update_endpoint_info();

	if (_socket.is_invalid())
		throw std::runtime_error("[Data] Invalid socket in Copy Constructor");
}

Message PlatformAnalyser::receive_message()
{
	process_socket_data();

	if (_stored_messages.size() > 0)
	{
		auto tmp = _stored_messages.front();
		_stored_messages.pop();
		return tmp;
	}

	return Message::null_message;
}

bool PlatformAnalyser::has_message()
{
	return _socket.has_message();
}

PtopSocket reuse_listen_construct(raw_name_data data, Protocol proto, std::string name)
{
	auto readable = convert_to_readable(data);
	std::cout << "[ListenReuseNoB] Creating Reusable Listen Socket '" << name << "' on: " << readable.ip_address << ":" << readable.port << std::endl;

	auto listen_socket = PtopSocket(proto, name);

	if (listen_socket.is_invalid())
		throw_new_exception("[ListenReuseNoB] (" + name + ") " + readable.ip_address + ":" + readable.port + " Failed to create reusable nonblocking listen socket: " + linux_error(), LINE_CONTEXT);

	listen_socket.set_non_blocking(true);
	listen_socket.set_socket_reuse();

	listen_socket.bind_socket(data);

	return listen_socket;
}

NonBlockingListener::NonBlockingListener(raw_name_data data, Protocol proto, std::string name) 
: Platform(reuse_listen_construct(data, proto, name))
{
	
}

void NonBlockingListener::listen()
{
	std::cout << "[ListenReuseNoB] " + get_identifier_str() + " Now Listening on  port: " << get_my_port() << std::endl;
	_socket.listen(4);
}

bool NonBlockingListener::has_connection()
{
	return _socket.has_connection();
}

std::unique_ptr<IDataSocketWrapper> NonBlockingListener::accept_connection()
{
	std::cout << "[ListenReuseNoB] " + get_identifier_str() + " Accepting Connection..." << std::endl;

	auto new_sock = _socket.accept_data_socket();
	return std::make_unique<PlatformAnalyser>(std::move(new_sock));
}

#endif