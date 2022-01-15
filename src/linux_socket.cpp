#include "linux_socket.h"

#ifdef __linux__
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

#include "message.h"
#include "loop.h"


std::string linux_error()
{
	auto err_code = errno;
	std::string error = "Err code: " + std::to_string(err_code) + " (";
	error += strerror(errno);
	return error + ")";
}

std::string linux_error(int err_code)
{
	std::string error = "Err code: " + std::to_string(err_code) + " (";
	error += strerror(errno);
	return error + ")";
}

readable_ip_info convert_to_readable(raw_name_data data)
{
	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &data.ipv4_addr().sin_addr, buf.data(), buf.size());

	if (!str) {
		throw print_new_exception(std::string("Failed to convert sockaddr to string: ") + linux_error(), LINE_CONTEXT);
	}
		

	std::string address = str;

	std::string port = std::to_string(ntohs(data.ipv4_addr().sin_port));
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

LinuxSocket::LinuxSocket(epic_socket&& socket) 
	: _socket(std::move(socket))
{ 
	update_name_info();

	if (_address == "Unassigned" || _address.empty() ||
		_port == "Unassigned" || _port.empty()) {
		throw print_new_exception("failed to update name info", LINE_CONTEXT);
	}
}

void LinuxSocket::update_name_info()
{
	auto name = get_myname_readable();
	_address = name.ip_address;
	_port = name.port;
}

void LinuxSocket::update_endpoint_info()
{
	auto name = get_peername_readable();
	_endpoint_address = name.ip_address;
	_endpoint_port = name.port;
	_endpoint_assigned = true;
}

void LinuxSocket::update_endpoint_if_needed()
{
	if (!_endpoint_assigned)
	{
		update_endpoint_info();
	}
}

LinuxSocket::~LinuxSocket()
{
	std::cout << (_socket.is_valid() ? "Closing socket: " : "Closing dead socket that had: ") << _endpoint_address << ":" << _endpoint_port << std::endl;
}

void LinuxSocket::shutdown()
{
}

readable_ip_info LinuxSocket::get_peer_data() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);
	if (n != 0)
		throw print_new_exception("Failed to getpeername: " + linux_error(), LINE_CONTEXT);

	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &peer_name.sin_addr, buf.data(), buf.size());
	if (!str)
		throw print_new_exception(std::string("Failed to convert sockaddr to string: ") + linux_error(), LINE_CONTEXT);

	std::string address = str;

	std::string port = std::to_string(peer_name.sin_port);
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

raw_name_data LinuxSocket::get_peername_raw() const
{
	return _socket.get_peer_raw();
}

raw_name_data LinuxSocket::get_myname_raw() const
{
	return _socket.get_name_raw();
}

readable_ip_info LinuxSocket::get_peername_readable() const 
{
	return convert_to_readable(get_peername_raw());
}

readable_ip_info LinuxSocket::get_myname_readable() const
{
	return convert_to_readable(get_myname_raw());
}

epic_socket listen_construct(std::string port, protocol input_proto)
{
	std::cout << "[Listen] Create new Socket on port (with localhost): " << port << std::endl;
	auto listen_socket = epic_socket(input_proto);

	socklen_t cli_len;
	if (listen_socket.is_invalid())
		throw std::runtime_error(std::string("[Listen] Failed to create linux socket: ") + linux_error());

	listen_socket.set_socket_reuse();

	struct sockaddr_in serv_addr, cli_addr;

	int portno = atoi(port.c_str());
	bzero((char*)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	std::cout << "Binding..." << std::endl;
	listen_socket.bind_socket(raw_name_data{ *(sockaddr*)&serv_addr, sizeof(serv_addr) });

	return listen_socket;
}

linux_listen_socket::linux_listen_socket(std::string port, protocol input_proto) : LinuxSocket(listen_construct(port, input_proto))
{
}

void linux_listen_socket::listen()
{	
	std::cout << "[Listen] Socket now Listening (" << get_my_ip() << ":" << get_my_port() << ")" << std::endl;
	_socket.start_listening();
}

bool linux_listen_socket::has_connection()
{
	return _socket.poll_for(POLLRDNORM);
}

std::unique_ptr<IDataSocket> linux_listen_socket::accept_connection()
{
	std::cout << "[Listen] Socket Attempting to accept a connection" << std::endl;
	auto tmp = _socket.accept_data_socket();
	return std::make_unique<linux_data_socket>(std::move(tmp));
}

epic_socket&& steal_construct(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old)
{
	std::cout << "[Data] Moving linux_reusable_nonblocking_connection_socket " << old->get_identifier_str() << " to a data_socket" << std::endl;
	linux_reuse_nonblock_connection_socket& real_old = *dynamic_cast<linux_reuse_nonblock_connection_socket*>(old.get());
	epic_socket epic = real_old.release_socket();
	epic.set_non_blocking(false);
	return std::move(epic);
}

void linux_data_socket::process_socket_data()
{
	std::cout << "[Data] Trying to receive new data from Socket: " << get_identifier_str() << std::endl;
	std::vector<char> recv_data = _socket.recv_bytes();
	if (recv_data.size() > 0)
	{
		std::cout << "Received " << recv_data.size() << " bytes" << std::endl;
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
			std::cout << "Socket " << (*this).get_identifier_str() << "Received " << "a Message of type: " << mt_to_string(new_message.Type) << " with length: " << new_message.Length << " bytes" << std::endl;
		}
	}
	else
	{
		std::cout << "Received empty data from: " << get_identifier_str() << std::endl;
		recv_data.clear();
	}
}

linux_data_socket::linux_data_socket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old) : LinuxSocket(steal_construct(std::move(old)))
{
	update_endpoint_info();
}

linux_data_socket::linux_data_socket(epic_socket&& socket) : LinuxSocket(std::move(socket))
{
	std::cout << "[Data] Copy Constructor Data socket" << std::endl;
	update_endpoint_info();

	if (_socket.is_invalid())
		throw std::runtime_error("[Data] Invalid socket in Copy Constructor");
}

epic_socket data_connect_construct(std::string peer_address, std::string peer_port, protocol ip_proto)
{
	std::cout << "[Data] Creating a Linux Data Socket connecting to: " << peer_address << ":" << peer_port << std::endl;

	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;

	bzero(&hints, sizeof(hints));
	hints.ai_family = ip_proto.get_ai_family();
	hints.ai_socktype = ip_proto.get_ai_socktype();
	hints.ai_protocol = ip_proto.get_ai_protocol();

	int n = getaddrinfo(peer_address.c_str(), peer_port.c_str(), &hints, &result);

	if (n == SOCKET_ERROR)
		throw print_new_exception("Failed to get address info for: " + peer_address + ":" + peer_port + " with: " + linux_error(), LINE_CONTEXT);

	epic_socket conn_socket = epic_socket(ip_proto);
	conn_socket.connect(result->ai_addr, result->ai_addrlen);

	return conn_socket;
}

linux_data_socket::linux_data_socket(std::string peer_address, std::string peer_port, protocol proto) : LinuxSocket(data_connect_construct(peer_address, peer_port, proto))
{
	update_endpoint_info();
}

Message linux_data_socket::receive_message()
{
	process_socket_data();

	if (_stored_messages.size() > 0)
	{
		auto tmp = _stored_messages.front();
		_stored_messages.pop();
		return tmp;
	}

	throw print_new_exception("Failed to parse incoming data", LINE_CONTEXT);
}

bool linux_data_socket::has_message()
{
	return _socket.has_message();
}

bool linux_data_socket::send_data(const Message& message)
{
	std::cout << "Socket " << (*this).get_identifier_str() << " sending a Message of type: " << mt_to_string(message.Type) << " with length: " << message.Length << " bytes" << std::endl;
	auto bytes = message.to_bytes();
	if (_socket.send_bytes(bytes))
	{
		_sent_bytes += bytes.size();
		return true;
	}
	return false;
}

bool linux_data_socket::has_died()
{
	return _socket.has_died();
}

epic_socket reuse_listen_construct(std::string port, protocol proto)
{
	std::cout << "[ListenReuseNoB] Creating Reusable Listen Socket on (localhost): " << port << std::endl;

	int portno = atoi(port.c_str());

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	epic_socket listen_socket = epic_socket(proto);
	if (listen_socket.is_invalid())
		throw std::runtime_error(std::string("[ListenReuseNoB] (localhost:") + port + ") Failed to create reusable nonblocking listen socket: " + linux_error());

	listen_socket.set_non_blocking(true);
	listen_socket.set_socket_reuse();

	listen_socket.bind_socket(raw_name_data{ serv_addr });

	return listen_socket;
}

linux_reuse_nonblock_listen_socket::linux_reuse_nonblock_listen_socket(std::string port, protocol proto) : LinuxSocket(reuse_listen_construct(port, proto))
{
	
}

void linux_reuse_nonblock_listen_socket::listen()
{
	std::cout << "[ListenReuseNoB] Now Listening on: " << get_my_ip() << ":" << get_my_port() << std::endl;
	_socket.listen(4);
}

bool linux_reuse_nonblock_listen_socket::has_connection()
{
	return _socket.has_connection();
}

std::unique_ptr<IDataSocket> linux_reuse_nonblock_listen_socket::accept_connection()
{
	std::cout << "[ListenReuseNoB] Accepting Connection..." << std::endl;

	auto new_sock = _socket.accept_data_socket();
	return std::make_unique<linux_data_socket>(std::move(new_sock));
}

epic_socket reuse_connection_construct(raw_name_data data, protocol proto)
{
	auto readable = convert_to_readable(data);
	std::cout << "[DataReuseNoB] Creating Connection socket to: " << readable.ip_address << ":" << readable.port << std::endl;
	epic_socket conn_socket = epic_socket(proto);
	if (conn_socket.is_invalid())
		throw std::runtime_error(std::string("[DataReuseNoB] Failed to create nonblocking socket: ") + linux_error());

	conn_socket.set_non_blocking(true);
	conn_socket.set_socket_reuse();

	conn_socket.bind_socket(data, "[DataReuseNoB] Failed to bind");
	std::cout << "[DataReuseNoB] Successfully bound Data socket to: " << readable.ip_address << ":" << readable.port << std::endl;

	return conn_socket;
}

linux_reuse_nonblock_connection_socket::linux_reuse_nonblock_connection_socket(raw_name_data data, std::string ip_address, std::string port, protocol proto) : LinuxSocket(reuse_connection_construct(data, proto))
{
	// if tcp?
	this->connect(ip_address, port);
}

void linux_reuse_nonblock_connection_socket::connect(std::string ip_address, std::string port)
{
	std::cout << "[DataReuseNoB] Trying to connect to: " << ip_address << ":" << port << std::endl;
	struct addrinfo* results, hints;
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	int iResult = 0;

	iResult = getaddrinfo(ip_address.c_str(), port.c_str(), &hints, &results);
	if (iResult != 0)
		throw std::runtime_error((std::string("Failed to getaddrinfo, error: ") + std::to_string(iResult)).c_str());

	if (results == nullptr)
		throw std::runtime_error((std::string("No possible sockets found for '") + ip_address + ":" + port + "'").c_str());

	_socket.connect(results->ai_addr, results->ai_addrlen);
	std::cout << "[DataReuseNoB] Successfully BEGUN Connection to: " << ip_address << ":" << port << std::endl;
}

ConnectionStatus linux_reuse_nonblock_connection_socket::has_connected()
{
	if (_socket.is_invalid())
		return ConnectionStatus::FAILED;

	if (_socket.poll_for(POLLWRNORM))
	{
		update_endpoint_if_needed();
		return ConnectionStatus::SUCCESS;
	}


	if (!_socket.select_for(select_for::EXCEPT))
		return ConnectionStatus::PENDING;

	auto sock_error = _socket.get_socket_option<int>(SO_ERROR);

	std::cerr << "Socket has error code: " << sock_error << std::endl;

	return ConnectionStatus::FAILED;
}
#endif