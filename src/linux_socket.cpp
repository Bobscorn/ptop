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
		throw print_new_exception(std::string("Failed to convert sockaddr to string: ") + linux_error(), CONTEXT);
	}
		

	std::string address = str;

	std::string port = std::to_string(ntohs(data.ipv4_addr().sin_port));
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

LinuxSocket::LinuxSocket(epic_socket&& socket, protocol proto) 
	: _socket(std::move(socket))
	, _protocol(proto)
{ 
	update_name_info();

	if (_address == "Unassigned" || _address.empty() ||
		_port == "Unassigned" || _port.empty()) {
		throw print_new_exception("failed to update name info", CONTEXT);
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
	int n = getpeername(_socket.handle, (sockaddr*)&peer_name, &peer_size);
	if (n != 0)
		throw print_new_exception("Failed to getpeername: " + linux_error(), CONTEXT);

	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &peer_name.sin_addr, buf.data(), buf.size());
	if (!str)
		throw print_new_exception(std::string("Failed to convert sockaddr to string: ") + linux_error(), CONTEXT);

	std::string address = str;

	std::string port = std::to_string(peer_name.sin_port);
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

raw_name_data LinuxSocket::get_peername_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getpeername(_socket.handle, (sockaddr*)&peer_name, &peer_size);
	if (n != 0)
		throw print_new_exception(std::string("[Socket] Failed to getpeername with: ") + linux_error(), CONTEXT);

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
}

raw_name_data LinuxSocket::get_myname_raw() const
{
	sockaddr_in peer_name;
	socklen_t peer_size = sizeof(peer_name);
	int n = getsockname(_socket.handle, (sockaddr*)&peer_name, &peer_size);
	if (n != 0)
		throw print_new_exception(std::string("[Socket] Failed to getsockname with: ") + linux_error(), CONTEXT);

	raw_name_data raw_data;
	raw_data.name = *(sockaddr*)&peer_name;
	raw_data.name_len = peer_size;
	return raw_data;
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
	epic_socket listen_socket = epic_socket(input_proto.get_ai_family(), input_proto.get_ai_socktype(), input_proto.get_ai_protocol());

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

linux_listen_socket::linux_listen_socket(std::string port, protocol input_proto) : LinuxSocket(listen_construct(port, input_proto), input_proto)
{
}

void linux_listen_socket::listen()
{
	if(_protocol.is_udp()) {
        std::cout << "UDP doesn't need a listen socket" << std::endl;
        return;
    }
	
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
	sockaddr_in client_addr;
	socklen_t client_len;
	SOCKET new_socket = accept(_socket.handle, (struct sockaddr*)&client_addr, &client_len);
	if (new_socket == INVALID_SOCKET)
		return nullptr;

	raw_name_data name;
	name.name = *(sockaddr*)&client_addr;
	name.name_len = client_len;
	auto readable = convert_to_readable(name);
	std::cout << "[Listen] Accepted a connection: " << readable.ip_address << ":" << readable.port << std::endl;
	return std::make_unique<linux_data_socket>(new_socket, _protocol);
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
	std::vector<char> recv_data = std::vector<char>(500, (char)0);
	int iResult = recv(_socket.handle, recv_data.data(), (int)recv_data.size(), 0);
	if (iResult > 0)
	{
		std::cout << "Received " << iResult << " bytes" << std::endl;
		recv_data.resize(iResult);
		_seen_data += iResult;

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
	else if (iResult == -1)
	{
		std::cerr << "Receiving data failed: " << linux_error() << std::endl;
	}
	else
	{
		std::cout << "Received empty data from: " << get_identifier_str() << std::endl;
		recv_data.clear();
	}
}

linux_data_socket::linux_data_socket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old, protocol input_proto) : LinuxSocket(steal_construct(std::move(old)), input_proto)
{
	update_endpoint_info();
}

linux_data_socket::linux_data_socket(epic_socket&& socket, protocol ip_proto) : LinuxSocket(std::move(socket), ip_proto)
{
	std::cout << "[Data] Copy Constructor Data socket" << std::endl;
	update_endpoint_info();

	if (socket.is_invalid())
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
		throw print_new_exception("Failed to get address info for: " + peer_address + ":" + peer_port + " with: " + linux_error(), CONTEXT);

	SOCKET conn_socket = INVALID_SOCKET;
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		epic_socket conn_socket = epic_socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (conn_socket.is_invalid())
		{
			auto last_err = linux_error();
			freeaddrinfo(result);
			throw print_new_exception("[Data] Failed to create data socket with: " + last_err, CONTEXT);
		}

		conn_socket.set_socket_reuse();
		
		if (ip_proto.is_tcp())
		{
			if (!conn_socket.try_connect(ptr->ai_addr, ptr->ai_addrlen))
				continue;

			auto readable = convert_to_readable(raw_name_data{ *ptr->ai_addr, ptr->ai_addrlen });
			std::cout << "[Data] Successfully connected to: " << readable.ip_address << ":" << readable.port << std::endl;
			return conn_socket;
		}
		break;
	}

	freeaddrinfo(result);

	if (conn_socket == INVALID_SOCKET)
		throw print_new_exception("[Data] No sockets successfully connected to peer", CONTEXT);

	return epic_socket();
}

linux_data_socket::linux_data_socket(std::string peer_address, std::string peer_port, protocol proto) : LinuxSocket(data_connect_construct(peer_address, peer_port, proto), proto)
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

	throw print_new_exception("Failed to parse incoming data", CONTEXT);
}

bool linux_data_socket::has_message()
{
	return _socket.has_message();
}

bool linux_data_socket::send_data(const Message& message)
{
	std::cout << "Socket " << (*this).get_identifier_str() << "sending " << "a Message of type: " << mt_to_string(message.Type) << " with length: " << message.Length << " bytes" << std::endl;
	auto bytes = message.to_bytes();
	int iSendResult = send(_socket.handle, bytes.data(), (int)bytes.size(), 0);
	if (iSendResult == SOCKET_ERROR)
	{
		std::cerr << "Failed to send data with: " << linux_error() << std::endl;
		return false;
	}
	_sent_bytes += bytes.size();
	return true;
}

bool linux_data_socket::has_died()
{
	if (has_message())
	{
		std::vector<char> recv_data{ 100, '0', std::allocator<char>() };
		int n = recv(_socket.handle, recv_data.data(), recv_data.size(), MSG_PEEK);
		if (n == SOCKET_ERROR)
		{
			std::cerr << "[Data] Failed to peek data from linux socket (trying to determine if closed): " << linux_error() << std::endl;
			return true;
		}
		return n == 0;
	}
	return false;
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

	epic_socket listen_socket = epic_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (listen_socket.is_invalid())
		throw std::runtime_error(std::string("[ListenReuseNoB] (localhost:") + port + ") Failed to create reusable nonblocking listen socket: " + linux_error());

	listen_socket.set_socket_reuse();

	listen_socket.bind_socket(raw_name_data{ *(sockaddr*)&serv_addr, sizeof(serv_addr) });

	return listen_socket;
}

linux_reuse_nonblock_listen_socket::linux_reuse_nonblock_listen_socket(std::string port, protocol proto) : LinuxSocket(reuse_listen_construct(port, proto), proto)
{
	
}

void linux_reuse_nonblock_listen_socket::listen()
{
	std::cout << "[ListenReuseNoB] Now Listening on: " << get_my_ip() << ":" << get_my_port() << std::endl;
	auto n = ::listen(_socket.handle, 4);
	if (n == SOCKET_ERROR && n != EINPROGRESS && n != EAGAIN)
	{
		auto err = errno;
		if (err && err != EINPROGRESS && err != EAGAIN)
			throw print_new_exception("[ListenReuseNoB] Failed to listen with: " + linux_error(), CONTEXT);
	}
}

bool linux_reuse_nonblock_listen_socket::has_connection()
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	fd_set poll_read_set;
	FD_ZERO(&poll_read_set);
	FD_SET(_socket.handle, &poll_read_set);

	int n = select(_socket.handle + 1, &poll_read_set, 0, 0, &timeout);
	if (n == SOCKET_ERROR)
		throw print_new_exception("[ListenReuseNoB] Failed to poll linux socket readability (has connection): " + linux_error(), CONTEXT);

	return n > 0;
}

std::unique_ptr<IDataSocket> linux_reuse_nonblock_listen_socket::accept_connection()
{
	std::cout << "[ListenReuseNoB] Accepting Connection..." << std::endl;
	sockaddr_in client_addr;
	socklen_t client_len;
	SOCKET accepted_socket = accept(_socket.handle, (struct sockaddr*)&client_addr, &client_len);

	if (accepted_socket == INVALID_SOCKET)
		return nullptr;
	raw_name_data name;
	name.name = *(sockaddr*)&client_addr;
	name.name_len = client_len;
	auto readable = convert_to_readable(name);
	std::cout << "[ListenReuseNoB] Accepted Connection from: " << readable.ip_address << ":" << readable.port << std::endl;
	return std::make_unique<linux_data_socket>(epic_socket(accepted_socket), _protocol);
}

epic_socket reuse_connection_construct(raw_name_data data, protocol proto)
{
	auto readable = convert_to_readable(data);
	std::cout << "[DataReuseNoB] Creating Connection socket to: " << readable.ip_address << ":" << readable.port << std::endl;
	epic_socket conn_socket = epic_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (conn_socket.is_invalid())
		throw std::runtime_error(std::string("[DataReuseNoB] Failed to create nonblocking socket: ") + linux_error());

	conn_socket.set_socket_reuse();

	conn_socket.bind_socket(data, "[DataReuseNoB] Failed to bind");
	std::cout << "[DataReuseNoB] Successfully bound Data socket to: " << readable.ip_address << ":" << readable.port << std::endl;

	return conn_socket;
}

linux_reuse_nonblock_connection_socket::linux_reuse_nonblock_connection_socket(raw_name_data data, std::string ip_address, std::string port, protocol proto) : LinuxSocket(reuse_connection_construct(data, proto), proto)
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

	int sock_error = 0;
	socklen_t sock_error_size = sizeof(sock_error);
	if (getsockopt(_socket.handle, SOL_SOCKET, SO_ERROR, (char*)&sock_error, &sock_error_size) == SOCKET_ERROR)
		throw std::runtime_error(std::string("Failed to get socket error code with: ") + linux_error());

	std::cerr << "Socket has error code: " << sock_error << std::endl;

	return ConnectionStatus::FAILED;
}
#endif