#include "linux_platform.h"

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
	error += strerror(err_code);
	return error + ")";
}

std::string linux_error(int err_code)
{
	std::string error = "Err code: " + std::to_string(err_code) + " (";
	error += strerror(err_code);
	return error + ")";
}

readable_ip_info convert_to_readable(raw_name_data data)
{
	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &data.ipv4_addr().sin_addr, buf.data(), buf.size());

	if (!str) {
		throw_new_exception(std::string("Failed to convert sockaddr to string: ") + linux_error(), LINE_CONTEXT);
	}
		

	std::string address = str;

	std::string port = std::to_string(ntohs(data.ipv4_addr().sin_port));
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

LinuxPlatform::LinuxPlatform(PtopSocket&& socket) 
	: _socket(std::move(socket))
{ 
	update_name_info();

	if (_address == "Unassigned" || _address.empty() ||
		_port == "Unassigned" || _port.empty()) {
		throw_new_exception("failed to update name info", LINE_CONTEXT);
	}
}

void LinuxPlatform::update_name_info()
{
	auto name = get_myname_readable();
	_address = name.ip_address;
	_port = name.port;
}

void LinuxPlatform::update_endpoint_info()
{
	try
	{
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

void LinuxPlatform::update_endpoint_if_needed()
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

LinuxPlatform::~LinuxPlatform()
{
	std::cout << (_socket.is_valid() ? "Closing socket: " : "Closing dead socket that had: ") << _endpoint_address << ":" << _endpoint_port << std::endl;
}

void LinuxPlatform::shutdown()
{
}

readable_ip_info LinuxPlatform::get_peer_data() const
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

raw_name_data LinuxPlatform::get_peername_raw() const
{
	return _socket.get_peer_raw();
}

raw_name_data LinuxPlatform::get_myname_raw() const
{
	return _socket.get_name_raw();
}

readable_ip_info LinuxPlatform::get_peername_readable() const 
{
	return convert_to_readable(get_peername_raw());
}

readable_ip_info LinuxPlatform::get_myname_readable() const
{
	return convert_to_readable(get_myname_raw());
}

PtopSocket listen_construct(std::string port, protocol input_proto)
{
	std::cout << "[Listen] Create new Socket on port (with localhost): " << port << std::endl;
	auto listen_socket = PtopSocket(input_proto);

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

LinuxPlatformListener::LinuxPlatformListener(std::string port, protocol input_proto) : LinuxPlatform(listen_construct(port, input_proto))
{
}

void LinuxPlatformListener::listen()
{	
	std::cout << "[Listen] Socket now Listening (" << get_my_ip() << ":" << get_my_port() << ")" << std::endl;
	_socket.start_listening();
}

bool LinuxPlatformListener::has_connection()
{
	return _socket.poll_for(POLLRDNORM);
}

std::unique_ptr<IDataSocketWrapper> LinuxPlatformListener::accept_connection()
{
	std::cout << "[Listen] Socket Attempting to accept a connection" << std::endl;
	auto tmp = _socket.accept_data_socket();
	return std::make_unique<LinuxPlatformAnalyser>(std::move(tmp));
}

PtopSocket&& steal_construct(std::unique_ptr<INonBlockingConnector>&& old)
{
	std::cout << "[Data] Moving linux_reusable_nonblocking_connection_socket " << old->get_identifier_str() << " to a data_socket" << std::endl;
	LinuxReusableConnector& real_old = *dynamic_cast<LinuxReusableConnector*>(old.get());
	PtopSocket sup = real_old.release_socket();
	sup.set_non_blocking(false);
	return std::move(sup);
}

void LinuxPlatformAnalyser::process_socket_data()
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
			std::cout << "Socket " << get_identifier_str() << " Received " << "a Message of type: " << mt_to_string(new_message.Type) << " with length: " << new_message.Length << " bytes (+ " << sizeof(type) + sizeof(length) << " type/length bytes)" << std::endl;
		}
	}
	else
	{
		std::cout << "Received empty data from: " << get_identifier_str() << std::endl;
		recv_data.clear();
	}
}

LinuxPlatformAnalyser::LinuxPlatformAnalyser(std::unique_ptr<INonBlockingConnector>&& old) 
: LinuxPlatform(steal_construct(std::move(old)))
{
	update_endpoint_info();
}

LinuxPlatformAnalyser::LinuxPlatformAnalyser(PtopSocket&& socket) : LinuxPlatform(std::move(socket))
{
	std::cout << "[Data] Copy Constructor Data socket" << std::endl;
	update_endpoint_info();

	if (_socket.is_invalid())
		throw std::runtime_error("[Data] Invalid socket in Copy Constructor");
}

PtopSocket data_connect_construct(std::string peer_address, std::string peer_port, protocol ip_proto)
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
		throw_new_exception("Failed to get address info for: " + peer_address + ":" + peer_port + " with: " + linux_error(), LINE_CONTEXT);

	auto conn_socket = PtopSocket(ip_proto);
	conn_socket.connect(result->ai_addr, result->ai_addrlen);

	return conn_socket;
}

LinuxPlatformAnalyser::LinuxPlatformAnalyser(std::string peer_address, std::string peer_port, protocol proto) 
: LinuxPlatform(data_connect_construct(peer_address, peer_port, proto))
{
	update_endpoint_info();
}

Message LinuxPlatformAnalyser::receive_message()
{
	process_socket_data();

	if (_stored_messages.size() > 0)
	{
		auto tmp = _stored_messages.front();
		_stored_messages.pop();
		return tmp;
	}

	throw_new_exception("Failed to parse incoming data", LINE_CONTEXT);
}

bool LinuxPlatformAnalyser::has_message()
{
	return _socket.has_message();
}

bool LinuxPlatformAnalyser::send_data(const Message& message)
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

bool LinuxPlatformAnalyser::has_died()
{
	return _socket.has_died();
}

PtopSocket reuse_listen_construct(raw_name_data data, protocol proto)
{
	auto readable = data.as_readable();
	std::cout << "[ListenReuseNoB] Creating Reusable Listen Socket on: " << readable.ip_address << ":" << readable.port << std::endl;

	auto listen_socket = PtopSocket(proto);

	if (listen_socket.is_invalid())
		throw std::runtime_error("[ListenReuseNoB] " + readable.ip_address + ":" + readable.port + " Failed to create reusable nonblocking listen socket: " + linux_error());

	listen_socket.set_non_blocking(true);
	listen_socket.set_socket_reuse();

	listen_socket.bind_socket(data);

	return listen_socket;
}

LinuxReusableListener::LinuxReusableListener(raw_name_data data, protocol proto) 
: LinuxPlatform(reuse_listen_construct(data, proto))
{
	
}

void LinuxReusableListener::listen()
{
	std::cout << "[ListenReuseNoB] Now Listening on: " << get_my_ip() << ":" << get_my_port() << std::endl;
	_socket.listen(4);
}

bool LinuxReusableListener::has_connection()
{
	return _socket.has_connection();
}

std::unique_ptr<IDataSocketWrapper> LinuxReusableListener::accept_connection()
{
	std::cout << "[ListenReuseNoB] Accepting Connection..." << std::endl;

	auto new_sock = _socket.accept_data_socket();
	return std::make_unique<LinuxPlatformAnalyser>(std::move(new_sock));
}

PtopSocket reuse_connection_construct(raw_name_data data, protocol proto)
{
	auto readable = convert_to_readable(data);
	std::cout << "[DataReuseNoB] Creating Connection socket bound to: " << readable.ip_address << ":" << readable.port << std::endl;
	auto conn_socket = PtopSocket(proto);

	if (conn_socket.is_invalid())
		throw_new_exception("[DataReuseNoB] Failed to create nonblocking socket: " + linux_error(), LINE_CONTEXT);

	conn_socket.set_non_blocking(true);
	conn_socket.set_socket_reuse();

	conn_socket.bind_socket(data, "[DataReuseNoB] Failed to bind");
	std::cout << "[DataReuseNoB] Successfully bound Data socket to: " << readable.ip_address << ":" << readable.port << std::endl;

	return conn_socket;
}

LinuxReusableConnector::LinuxReusableConnector(raw_name_data data, std::string ip_address, std::string port, protocol proto) 
: LinuxPlatform(reuse_connection_construct(data, proto))
{
	// if tcp?
	try
	{
		this->connect(ip_address, port);
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

void LinuxReusableConnector::connect(std::string ip_address, std::string port)
{
	try
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
			throw_new_exception("Failed to getaddrinfo, error: " + std::to_string(iResult), LINE_CONTEXT);

		if (results == nullptr)
			throw_new_exception(("No possible sockets found for '") + ip_address + ":" + port + "'", LINE_CONTEXT);

		_socket.connect(results->ai_addr, results->ai_addrlen);
		std::cout << "[DataReuseNoB] Successfully BEGUN Connection to: " << ip_address << ":" << port << std::endl;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

ConnectionStatus LinuxReusableConnector::has_connected()
{
	try
	{
		if (_socket.is_invalid())
			return ConnectionStatus::FAILED;

		if (_socket.select_for(select_for::WRITE))
		{
			auto sock_error = _socket.get_socket_option<int>(SO_ERROR);
			if (sock_error != 0 && sock_error != EAGAIN && sock_error != EINPROGRESS)
			{
				std::cerr << LINE_CONTEXT << " [DataReuseNoB] Socket failed to connect with: " << linux_error(sock_error) << std::endl;
				return ConnectionStatus::FAILED;
			}

			update_endpoint_if_needed();
			return ConnectionStatus::SUCCESS;
		}


		if (!_socket.select_for(select_for::EXCEPT))
			return ConnectionStatus::PENDING;

		auto sock_error = _socket.get_socket_option<int>(SO_ERROR);

		std::cerr << LINE_CONTEXT << " [DataReuseNoB] Socket failed to connect with: " << linux_error(sock_error) << std::endl;

		return ConnectionStatus::FAILED;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}
#endif