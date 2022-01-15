#include "socket.h"
#include "protocol.h"

#include <string>
#include <memory>
#include <exception>
#include <stdexcept>

#if defined(WIN32) | defined(_WIN64)
#include "windows_socket.h"

extern readable_ip_info convert_to_readable(raw_name_data data);
readable_ip_info windows_name_data::as_readable() const { return convert_to_readable(*this); }
#elif __linux__
#include "linux_socket.h"

extern readable_ip_info convert_to_readable(raw_name_data data);
readable_ip_info linux_name_data::as_readable() const { return convert_to_readable(*this); }
#endif

const std::string Sockets::ServerListenPort = "27069";
const std::string Sockets::ClientListenPort = "6969";


std::unique_ptr<IListenSocket> Sockets::CreateListenSocket(std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<windows_listen_socket>(port, input_protocol);
#elif __linux__
		return std::make_unique<linux_listen_socket>(port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<IDataSocket> Sockets::CreateConnectionSocket(std::string peer_ip, std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<windows_data_socket>(peer_ip, port, input_protocol);
#elif __linux__
		return std::make_unique<linux_data_socket>(peer_ip, port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<IReusableNonBlockingListenSocket> Sockets::CreateReusableNonBlockingListenSocket(std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<windows_reusable_nonblocking_listen_socket>(port, input_protocol);
#elif __linux__
		return std::make_unique<linux_reuse_nonblock_listen_socket>(port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<IReusableNonBlockingConnectSocket> Sockets::CreateReusableConnectSocket(raw_name_data data, std::string ip_address, std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<windows_reusable_nonblocking_connection_socket>(data, ip_address, port, input_protocol);
#elif __linux__
		return std::make_unique<linux_reuse_nonblock_connection_socket>(data, ip_address, port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<IDataSocket> Sockets::ConvertToDataSocket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<windows_data_socket>(std::move(old));
#elif __linux__
		return std::make_unique<linux_data_socket>(std::move(old));
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
	throw std::runtime_error("Failed to convert to datasocket");
}
