#include "socket.h"
#include "protocol.h"

#include <string>
#include <memory>
#include <exception>
#include <stdexcept>

#ifdef WIN32
#include "windows_socket.h"
#elif __linux__
#include "linux_socket.h"
#endif

const std::string Sockets::ServerListenPort = "27069";
const std::string Sockets::ClientListenPort = "6969";


std::unique_ptr<IListenSocket> Sockets::CreateListenSocket(std::string port, protocol input_protocol)
{
#ifdef WIN32
	return std::make_unique<windows_listen_socket>(port, input_protocol);
#elif __linux__
	return std::make_unique<linux_listen_socket>(port, input_protocol);
#endif
}

std::unique_ptr<IDataSocket> Sockets::CreateConnectionSocket(std::string peer_ip, std::string port, protocol input_protocol)
{
#ifdef WIN32
	return std::make_unique<windows_data_socket>(peer_ip, port, input_protocol);
#elif __linux__
	return std::make_unique<linux_data_socket>(peer_ip, port, input_protocol);
#endif
}

std::unique_ptr<IReusableNonBlockingListenSocket> Sockets::CreateReusableNonBlockingListenSocket(std::string port, protocol input_protocol)
{
#ifdef WIN32
	return std::make_unique<windows_reusable_nonblocking_listen_socket>(port, input_protocol);
#elif __linux__
	return std::make_unique<linux_reuse_nonblock_listen_socket>(port, input_protocol);
#endif
}

std::unique_ptr<IReusableNonBlockingConnectSocket> Sockets::CreateReusableConnectSocket(raw_name_data data, std::string ip_address, std::string port, protocol input_protocol)
{
#ifdef WIN32
	return std::make_unique<windows_reusable_nonblocking_connection_socket>(data, ip_address, port, input_protocol);
#elif __linux__
	return std::make_unique<linux_reuse_nonblock_connection_socket>(data, ip_address, port, input_protocol);
#endif
}

std::unique_ptr<IDataSocket> Sockets::ConvertToDataSocket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old)
{
#ifdef WIN32
	if (auto reuse_nb = dynamic_cast<windows_reusable_nonblocking_connection_socket*>(old.get()))
		return std::make_unique<windows_data_socket>(std::move(old), reuse_nb->get_protocol());
#elif __linux__
	if (auto reuse_nb = dynamic_cast<linux_reuse_nonblock_connection_socket*>(old.get()))
		return std::make_unique<linux_data_socket>(std::move(old), reuse_nb->get_protocol());
#endif
	throw std::runtime_error("Failed to convert to datasocket");
}
