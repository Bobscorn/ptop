#include "socket.h"

#include <string>
#include <memory>

#ifdef WIN32
#include "windows_socket.h"
#elif __linux__
#include "linux_socket.h"
#endif

const std::string Sockets::ServerListenPort = "27069";
const std::string Sockets::ClientListenPort = "6969";


std::unique_ptr<IListenSocket> Sockets::CreateListenSocket(std::string port)
{
#ifdef WIN32
	return std::make_unique<windows_listen_socket>(port);
#elif __linux__
	return std::make_unique<linux_listen_socket>(port);
#endif
}

std::unique_ptr<IDataSocket> Sockets::CreateConnectionSocket(std::string peer_ip, std::string port)
{
#ifdef WIN32
	return std::make_unique<windows_data_socket>(peer_ip, port);
#elif __linux__
	return std::make_unique<linux_data_socket>(peer_ip, port);
#endif
}

std::unique_ptr<IReusableNonBlockingListenSocket> Sockets::CreateReusableNonBlockingListenSocket(std::string port)
{
#ifdef WIN32
	return std::make_unique<windows_reusable_nonblocking_listen_socket>(port);
#elif __linux__
	return std::make_unique<linux_reuse_nonblock_listen_socket>(port);
#endif
}

std::unique_ptr<IReusableNonBlockingConnectSocket> Sockets::CreateReusableConnectSocket(raw_name_data data, std::string ip_address, std::string port)
{
#ifdef WIN32
	return std::make_unique<windows_reusable_nonblocking_connection_socket>(data, ip_address, port);
#elif __linux__
	return std::make_unique<linux_reuse_nonblock_connection_socket>(data, ip_address, port);
#endif
}

std::unique_ptr<IDataSocket> Sockets::ConvertToDataSocket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old)
{
#ifdef WIN32
	return std::make_unique<windows_data_socket>(std::move(old));
#elif __linux__
	return std::make_unique<linux_data_socket>(std::move(old));
#endif
}

#define DO_MSG_TYPE_LOGGING
#ifdef DO_MSG_TYPE_LOGGING
#include <iostream>

#include "message.h"
void log_msg(const Message& mess, bool sending, ISocket& sock)
{
	std::cout << "Socket " << sock.get_identifier_str() << (sending ? "Sending " : "Received ") << "a Message of type: " << mt_to_string(mess.Type) << " with length: " << mess.Length << " bytes" << std::endl;
}
#else
void log_msg(const std::vector<char>& data, bool sending, ISocket& sock)
{

}
#endif
