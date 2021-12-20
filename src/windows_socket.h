#pragma once

#include "socket.h"

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include <memory>
#include <string>

#pragma warning( push )
#pragma warning(disable : 4250)

/// <summary>
/// An RAII Wrapper over WSAStartup and WSACleanup, called in constructors and destructors
/// </summary>
class windows_internet
{
	protected:
	WSAData _data;

	public:
	windows_internet(WORD versionRequested);
	~windows_internet();
};

readable_ip_info convert_to_readable(raw_name_data);

class WindowsSocket : virtual public ISocket
{
protected:
	WindowsSocket(SOCKET socket);
	SOCKET _socket;
	std::string _address;
	std::string _port;
	std::string _endpoint_address;
	std::string _endpoint_port;

	void update_name_info();
	void update_endpoint_info();

	virtual ~WindowsSocket();

public:
	void shutdown() override;
	readable_ip_info get_peer_data() override;
	raw_name_data get_sock_data() override;
	raw_name_data get_peername_raw() override;
	raw_name_data get_myname_raw() override;
	readable_ip_info get_peername_readable() override;
	readable_ip_info get_myname_readable() override;
	std::string get_my_ip() override;
	std::string get_my_port() override;
	std::string get_endpoint_ip() override;
	std::string get_endpoint_port() override;

	inline SOCKET get_socket() const { return _socket; }
};

class windows_listen_socket : public WindowsSocket, public IListenSocket
{
	public:
	windows_listen_socket(std::string port);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocket> accept_connection() override;
};

class windows_data_socket : public WindowsSocket, public virtual IDataSocket
{
public:
	windows_data_socket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old);
	windows_data_socket(SOCKET source_socket);
	windows_data_socket(std::string peer_address, std::string peer_port);

	std::vector<char> receive_data() override;
	bool has_data() override;

	bool send_data(const std::vector<char>& data) override;
};

class windows_reusable_nonblocking_listen_socket : public WindowsSocket, public IReusableNonBlockingListenSocket
{
public:
	windows_reusable_nonblocking_listen_socket(std::string port);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocket> accept_connection() override;
};

class windows_reusable_nonblocking_connection_socket : public WindowsSocket, public IReusableNonBlockingConnectSocket
{
public:
	windows_reusable_nonblocking_connection_socket(raw_name_data data);

	void connect(std::string ip_address, std::string port) override;
	ConnectionStatus has_connected() override;
};

#pragma warning(pop)

#endif