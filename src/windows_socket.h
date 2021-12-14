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

using namespace std;

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

class IWindowsSocket : virtual public ISocket
{
	protected:
	SOCKET _socket;

	virtual ~IWindowsSocket();

	public:
	void shutdown() override;
	peer_data get_peer_data() override;
	name_data get_sock_data() override;
};

class windows_listen_socket : public IWindowsSocket, public IListenSocket
{
	public:
	windows_listen_socket(string port);

	void listen() override;
	bool has_connection() override;
	unique_ptr<IDataSocket> accept_connection() override;
};

class windows_data_socket : public IWindowsSocket, public virtual IDataSocket
{
public:
	windows_data_socket(SOCKET source_socket);
	windows_data_socket(string peer_address, string peer_port);

	vector<char> receive_data() override;
	bool has_data() override;

	bool send_data(const vector<char>& data) override;
};

class windows_reusable_nonblocking_listen_socket : public IWindowsSocket, public IReusableNonBlockingListenSocket
{
public:
	windows_reusable_nonblocking_listen_socket(string port);

	void listen() override;
	bool has_connection() override;
	unique_ptr<IDataSocket> accept_connection() override;
};

class windows_reusable_nonblocking_connection_socket : public IWindowsSocket, public IReusableNonBlockingConnectSocket
{
public:
	windows_reusable_nonblocking_connection_socket(SOCKET socket); // Not sure if needed
	windows_reusable_nonblocking_connection_socket(name_data data);

	void connect(string ip_address, string port) override;
	ConnectionStatus has_connected() override;

	unique_ptr<IDataSocket> convert_to_datasocket() override;
};
#endif