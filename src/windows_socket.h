#pragma once

#include "socket.h"

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

class windows_internet
{
	protected:
	WSAData _data;

	public:
	windows_internet(WORD versionRequested);
	~windows_internet();
};

class IWindowsSocket : public virtual ISocket
{
	protected:
	SOCKET _socket;

	public:
	void shutdown() override;
};

class windows_listen_socket : public IWindowsSocket, public IListenSocket
{
	public:
	windows_listen_socket();
	~windows_listen_socket();

	std::unique_ptr<IReceiverSocket> accept_connection() override;
};

class windows_send_socket : public IWindowsSocket, public ISenderSocket
{
	public:
	windows_send_socket(string peer_ip);
	~windows_send_socket();

	bool send_data(const vector<char>& data) override;
};

class windows_receive_socket : public IWindowsSocket, public IReceiverSocket
{
	public:
	windows_receive_socket(SOCKET send_socket);
	~windows_receive_socket();

	vector<char> receive_data() override;
	bool has_data() override;
};