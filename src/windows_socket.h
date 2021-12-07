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
#endif

#include <memory>


class windows_listen_socket : IListenSocket
{
	SOCKET _socket;

public:
	windows_listen_socket();
	~windows_listen_socket();

	ISenderSocket* accept_connection() override;
};

class windows_send_socket : ISenderSocket
{
public:
	windows_send_socket();
	~windows_send_socket();

	bool send_data(const vector<char>& data) override;
};

class windows_receive_socket : IReceiverSocket
{
public:
	windows_receive_socket();
	~windows_receive_socket();

	vector<char> receive_data() override;
};