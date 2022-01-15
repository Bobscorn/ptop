#include "sock.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

extern std::string get_last_error();
extern std::string get_win_error(DWORD);

void throw_if_socket_error(int val, std::string error_message)
{
	if (val == SOCKET_ERROR)
	{
		auto last_err = WSAGetLastError();

		if (last_err != WSAEWOULDBLOCK) {
			auto input = error_message + " with: " + get_win_error(last_err);
			throw print_new_exception(input, CONTEXT);
		}
	}
}

epic_socket::~epic_socket()
{
	if (_handle != REALLY_INVALID_SOCKET)
	{
		closesocket(_handle);
		_handle = REALLY_INVALID_SOCKET;
	}
}

epic_socket& epic_socket::set_non_blocking(bool value)
{
	u_long blockMode = value;
	int result = ioctlsocket(_handle, FIONBIO, &blockMode);

	if (result == SOCKET_ERROR) {
		auto input = "Failed to set non blocking mode: " + get_last_error();
		throw print_new_exception(input, CONTEXT);
		
	}
}