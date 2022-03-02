#include "ptop_socket.h"
#include "message.h"
#include "error.h"

#if defined(WIN32) | defined(_WIN64)
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

void throw_if_socket_error(int val, std::string error_message, std::string line_context)
{
	if (val == SOCKET_ERROR)
	{
		auto last_err = WSAGetLastError();

		if (last_err != WSAEWOULDBLOCK) {
			auto input = error_message + " with: " + get_win_error(last_err);
			throw_new_exception(input, line_context);
		}
	}
}

std::string socket_error_to_string(int err)
{
	return get_win_error(err);
}

PtopSocket::~PtopSocket()
{
	if (is_valid())
	{
		auto lock = std::unique_lock(*_handle_mutex);
		std::cout << "Closing socket" << std::endl;
		closesocket(*_handle);
		*_handle = REALLY_INVALID_SOCKET;
		_handle = nullptr;
	}
	if (_thread_die)
	{
		*_thread_die = true;
		_polling_thread.join();
	}
}

PtopSocket& PtopSocket::set_non_blocking(bool value)
{
	u_long blockMode = value;
	int result = ioctlsocket(*_handle, FIONBIO, &blockMode);

	throw_if_socket_error(result, "Failed to set non blocking state", LINE_CONTEXT);
	return *this;
}
#endif