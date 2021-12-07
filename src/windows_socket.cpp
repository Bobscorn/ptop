#include "windows_socket.h"

#include <exception>
#include <string>

using namespace std;

windows_listen_socket::windows_listen_socket()
{
    int iResult;
    struct addrinfo* result = NULL, *ptr = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &results);
    if (iResult != 0)
    {
        throw exception((string("Failed to create windows socket: getaddrinfo failed with") + iResult).c_str());
    }

    _socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if (_socket == INVALID_SOCKET)
    {
        throw exception((string("Failed to create socket with WSA error: ") + ).c_str());
    }
}