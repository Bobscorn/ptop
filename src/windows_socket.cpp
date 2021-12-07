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
        throw exception((string("Failed to create socket with WSA error: ") + WSAGetLastError()).c_str());
    }

    iResult = bind(_socket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult != 0)
    {
        throw exception((string("Failed to bind to socket with WSA error: ") + WSAGetLastError()).c_str());
    }
}

ISenderSocket* windows_listen_socket::accept_connection() {
    SOCKET send_socket = INVALID_SOCKET;

    send_socket = accept(_socket, NULL, NULL);
    if (send_socket != INVALID_SOCKET)
    {
        return new windows_receive_socket(send_socket);
    }
    return nullptr;
}

windows_listen_socket::~windows_listen_socket() {
    closesocket(_socket);
}

windows_send_socket::windows_send_socket(string peer_ip) {
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::cout << "Resolving server with IP Address " << peer_address << '\'' << std::endl;

    // Resolve the server address and port
    iResult = getaddrinfo(peer_address.c_str(), DEFAULT_PORT, &hints, &result);

    if (iResult != 0) {
        std::cerr << "Failed to resolve server: " << iResult << std::endl;
        throw exception((string("Failed to resolve with error: ") + iResult).c_str());
    }

    SOCKET ConnectSocket = INVALID_SOCKET;

    // As result is an addrinfo array, we'll just connect to the first
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {

        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET)
        {
            auto last_error = WSAGetLastError();
            std::cerr << "Error creating client socket (socket()):" << last_error << std::endl;
            freeaddrinfo(result);
            throw exception((string("Failed to create client socket with: ") + last_error));
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }



    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        throw exception("No sockets successfully connected to peer");
    }
    _socket = ConnectSocket;
}

bool windows_send_socket::send_data(const vector<char>& data) {
    int iSendResult = send(_socket, data.data(), data.size(), 0);
    if (iSendResult == SOCKET_ERROR)
    {
        std::cerr << "Failed to echo data back on send(): " << WSAGetLastError() << std::endl;
        return false;
    }
    return true;
}

windows_send_socket::~windows_send_socket() {
    if (_socket != INVALID_SOCKET && _socket != NULL)
        closesocket(_socket);
}

windows_receive_socket::windows_receive_socket(SOCKET _socket) {
    _socket = send_socket;
    if (_socket == INVALID_SOCKET)
    {
        throw exception("Invalid Socket");
    }
}

vector<char> windows_receive_socket::receive_data() {
    vector<char> recv_data = vector<char>(500, (char)0);
    int iResult = recv(_socket, recv_data.data(), recv_data.size(), 0);
    if (iResult > 0)
    {
        cout << "Received " << iResult << " bytes" << std::endl;
    }
}

windows_receive_socket::~windows_receive_socket() {
    if (_socket != INVALID_SOCKET && _socket != NULL)
        closesocket(_socket);
}