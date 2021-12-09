#include "windows_socket.h"
#include "windows_socket.h"

#include <exception>
#include <string>
#include <array>
#include <iostream>

using namespace std;

string get_last_error()
{
    LPVOID lpMsgBuf;
    DWORD dw = WSAGetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    string message((char*)lpMsgBuf, (char*)lpMsgBuf + lstrlen((LPCTSTR)lpMsgBuf));

    LocalFree(lpMsgBuf);
    return message;
}

windows_listen_socket::windows_listen_socket()
{
    int iResult;
    struct addrinfo* result = NULL, *ptr = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0)
    {
        throw exception((string("Failed to create windows socket: getaddrinfo failed with") + to_string(iResult)).c_str());
    }

    _socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if (_socket == INVALID_SOCKET)
    {
        throw exception((string("Failed to create socket with WSA error: ") + get_last_error()).c_str());
    }

    iResult = bind(_socket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult != 0)
    {
        throw exception((string("Failed to bind to socket with WSA error: ") + get_last_error()).c_str());
    }
}

unique_ptr<IReceiverSocket> windows_listen_socket::accept_connection() {
    if (listen(_socket, SOMAXCONN) == SOCKET_ERROR)
        throw exception((string("Failed to listen with: ") + get_last_error()).c_str());

    SOCKET send_socket = INVALID_SOCKET;

    send_socket = accept(_socket, NULL, NULL);
    if (send_socket != INVALID_SOCKET)
    {
        return make_unique<windows_receive_socket>(send_socket);
    }
    return nullptr;
}

windows_listen_socket::~windows_listen_socket() {
    closesocket(_socket);
}

windows_send_socket::windows_send_socket(string peer_address) {
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    cout << "Resolving server with IP Address \'" << peer_address << '\'' << endl;

    // Resolve the server address and port
    int iResult = getaddrinfo(peer_address.c_str(), DEFAULT_PORT, &hints, &result);

    if (iResult != 0) {
        cerr << "Failed to resolve server: " << iResult << endl;
        throw exception((string("Failed to resolve peer address, error: ") + to_string(iResult)).c_str());
    }

    SOCKET ConnectSocket = INVALID_SOCKET;

    // As result is an addrinfo array, we'll just connect to the first
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {

        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET)
        {
            auto last_error = get_last_error();
            cerr << "Error creating client socket (socket()):" << last_error << endl;
            freeaddrinfo(result);
            throw exception((string("Failed to create client socket with: ") + last_error).c_str());
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
        cerr << "Failed to echo data back on send(): " << WSAGetLastError() << endl;
        return false;
    }
    return true;
}

windows_send_socket::~windows_send_socket() {
    if (_socket != INVALID_SOCKET && _socket != NULL)
        closesocket(_socket);
}

windows_receive_socket::windows_receive_socket(SOCKET send_socket) {
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
        cout << "Received " << iResult << " bytes" << endl;
    }
    else if (iResult == SOCKET_ERROR)
    {
        cerr << "Receiving data failed: " << get_last_error() << endl;
        return vector<char>();
    }
    recv_data.resize(iResult);
    return recv_data;
}

bool windows_receive_socket::has_data()
{
    array<WSAPOLLFD, 1> poll_states = { WSAPOLLFD{ _socket, POLLRDNORM, 0 } };
    int num_polled = WSAPoll(poll_states.data(), 1, 0);
    if (num_polled > 0)
        return poll_states[0].revents | POLLRDNORM;
    return false;
}

windows_receive_socket::~windows_receive_socket() {
    if (_socket != INVALID_SOCKET && _socket != NULL)
        closesocket(_socket);
}

void IWindowsSocket::shutdown()
{
    ::shutdown(_socket, SD_SEND);
}

windows_internet::windows_internet(WORD versionRequested)
{
    int iResult = WSAStartup(versionRequested, &_data);
    if (iResult != 0)
        throw exception((string("Winsock API initialization failed: ") + to_string(iResult)).c_str());
}

windows_internet::~windows_internet()
{
    WSACleanup();
}
