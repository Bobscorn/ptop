#include "windows_socket.h"

#include <exception>
#include <string>
#include <array>
#include <iostream>

#include "message.h"
#include "loop.h"
#include "protocol.h"

#define AF_FAM AF_INET

WindowsSocket::WindowsSocket(SOCKET socket, protocol input_protocol) 
    : _socket(socket)
    , _protocol(input_protocol)
{ 
	try
	{
        update_name_info();

	    if (_address == "Unassigned" || _address.empty() ||
		    _port == "Unassigned" || _port.empty()) {
		    throw PRINT_MSG_LINE("failed to update name info");
	    }
	}
	catch (...)
	{
        std::throw_with_nested(PRINT_MSG_LINE("failed instantiating a WindowsSocket"));
	}
	
}

std::string get_last_error()
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

    std::string message((char*)lpMsgBuf, (char*)lpMsgBuf + lstrlen((LPCTSTR)lpMsgBuf));

    LocalFree(lpMsgBuf);
    return message;
}

std::string get_win_error(DWORD word)
{
    LPVOID lpMsgBuf;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        word,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    std::string message((char*)lpMsgBuf, (char*)lpMsgBuf + lstrlen((LPCTSTR)lpMsgBuf));

    LocalFree(lpMsgBuf);
    return message;
}


readable_ip_info convert_to_readable(raw_name_data name)
{
    std::vector<char> name_buf(100, '0');
    const char* str = inet_ntop(AF_INET, &name.ipv4_addr().sin_addr, name_buf.data(), name_buf.size());
    if (!str)
        throw PRINT_MSG_LINE(std::string("Failed to convert sockaddr info to human readable address: ") + get_last_error());

    std::string port_str = std::to_string(htons(name.ipv4_addr().sin_port));

    readable_ip_info out_data;
    out_data.ip_address = std::string(str);
    out_data.port = std::move(port_str);
    return out_data;
}

void WindowsSocket::update_name_info()
{
    try
    {
        auto name = get_myname_readable();
        _address = name.ip_address;
        _port = name.port;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

void WindowsSocket::update_endpoint_info()
{
    try
    {
        auto name = get_peername_readable();
        _endpoint_address = name.ip_address;
        _endpoint_port = name.port;
        _endpoint_assigned = true;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_MSG_LINE("failed to update_endpoint_info"));
    }
}

void WindowsSocket::update_endpoint_if_needed()
{
    if (!_endpoint_assigned)
    {
        update_endpoint_info();
    }
}

readable_ip_info WindowsSocket::get_peer_data() const
{
    try
    {
        sockaddr_in peer_name;
        socklen_t peer_size = sizeof(peer_name);
        int n = getpeername(_socket, (sockaddr*)&peer_name, &peer_size);

        std::vector<char> buf{ 50, '0', std::allocator<char>() };
        const char* str = inet_ntop(AF_INET, &peer_name.sin_addr, buf.data(), buf.size());
        if (!str)
            throw std::runtime_error(std::string("Failed to convert sockaddr to string: ") + get_last_error());

        std::string address = str;

        std::string port = std::to_string(peer_name.sin_port);
        readable_ip_info out;
        out.ip_address = address;
        out.port = port;
        return out;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

raw_name_data WindowsSocket::get_peername_raw() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getpeername(_socket, (sockaddr*)&peer_name, &peer_size);
    if (n != 0)
        throw PRINT_MSG_LINE(std::string("[Socket] Failed to getpeername with: ") + get_last_error());

    raw_name_data raw_data;
    raw_data.name = *(sockaddr*)&peer_name;
    raw_data.name_len = peer_size;
    return raw_data;
}

raw_name_data WindowsSocket::get_myname_raw() const
{
    try
    {
        sockaddr_in peer_name;
        socklen_t peer_size = sizeof(peer_name);
        int n = getsockname(_socket, (sockaddr*)&peer_name, &peer_size);
        if (n != 0)
            throw PRINT_MSG_LINE(std::string("[Socket] Failed to getsockname with: ") + get_last_error());

        raw_name_data raw_data;
        raw_data.name = *(sockaddr*)&peer_name;
        raw_data.name_len = peer_size;
        return raw_data;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

readable_ip_info WindowsSocket::get_peername_readable() const
{
    try
    {
        return convert_to_readable(get_peername_raw());
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

readable_ip_info WindowsSocket::get_myname_readable() const
{
    try
    {
        return convert_to_readable(get_myname_raw());
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

SOCKET construct_windowslistensocket(std::string port, protocol input_protocol) {
    try
    {
        std::cout << "[Listen] Create new Socket on port (with localhost): " << port << std::endl;
        int iResult;
        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = input_protocol.get_ai_family();
        hints.ai_socktype = input_protocol.get_ai_socktype();
        hints.ai_protocol = input_protocol.get_ai_protocol();
        hints.ai_flags = input_protocol.get_ai_flags();

        iResult = getaddrinfo(NULL, port.c_str(), &hints, &result);
        if (iResult != 0)
        {
            throw std::exception((std::string("[Listen] Failed to create windows socket: getaddrinfo failed with") + std::to_string(iResult)).c_str());
        }

        SOCKET ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

        if (ConnectSocket == INVALID_SOCKET)
        {
            throw std::exception((std::string("[Listen] Failed to create socket with WSA error: ") + get_last_error()).c_str());
        }

        std::cout << "Binding..." << std::endl;
        iResult = bind(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
        if (iResult != 0)
        {
            throw std::exception((std::string("Failed to bind to socket with WSA error: ") + get_last_error()).c_str());
        }
        return ConnectSocket;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

windows_listen_socket::windows_listen_socket(std::string port, protocol input_protocol) : WindowsSocket(
    construct_windowslistensocket(port, input_protocol), input_protocol) 
{
    std::cout << "[Listen] Post Bind Check: Bound to: " << get_my_ip() << ":" << get_my_port() << std::endl;
}

void windows_listen_socket::listen()
{
    std::cout << "[Listen] Socket now Listening (" << get_my_ip() << ":" << get_my_port() << ")" << std::endl;
    if (::listen(_socket, SOMAXCONN) == SOCKET_ERROR)
        throw PRINT_MSG_LINE(std::string("Socket ") + get_identifier_str() + " Failed to listen with: " + get_last_error());
}

bool windows_listen_socket::has_connection()
{
    std::array<WSAPOLLFD, 1> poll_states = { WSAPOLLFD{ _socket, POLLRDNORM, 0 } };
    int num_polled = WSAPoll(poll_states.data(), 1, 0);
    if (num_polled > 0)
        return poll_states[0].revents | POLLRDNORM;
    return false;
}

std::unique_ptr<IDataSocket> windows_listen_socket::accept_connection() {
    std::cout << "[Listen] " << get_identifier_str() << " Socket Attempting to accept a connection" << std::endl;
    sockaddr_in endpoint_addr;
    socklen_t endpoint_len = sizeof(endpoint_addr);
    SOCKET send_socket = accept(_socket, (sockaddr*)&endpoint_addr, &endpoint_len);

    if (send_socket != INVALID_SOCKET)
    {
        auto raw = raw_name_data{ *(sockaddr*)&endpoint_addr, endpoint_len };
        auto readable = convert_to_readable(raw);
        std::cout << "[Listen] " << get_identifier_str() << " Accepted a connection : " << readable.ip_address << " : " << readable.port << std::endl;
        return std::make_unique<windows_data_socket>(send_socket);
    }
    return nullptr;
}

SOCKET construct_windows_data_socket(std::string peer_address, std::string peer_port, protocol input_protocol) {
    try
    {
        std::cout << "[Data] Creating a Windows Data Socket connecting to: " << peer_address << ":" << peer_port << std::endl;
        struct addrinfo* result = NULL,
            *ptr = NULL,
            hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = input_protocol.get_ai_family();
        hints.ai_socktype = input_protocol.get_ai_socktype();
        hints.ai_protocol = input_protocol.get_ai_protocol();

        // Resolve the server address and port
        int iResult = getaddrinfo(peer_address.c_str(), peer_port.c_str(), &hints, &result);

        if (iResult != 0) {
            std::cerr << "Failed to resolve server: " << iResult << std::endl;
            throw std::exception((std::string("Failed to resolve peer address, error: ") + std::to_string(iResult)).c_str());
        }

        SOCKET ConnectSocket = INVALID_SOCKET; //the other one place we need this

        // Go through all available sockets and try to connect
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
        {

            ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (ConnectSocket == INVALID_SOCKET)
            {
                auto last_error = get_last_error();
                std::cerr << "[Data] Error creating client socket (socket()):" << last_error << std::endl;
                freeaddrinfo(result);
                throw std::exception((std::string("[Data] Failed to create data socket with: ") + last_error).c_str());
            }

            // Connect to server.
            iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
            if (iResult == SOCKET_ERROR) {
                closesocket(ConnectSocket);
                ConnectSocket = INVALID_SOCKET; //the one place we need this
                continue;
            }
            auto readable = convert_to_readable(*ptr->ai_addr);
            std::cout << "[Data] Successfully connected to: " << readable.ip_address << ":" << readable.port << std::endl;
            break;
        }



        freeaddrinfo(result);

        if (ConnectSocket == INVALID_SOCKET) {
            throw std::exception("[Data] No sockets successfully connected to peer");
        }
        return ConnectSocket;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

windows_data_socket::windows_data_socket(std::string peer_address, std::string peer_port, protocol input_protocol) : WindowsSocket(
    construct_windows_data_socket(peer_address, peer_port, input_protocol), input_protocol) 
{
    update_endpoint_info();
}

bool windows_data_socket::send_data(const Message& message)
{
    log_msg(message, true, *this);
    auto bytes = message.to_bytes();
    int iSendResult = send(_socket, bytes.data(), (int)bytes.size(), 0);
    if (iSendResult == SOCKET_ERROR)
    {
        std::cerr << "Failed to send data with: " << WSAGetLastError() << std::endl;
        return false;
    }
    _sent_bytes += bytes.size();
    return true;
}

SOCKET windows_data_socket_steal_construct(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old)
{
    try
    {
        std::cout << "[Data] Moving windows_reusable_nonblocking_connection_socket " << old->get_identifier_str() << " to a data_socket" << std::endl;
        windows_reusable_nonblocking_connection_socket& real_old = *dynamic_cast<windows_reusable_nonblocking_connection_socket*>(old.get());
        u_long blockMode = 1;
        int iResult = ioctlsocket(real_old.get_socket(), FIONBIO, &blockMode);
        if (iResult == SOCKET_ERROR)
            throw std::exception((std::string("Failed to convert reusable non blocking connection socket to regular socket with:") + get_last_error()).c_str());
        SOCKET ConnectSocket = real_old.get_socket();
        real_old.clear_socket();
        old = nullptr;
        return ConnectSocket;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

void windows_data_socket::process_socket_data()
{
    std::cout << "[Data] Begin Receive " << get_identifier_str() << std::endl;
    std::vector<char> recv_data = std::vector<char>(500, (char)0);
    int iResult = recv(_socket, recv_data.data(), (int)recv_data.size(), 0);
    if (iResult > 0)
    {
        recv_data.resize(iResult);
        _seen_data += iResult;

        int data_read = 0;

        while ((recv_data.size() - data_read) > 0)
        {
            MESSAGE_TYPE type;
            MESSAGE_LENGTH_T length;
            std::vector<char> data;

            if (!try_read_data(recv_data.data(), data_read, recv_data.size(), type))
            {
                std::cerr << "Socket " << get_identifier_str() << " Failed to process socket data into a message" << std::endl;
                return;
            }
            if (!try_read_data(recv_data.data(), data_read, recv_data.size(), length))
            {
                std::cerr << "Socket " << get_identifier_str() << " Failed to process socket data into a message" << std::endl;
                return;
            }
            data = std::vector<char>(recv_data.data() + data_read, recv_data.data() + data_read + length);
            data_read += length;
            auto new_message = Message{ type, length, std::move(data) };
            _stored_messages.push(new_message);
            log_msg(new_message, false, *this);
        }
    }
    else if (iResult == SOCKET_ERROR)
    {
        std::cerr << "Receiving data failed: " << get_last_error() << std::endl;
    }
    else
    {
        std::cout << "Received empty data from: " << get_identifier_str() << std::endl;
        recv_data.clear();
    }
}

windows_data_socket::windows_data_socket(std::unique_ptr<IReusableNonBlockingConnectSocket>&& old, protocol input_protocol) : WindowsSocket(
    windows_data_socket_steal_construct(std::move(old)), input_protocol)
{
    update_endpoint_info();
}

windows_data_socket::windows_data_socket(SOCKET source_socket, protocol input_protocol) : WindowsSocket(source_socket, input_protocol)
{
    try
    {
        auto readable = get_peername_readable();
        std::cout << "[Data] Copy Constructor Data socket with endpoint: " << readable.ip_address << ":" << readable.port << std::endl;
        if (_socket == INVALID_SOCKET)
        {
            throw std::exception("Invalid Socket Given");
        }
        update_endpoint_info();
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}

Message windows_data_socket::receive_message() {
    process_socket_data();

    if (_stored_messages.size() > 0)
    {
        auto tmp = _stored_messages.front();
        _stored_messages.pop();
        return tmp;
    }

    return Message::null_message;
}

bool windows_data_socket::has_message()
{
    std::array<WSAPOLLFD, 1> poll_states = { WSAPOLLFD{ _socket, POLLRDNORM, 0 } };
    int num_polled = WSAPoll(poll_states.data(), 1, 0);
    if (num_polled > 0)
        return poll_states[0].revents | POLLRDNORM;
    return false;
}

WindowsSocket::~WindowsSocket()
{
    if (_socket != INVALID_SOCKET && _socket != NULL)
    {
        std::cout << "Closing socket: " << get_identifier_str() << std::endl;
        closesocket(_socket);
    }
}

void WindowsSocket::shutdown()
{
    ::shutdown(_socket, SD_SEND);
}

windows_internet::windows_internet(WORD versionRequested)
{
    int iResult = WSAStartup(versionRequested, &_data);
    if (iResult != 0)
        throw PRINT_MSG_LINE("Winsock API initialization failed: " + std::to_string(iResult));
    std::cout << "Winsock has been started" << std::endl;
}

windows_internet::~windows_internet()
{
    WSACleanup();
    std::cout << "Winsock has been cleaned" << std::endl;
}

SOCKET windows_reuse_nb_listen_construct(std::string port)
{
    try
    {
        std::cout << "[ListenReuseNoB] Creating Reusable Listen Socket on (localhost): " << port << std::endl;
        int iResult;
        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        iResult = getaddrinfo(NULL, port.c_str(), &hints, &result);
        if (iResult != 0)
        {
            throw std::exception((std::string("[ListenReuseNoB] Failed to create windows socket: getaddrinfo failed with") + std::to_string(iResult)).c_str());
        }

        SOCKET ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

        if (ConnectSocket == INVALID_SOCKET)
        {
            throw std::exception((std::string("Failed to create socket with WSA error: ") + get_last_error()).c_str());
        }

        int reuseVal = 1;
        iResult = setsockopt(ConnectSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseVal, sizeof(reuseVal));
        if (iResult == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            throw std::exception("Failed to set socket as SO_REUSEADDR");
        }

        u_long blockMode = 1;
        iResult = ioctlsocket(ConnectSocket, FIONBIO, &blockMode);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            throw std::exception("Failed to set socket as non-blocking");
        }

        iResult = bind(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
        if (iResult == SOCKET_ERROR)
        {
            auto last_err = get_last_error();
            closesocket(ConnectSocket);
            throw std::exception((std::string("Failed to bind to socket with WSA error: ") + last_err).c_str());
        }
        return ConnectSocket;
    }
    catch (...)
    {
        std::throw_with_nested(PRINT_LINE);
    }
}
windows_reusable_nonblocking_listen_socket::windows_reusable_nonblocking_listen_socket(std::string port, protocol input_protocol) : WindowsSocket(
    windows_reuse_nb_listen_construct(port), input_protocol)
{}

void windows_reusable_nonblocking_listen_socket::listen()
{
    std::cout << "[ListenReuseNoB] Now Listening on: " << get_my_ip() << ":" << get_my_port() << std::endl;
    if (::listen(_socket, SOMAXCONN) == SOCKET_ERROR)
        throw PRINT_MSG_LINE("Socket: " + get_identifier_str() + " Failed to listen with : " + get_last_error());
}

bool windows_reusable_nonblocking_listen_socket::has_connection()
{
    fd_set read_sockets;
    read_sockets.fd_count = 1;
    read_sockets.fd_array[0] = _socket;
    TIMEVAL timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;

    int iResult = select(0, &read_sockets, NULL, NULL, &timeout);

    if (iResult == SOCKET_ERROR)
        throw std::exception((std::string("Failed to select on reusable listen socket with: ") + get_last_error()).c_str());

    return iResult;
}

std::unique_ptr<IDataSocket> windows_reusable_nonblocking_listen_socket::accept_connection()
{
    std::cout << "[ListenReuseNoB] Accepting Connection..." << std::endl;
    sockaddr_in endpoint_addr;
    socklen_t endpoint_len = 0;
    SOCKET accepted_socket = accept(_socket, (sockaddr*)&endpoint_addr, &endpoint_len);

    if (accepted_socket == INVALID_SOCKET)
        return nullptr;
    raw_name_data name;
    name.name = *(sockaddr*)&endpoint_addr;
    name.name_len = endpoint_len;
    auto readable = convert_to_readable(name);
    std::cout << "[ListenReuseNoB] Accepted Connection from: " << readable.ip_address << ":" << readable.port << std::endl;
    return std::make_unique<windows_data_socket>(accepted_socket);
}

SOCKET windows_reuse_nb_construct(raw_name_data name)
{
    auto readable = convert_to_readable(name);
    std::cout << "[DataReuseNoB] Creating Connection socket bound to: " << readable.ip_address << ":" << readable.port << std::endl;

    SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (ConnectSocket == INVALID_SOCKET)
    {
        auto last_error = get_last_error();
        std::cerr << "Error creating client socket (socket()):" << last_error << std::endl;
        throw std::exception((std::string("Failed to create client socket with: ") + last_error).c_str());
    }

    int iResult;

    BOOL optVal = true;
    int optSize = sizeof(BOOL);
    iResult = setsockopt(ConnectSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optVal, optSize);
    if (iResult == SOCKET_ERROR)
    {
        closesocket(ConnectSocket);
        throw std::exception("Failed to set socket to reusable");
    }

    u_long blockMode = 1;
    iResult = ioctlsocket(ConnectSocket, FIONBIO, &blockMode);
    if (iResult == SOCKET_ERROR)
    {
        closesocket(ConnectSocket);
        throw std::exception((std::string("Failed to make socket non-blocking with: ") + get_last_error()).c_str());
    }

    iResult = bind(ConnectSocket, &name.name, name.name_len);
    if (iResult == SOCKET_ERROR)
    {
        closesocket(ConnectSocket);
        throw std::exception((std::string("Failed to bind connect socket with: ") + get_last_error()).c_str());
    }

    std::cout << "[DataReuseNoB] Successfully bound Data socket to: " << readable.ip_address << ":" << readable.port << std::endl;
    return ConnectSocket;
}

windows_reusable_nonblocking_connection_socket::windows_reusable_nonblocking_connection_socket(
    raw_name_data name, std::string ip_address, std::string port, protocol input_protocol) : WindowsSocket(
    windows_reuse_nb_construct(name), input_protocol)
{
    connect(ip_address, port);
}

void windows_reusable_nonblocking_connection_socket::connect(std::string ip_address, std::string port)
{
    std::cout << "[DataReuseNoB] Trying to connect to: " << ip_address << ":" << port << std::endl;
    struct addrinfo* results, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int iResult = 0;

    iResult = getaddrinfo(ip_address.c_str(), port.c_str(), &hints, &results);
    if (iResult != 0)
        throw std::exception((std::string("Failed to resolve peer address, error: ") + std::to_string(iResult)).c_str());

    if (results == nullptr)
        throw std::exception((std::string("Could not resolve '") + ip_address + ":" + port + "'").c_str());

    iResult = ::connect(_socket, results->ai_addr, (int)results->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        auto last_err = WSAGetLastError();
        if (last_err != WSAEWOULDBLOCK)
            throw std::exception((std::string("Failed when attempting to connect to '") + ip_address + ":" + port + "' with error code: " + std::to_string(last_err)).c_str());
    }
    std::cout << "[DataReuseNoB] Initiated Connection to: " << ip_address << ":" << port << std::endl;
}

ConnectionStatus windows_reusable_nonblocking_connection_socket::has_connected()
{
    if (_socket == INVALID_SOCKET)
        return ConnectionStatus::FAILED;
    fd_set write_fd;
    fd_set except_fd;
    write_fd.fd_count = 1;
    write_fd.fd_array[0] = _socket;
    except_fd.fd_count = 1;
    except_fd.fd_array[0] = _socket;
    TIMEVAL timeout{ 0, 10000 };

    int iResult = select(0, NULL, &write_fd, NULL, &timeout);

    if (iResult == SOCKET_ERROR)
        throw std::exception((std::string("Failed to query socket write-ability with: ") + get_last_error()).c_str());
    if (iResult < 1)
    {
        iResult = select(0, NULL, NULL, &except_fd, &timeout);
        if (iResult == SOCKET_ERROR)
            throw std::exception((std::string("Failed to select socket error status with: ") + get_last_error()).c_str());
        if (iResult < 1)
            return ConnectionStatus::PENDING;

        int sock_error = 0;
        int sock_error_size = sizeof(sock_error);
        if (getsockopt(_socket, SOL_SOCKET, SO_ERROR, (char*)&sock_error, &sock_error_size) == SOCKET_ERROR)
            throw std::exception((std::string("Failed to get socket error code with: ") + get_last_error()).c_str());

        std::cerr << "[DataReuseNoB] Socket " << get_identifier_str() << " has error code : " << sock_error << " (" << get_win_error(sock_error) << ")" << std::endl;

        return ConnectionStatus::FAILED;
    }

    update_endpoint_if_needed();
    return ConnectionStatus::SUCCESS;
}