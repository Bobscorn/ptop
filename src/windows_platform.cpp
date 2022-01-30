#if defined(WIN32) | defined(_WIN64)
#include "message.h"
#include "loop.h"
#include "protocol.h"
#include "platform.h"
#include "error.h"

#include <exception>
#include <string>
#include <array>
#include <iostream>

#define AF_FAM AF_INET

Platform::Platform(PtopSocket&& socket) 
    : _socket(std::move(socket))
{ 
    try_update_name_info();
    // big chungus

    if(_socket.is_udp()) {
        std::cout << "Platform constructed for UDP" << std::endl;
        return;
    }

    if (_address == "Unassigned" || _address.empty() ||
        _port == "Unassigned" || _port.empty()) {
        auto message = "failed to update name info";        
        throw_new_exception(message, LINE_CONTEXT);
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

void Platform::try_update_name_info()
{
    try
    {
        update_name_info();
    }
    catch (const std::exception& e)
    {
    }
}

void Platform::try_update_endpoint_info()
{
    try
    {
        update_endpoint_info();
    }
    catch (const std::exception& e)
    {
    }
}

void Platform::update_name_info()
{
    auto name = get_myname_readable();
    _address = name.ip_address;
    _port = name.port;
}

void Platform::update_endpoint_info()
{
    try
	{
        if (_socket.is_tcp() && _socket.is_listen())
        {
            std::cout << "[Socket] Not updating endpoint as this socket " << get_identifier_str() << " is a listen socket" << std::endl;
            return;
        }
		auto name = get_peername_readable();
		_endpoint_address = name.ip_address;
		_endpoint_port = name.port;
		_endpoint_assigned = true;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

void Platform::update_endpoint_if_needed()
{
	try
	{
		if (!_endpoint_assigned)
		{
			update_endpoint_info();
		}
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

readable_ip_info Platform::get_peer_data() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getpeername(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);

    std::vector<char> buf{ 50, '0', std::allocator<char>() };
    const char* str = inet_ntop(AF_INET, &peer_name.sin_addr, buf.data(), buf.size());
    if (!str)
        throw std::runtime_error(std::string("Socket '") + get_name() + "' Failed to convert sockaddr to string : " + get_last_error());

    std::string address = str;

    std::string port = std::to_string(peer_name.sin_port);
    readable_ip_info out;
    out.ip_address = address;
    out.port = port;
    return out;
}

raw_name_data Platform::get_peername_raw() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getpeername(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);
    if (n != 0) {
        auto error = std::string("[Socket] (" + get_name() + ") Failed to getpeername : ") + get_last_error();      
        throw_new_exception(error, LINE_CONTEXT);
    }

    raw_name_data raw_data;
    raw_data.name = *(sockaddr*)&peer_name;
    raw_data.name_len = peer_size;
    return raw_data;
}

raw_name_data Platform::get_myname_raw() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getsockname(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);

    if (n != 0) {
        auto error = std::string("[Socket] (" + get_name() + ") Failed to getsockname : ") + get_last_error();        
        throw_new_exception(error, LINE_CONTEXT);
    }

    raw_name_data raw_data;
    raw_data.name = *(sockaddr*)&peer_name;
    raw_data.name_len = peer_size;
    return raw_data;
}

PtopSocket construct_windowslistensocket(std::string port, protocol input_protocol, std::string name) {
    try
    {
        std::cout << "[Listen] Creating new Socket on port (with localhost, named: " << name << "): " << port << std::endl;
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
            throw std::exception((std::string("[Listen] (" + name + ") Failed to create windows socket : getaddrinfo failed with") + std::to_string(iResult)).c_str());
        }

        PtopSocket conn_socket = PtopSocket(input_protocol, name);

        if (conn_socket.is_invalid())
        {
            throw std::exception((std::string("[Listen] (" + name + ") Failed to create socket with WSA error : ") + get_last_error()).c_str());
        }

        std::cout << name << " is Binding..." << std::endl;
        conn_socket.bind_socket(raw_name_data{ *result->ai_addr, (socklen_t)result->ai_addrlen });

        return conn_socket;
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

PlatformListener::PlatformListener(std::string port, protocol input_protocol, std::string name) : Platform(construct_windowslistensocket(port, input_protocol, name)) 
{
}

void PlatformListener::listen()
{
    std::cout << "[Listen] Socket " << get_name() << " now Listening(" << get_my_ip() << ":" << get_my_port() << ")" << std::endl;
    _socket.listen(4);
}

bool PlatformListener::has_connection()
{
    return _socket.has_connection();
}

std::unique_ptr<IDataSocketWrapper> PlatformListener::accept_connection() {
    std::cout << "[Listen] " << get_identifier_str() << " Socket Attempting to accept a connection" << std::endl;
    auto tmp = _socket.accept_data_socket();
    return std::make_unique<PlatformAnalyser>(std::move(tmp));
}

PtopSocket construct_windows_data_socket(std::string peer_address, std::string peer_port, protocol input_protocol, std::string name) {
    std::cout << "[Data] Creating a Windows Data Socket (" << name << ") connecting to : " << peer_address << " : " << peer_port << std::endl;
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
        throw std::exception((std::string("Socket " + name + " Failed to resolve peer address, error: ") + std::to_string(iResult)).c_str());
    }

    PtopSocket conn_socket = PtopSocket(input_protocol, name);

    conn_socket.connect(result->ai_addr, (socklen_t)result->ai_addrlen);

    return conn_socket;
}

PlatformAnalyser::PlatformAnalyser(std::string peer_address, std::string peer_port, protocol input_protocol, std::string name) : Platform(construct_windows_data_socket(peer_address, peer_port, input_protocol, name)) 
{
    try
    {
        try_update_endpoint_info();
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

bool PlatformAnalyser::send_data(const Message& message)
{
    std::cout << "Socket " << Platform::get_identifier_str() << " sending a Message of type: " << mt_to_string(message.Type) << " with length: " << message.Length << " bytes" << std::endl;
    auto bytes = message.to_bytes();
    if (_socket.send_bytes(bytes))
    {
        _sent_bytes += bytes.size();
        return true;
    }
    return false;
}

PtopSocket windows_data_socket_steal_construct(std::unique_ptr<INonBlockingConnector>&& old)
{
    std::cout << "[Data] Moving INonBlockingConnector " << old->get_identifier_str() << " to a PlatformAnalyzer" << std::endl;
    NonBlockingConnector& real_old = *dynamic_cast<NonBlockingConnector*>(old.get());
    PtopSocket epic = real_old.release_socket();
    epic.set_non_blocking(false);
    epic.set_socket_no_reuse();
    return epic;
}

void PlatformAnalyser::process_socket_data()
{
    std::cout << "[Data] Trying to receive new data from Socket: " << Platform::get_identifier_str() << std::endl;
    std::vector<char> recv_data = _socket.recv_bytes();
    if (recv_data.size() > 0)
    {
        std::cout << "Received " << recv_data.size() << " bytes" << std::endl;
        _seen_data += recv_data.size();

        int data_read = 0;

        while ((recv_data.size() - data_read) > 0)
        {
            MESSAGE_TYPE type;
            MESSAGE_LENGTH_T length;
            std::vector<char> data;

            if (!try_read_data(recv_data.data(), data_read, recv_data.size(), type))
            {
                std::cerr << "Socket " << Platform::get_identifier_str() << " Failed to process socket data into a message" << std::endl;
                recv_data.clear();
                return;
            }
            if (!try_read_data(recv_data.data(), data_read, recv_data.size(), length))
            {
                std::cerr << "Socket " << Platform::get_identifier_str() << " Failed to process socket data into a message" << std::endl;
                recv_data.clear();
                return;
            }
            if ((size_t)data_read + length > recv_data.size())
            {
                std::cerr << "Socket " << Platform::get_identifier_str() << " Read an invalid Length for a message" << std::endl;
                recv_data.clear();
                return;
            }
            data = std::vector<char>(recv_data.data() + data_read, recv_data.data() + data_read + length);
            data_read += length;
            auto new_message = Message{ type, length, std::move(data) };
            _stored_messages.push(new_message);
            std::cout << "Socket " << Platform::get_identifier_str() << " Received " << "a Message of type: " << mt_to_string(new_message.Type) << " with length: " << new_message.Length << " bytes (+ " << sizeof(type) + sizeof(length) << " type/length bytes)" << std::endl;
        }
    }
    else
    {
        std::cout << "Received empty data from: " << Platform::get_identifier_str() << std::endl;
        recv_data.clear();
    }
}

PlatformAnalyser::PlatformAnalyser(std::unique_ptr<INonBlockingConnector>&& old) 
: Platform(windows_data_socket_steal_construct(std::move(old)))
{
    try
    {
        try_update_endpoint_info();
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

PlatformAnalyser::PlatformAnalyser(PtopSocket&& socket) 
: Platform(std::move(socket))
{
	try
	{
		std::cout << "[Data] Copy Constructor Data socket" << std::endl;
		update_endpoint_info();

		if (_socket.is_invalid())
			throw std::runtime_error("[Data] Invalid socket in Copy Constructor");
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

Message PlatformAnalyser::receive_message() {
    process_socket_data(); // Will block until it receives data

    if (_stored_messages.size() > 0)
    {
        auto tmp = _stored_messages.front();
        _stored_messages.pop();
        return tmp;
    }

    // Only way we have no messages is if connection closed
    return Message::null_message;
}

bool PlatformAnalyser::has_message()
{
    return _socket.has_message();
}

PtopSocket windows_reuse_nb_listen_construct(raw_name_data data, protocol proto, std::string name)
{
    try
    {
        auto readable = convert_to_readable(data);
        std::cout << "[ListenReuseNoB] Creating Reusable Listen Socket '" << name << "' on: " << readable.ip_address << ":" << readable.port << std::endl;

        PtopSocket listen_socket = PtopSocket(proto, name);
        if (listen_socket.is_invalid())
            throw_new_exception("[ListenReuseNoB] (" + name + ") " + readable.ip_address + ":" + readable.port + " Failed to create reusable nonblocking listen socket: " + get_last_error(), LINE_CONTEXT);

        listen_socket.set_non_blocking(true);
        listen_socket.set_socket_reuse();

        listen_socket.bind_socket(data);

        return listen_socket;
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

NonBlockingListener::NonBlockingListener(raw_name_data data, protocol input_protocol, std::string name) 
    : Platform(
        windows_reuse_nb_listen_construct(data, input_protocol, name)
    )
{}

void NonBlockingListener::listen()
{
	std::cout << "[ListenReuseNoB] " + get_identifier_str() + " Now Listening on  port: " << get_my_port() << std::endl;
    _socket.listen(4);
}

bool NonBlockingListener::has_connection()
{
    return _socket.has_connection();
}

std::unique_ptr<IDataSocketWrapper> NonBlockingListener::accept_connection()
{
    std::cout << "[ListenReuseNoB] " + get_identifier_str() + " Accepting Connection..." << std::endl;

    auto new_sock = _socket.accept_data_socket();
    return std::make_unique<PlatformAnalyser>(std::move(new_sock));
}

PtopSocket windows_reuse_nb_construct(raw_name_data data, protocol proto, std::string name)
{
	try {
		auto readable = convert_to_readable(data);
        std::cout << "[DataReuseNoB] Creating Connection socket '" << name << "' bound to : " << readable.ip_address << ":" << readable.port << std::endl;
		auto conn_socket = PtopSocket(proto, name);
		if (conn_socket.is_invalid())
			throw_new_exception(std::string("[DataReuseNoB] Failed to create nonblocking socket (" + name + "): ") + get_last_error(), LINE_CONTEXT);

		conn_socket.set_non_blocking(true);
		conn_socket.set_socket_reuse();

		conn_socket.bind_socket(data, "[DataReuseNoB] '" + name + "' Failed to bind");
		std::cout << "[DataReuseNoB] Successfully bound Data socket (" << name << ") to: " << readable.ip_address << " : " << readable.port << std::endl;

		return conn_socket;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

NonBlockingConnector::NonBlockingConnector(
    raw_name_data data, std::string ip_address, std::string port, protocol input_protocol, std::string name) 
    : Platform(
        windows_reuse_nb_construct(data, input_protocol, name)
    )
{
    connect(ip_address, port);
}

void NonBlockingConnector::connect(std::string ip_address, std::string port)
{
	try
	{
        std::cout << "[DataReuseNoB] (" << get_name() << ") Trying to connect to : " << ip_address << ":" << port << std::endl;
		struct addrinfo* results, hints;
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		int iResult = 0;

		iResult = getaddrinfo(ip_address.c_str(), port.c_str(), &hints, &results);
		if (iResult != 0)
            throw_new_exception("Socket '" + get_name() + "' Failed to getaddrinfo, error: " + std::to_string(iResult), LINE_CONTEXT);

		if (results == nullptr)
            throw_new_exception(("No possible sockets found for '") + ip_address + ":" + port + "' (socket '" + get_name() + "')", LINE_CONTEXT);

		_socket.connect(results->ai_addr, (socklen_t)results->ai_addrlen);
        std::cout << "[DataReuseNoB] (" << get_name() << ") Successfully BEGUN Connection to : " << ip_address << ":" << port << std::endl;
        try_update_endpoint_info();
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

ConnectionStatus NonBlockingConnector::has_connected()
{
    try
    {
        if (_socket.is_invalid())
            return ConnectionStatus::FAILED;

        if (_socket.select_for(select_for::WRITE))
        {
            auto sock_error = _socket.get_socket_option<int>(SO_ERROR);
            if (sock_error != 0 && sock_error != EAGAIN && sock_error != EINPROGRESS)
            {
                std::cerr << "[DataReuseNoB] " << LINE_CONTEXT << " Socket '" << get_name() << "' failed to connect with: " << get_win_error(sock_error) << std::endl;
                return ConnectionStatus::FAILED;
            }

            update_endpoint_if_needed();
            return ConnectionStatus::SUCCESS;
        }


        if (!_socket.select_for(select_for::EXCEPT))
            return ConnectionStatus::PENDING;

        auto sock_error = _socket.get_socket_option<int>(SO_ERROR);

        std::cerr << "[DataReuseNoB] " << LINE_CONTEXT << " Socket '" << get_name() << "' failed to connect with: " << get_win_error(sock_error) << std::endl;

        return ConnectionStatus::FAILED;
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

#endif