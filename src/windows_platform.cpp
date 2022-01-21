#include "ptop_socket.h"

#if defined(WIN32) | defined(_WIN64)
#include <exception>
#include <string>
#include <array>
#include <iostream>

#include "message.h"
#include "loop.h"
#include "protocol.h"
#include "windows_platform.h"

#define AF_FAM AF_INET

WindowsPlatform::WindowsPlatform(PtopSocket&& socket) 
    : _socket(std::move(socket))
{ 
    update_name_info();

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


readable_ip_info convert_to_readable(raw_name_data name)
{
    std::vector<char> name_buf(100, '0');
    const char* str = inet_ntop(AF_INET, &name.ipv4_addr().sin_addr, name_buf.data(), name_buf.size());

    if (!str) {
        auto error = std::string("Failed to convert sockaddr info to human readable address: ") + get_last_error();        
        throw_new_exception(error, LINE_CONTEXT);
    }
    std::string port_str = std::to_string(htons(name.ipv4_addr().sin_port));

    readable_ip_info out_data;
    out_data.ip_address = std::string(str);
    out_data.port = std::move(port_str);
    return out_data;
}

void WindowsPlatform::update_name_info()
{
    auto name = get_myname_readable();
    _address = name.ip_address;
    _port = name.port;
}

void WindowsPlatform::update_endpoint_info()
{
    try
	{
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

void WindowsPlatform::update_endpoint_if_needed()
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

readable_ip_info WindowsPlatform::get_peer_data() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getpeername(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);

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

raw_name_data WindowsPlatform::get_peername_raw() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getpeername(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);
    if (n != 0) {
        auto error = std::string("[Socket] Failed to getpeername with: ") + get_last_error();      
        throw_new_exception(error, LINE_CONTEXT);
    }

    raw_name_data raw_data;
    raw_data.name = *(sockaddr*)&peer_name;
    raw_data.name_len = peer_size;
    return raw_data;
}

raw_name_data WindowsPlatform::get_myname_raw() const
{
    sockaddr_in peer_name;
    socklen_t peer_size = sizeof(peer_name);
    int n = getsockname(_socket.get_handle(), (sockaddr*)&peer_name, &peer_size);

    if (n != 0) {
        auto error = std::string("[Socket] Failed to getsockname with: ") + get_last_error();        
        throw_new_exception(error, LINE_CONTEXT);
    }

    raw_name_data raw_data;
    raw_data.name = *(sockaddr*)&peer_name;
    raw_data.name_len = peer_size;
    return raw_data;
}

readable_ip_info WindowsPlatform::get_peername_readable() const
{
    try
    {
        return convert_to_readable(get_peername_raw());
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

readable_ip_info WindowsPlatform::get_myname_readable() const
{
    return convert_to_readable(get_myname_raw());
}

PtopSocket construct_windowslistensocket(std::string port, protocol input_protocol) {
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

        PtopSocket conn_socket = PtopSocket(input_protocol);

        if (conn_socket.is_invalid())
        {
            throw std::exception((std::string("[Listen] Failed to create socket with WSA error: ") + get_last_error()).c_str());
        }

        std::cout << "Binding..." << std::endl;
        conn_socket.bind_socket(raw_name_data{ *result->ai_addr, (socklen_t)result->ai_addrlen });

        return conn_socket;
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

WindowsPlatformListener::WindowsPlatformListener(std::string port, protocol input_protocol) : WindowsPlatform(construct_windowslistensocket(port, input_protocol)) 
{
    std::cout << "[Listen] Post Bind Check: Bound to: " << get_my_ip() << ":" << get_my_port() << std::endl;
}

void WindowsPlatformListener::listen()
{
    _socket.listen(4);
}

bool WindowsPlatformListener::has_connection()
{
    return _socket.has_connection();
}

std::unique_ptr<IDataSocketWrapper> WindowsPlatformListener::accept_connection() {
    std::cout << "[Listen] " << get_identifier_str() << " Socket Attempting to accept a connection" << std::endl;
    auto tmp = _socket.accept_data_socket();
    return std::make_unique<WindowsPlatformAnalyser>(std::move(tmp));
}

PtopSocket construct_windows_data_socket(std::string peer_address, std::string peer_port, protocol input_protocol) {
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

    PtopSocket conn_socket = PtopSocket(input_protocol);

    conn_socket.connect(result->ai_addr, result->ai_addrlen);

    return conn_socket;
}

WindowsPlatformAnalyser::WindowsPlatformAnalyser(std::string peer_address, std::string peer_port, protocol input_protocol) : WindowsPlatform(construct_windows_data_socket(peer_address, peer_port, input_protocol)) 
{
    try
    {
        update_endpoint_info();
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

bool WindowsPlatformAnalyser::send_data(const Message& message)
{
    std::cout << "Socket " << (*this).get_identifier_str() << " sending a Message of type: " << mt_to_string(message.Type) << " with length: " << message.Length << " bytes" << std::endl;
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
    std::cout << "[Data] Moving linux_reusable_nonblocking_connection_socket " << old->get_identifier_str() << " to a data_socket" << std::endl;
    WindowsReusableConnector& real_old = *dynamic_cast<WindowsReusableConnector*>(old.get());
    PtopSocket epic = real_old.release_socket();
    epic.set_non_blocking(false);
    return epic;
}

void WindowsPlatformAnalyser::process_socket_data()
{
    std::cout << "[Data] Trying to receive new data from Socket: " << get_identifier_str() << std::endl;
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
                std::cerr << "Socket " << get_identifier_str() << " Failed to process socket data into a message" << std::endl;
                recv_data.clear();
                return;
            }
            if (!try_read_data(recv_data.data(), data_read, recv_data.size(), length))
            {
                std::cerr << "Socket " << get_identifier_str() << " Failed to process socket data into a message" << std::endl;
                recv_data.clear();
                return;
            }
            if ((size_t)data_read + length > recv_data.size())
            {
                std::cerr << "Socket " << get_identifier_str() << " Read an invalid Length for a message" << std::endl;
                recv_data.clear();
                return;
            }
            data = std::vector<char>(recv_data.data() + data_read, recv_data.data() + data_read + length);
            data_read += length;
            auto new_message = Message{ type, length, std::move(data) };
            _stored_messages.push(new_message);
            std::cout << "Socket " << get_identifier_str() << " Received " << "a Message of type: " << mt_to_string(new_message.Type) << " with length: " << new_message.Length << " bytes (+ " << sizeof(type) + sizeof(length) << " type/length bytes)" << std::endl;
        }
    }
    else
    {
        std::cout << "Received empty data from: " << get_identifier_str() << std::endl;
        recv_data.clear();
    }
}

WindowsPlatformAnalyser::WindowsPlatformAnalyser(std::unique_ptr<INonBlockingConnector>&& old) 
: WindowsPlatform(windows_data_socket_steal_construct(std::move(old)))
{
    try
    {
        update_endpoint_info();
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

WindowsPlatformAnalyser::WindowsPlatformAnalyser(PtopSocket&& socket) 
: WindowsPlatform(std::move(socket))
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

Message WindowsPlatformAnalyser::receive_message() {
    process_socket_data();

    if (_stored_messages.size() > 0)
    {
        auto tmp = _stored_messages.front();
        _stored_messages.pop();
        return tmp;
    }

    return Message::null_message;
}

bool WindowsPlatformAnalyser::has_message()
{
    return _socket.has_message();
}

void WindowsPlatform::shutdown()
{
}

windows_internet::windows_internet(WORD versionRequested)
{
    int iResult = WSAStartup(versionRequested, &_data);
    
    if (iResult != 0) {
        auto error = "Winsock API initialization failed: " + std::to_string(iResult);        
        throw_new_exception(error, LINE_CONTEXT);
    }
    std::cout << "Winsock has been started" << std::endl;
}

windows_internet::~windows_internet()
{
    WSACleanup();
    std::cout << "Winsock has been cleaned" << std::endl;
}

PtopSocket windows_reuse_nb_listen_construct(raw_name_data data, protocol proto)
{
    try
    {
        auto readable = data.as_readable();
        std::cout << "[ListenReuseNoB] Creating Reusable Listen Socket on: " << readable.ip_address << ":" << readable.port << std::endl;

        PtopSocket listen_socket = PtopSocket(proto);
        if (listen_socket.is_invalid())
            throw_new_exception("[ListenReuseNoB] " + readable.ip_address + ":" + readable.port + " Failed to create reusable nonblocking listen socket: " + get_last_error(), LINE_CONTEXT);

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
WindowsReusableListener::WindowsReusableListener(raw_name_data data, protocol input_protocol) : WindowsPlatform(
    windows_reuse_nb_listen_construct(data, input_protocol))
{}

void WindowsReusableListener::listen()
{
    std::cout << "[ListenReuseNoB] Now Listening on: " << get_my_ip() << ":" << get_my_port() << std::endl;
    _socket.listen(4);
}

bool WindowsReusableListener::has_connection()
{
    return _socket.has_connection();
}

std::unique_ptr<IDataSocketWrapper> WindowsReusableListener::accept_connection()
{
    std::cout << "[ListenReuseNoB] Accepting Connection..." << std::endl;

    auto new_sock = _socket.accept_data_socket();
    return std::make_unique<WindowsPlatformAnalyser>(std::move(new_sock));
}

PtopSocket windows_reuse_nb_construct(raw_name_data name, protocol proto)
{
	try {
		auto readable = convert_to_readable(name);
		std::cout << "[DataReuseNoB] Creating Connection socket bound to: " << readable.ip_address << ":" << readable.port << std::endl;
		auto conn_socket = PtopSocket(proto);
		if (conn_socket.is_invalid())
			throw std::runtime_error(std::string("[DataReuseNoB] Failed to create nonblocking socket: ") + get_last_error());

		conn_socket.set_non_blocking(true);
		conn_socket.set_socket_reuse();

		conn_socket.bind_socket(name, "[DataReuseNoB] Failed to bind");
		std::cout << "[DataReuseNoB] Successfully bound Data socket to: " << readable.ip_address << ":" << readable.port << std::endl;

		return conn_socket;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

WindowsReusableConnector::WindowsReusableConnector(
    raw_name_data name, std::string ip_address, std::string port, protocol input_protocol) : WindowsPlatform(
    windows_reuse_nb_construct(name, input_protocol))
{
    connect(ip_address, port);
}

void WindowsReusableConnector::connect(std::string ip_address, std::string port)
{
	try
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

		_socket.connect(results->ai_addr, results->ai_addrlen);
		std::cout << "[DataReuseNoB] Successfully BEGUN Connection to: " << ip_address << ":" << port << std::endl;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

ConnectionStatus WindowsReusableConnector::has_connected()
{
	try
	{
		if (_socket.is_invalid())
			return ConnectionStatus::FAILED;

		if (_socket.poll_for(POLLWRNORM))
		{
			//update_endpoint_if_needed();
			return ConnectionStatus::SUCCESS;
		}


		if (!_socket.select_for(select_for::EXCEPT))
			return ConnectionStatus::PENDING;

		auto sock_error = _socket.get_socket_option<int>(SO_ERROR);

		std::cerr << "Socket has error code: " << sock_error << std::endl;

		return ConnectionStatus::FAILED;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}
#endif