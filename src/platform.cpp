#include "platform.h"
#include "error.h"
#include "loop.h"

#if defined(__linux__)
#include <arpa/inet.h>
#endif

#include <string>
#include <algorithm>
#include <functional>

std::string Platform::get_identifier_str() {
	std::string name_str = "Unnamed";
	if (_socket.get_name().size())
		name_str = _socket.get_name();
	if (_socket.is_tcp() && _socket.is_listen())
		return std::string("(") + name_str + " is a listen on: " + _address + ":" + _port + ")";

	if (_endpoint_assigned == false)
		try_update_endpoint_info();

	if (_endpoint_assigned == false)
        return std::string("(") + name_str + " priv: " + _address + ":" + _port + ", pub : N / A)";
    
    return std::string("(") + name_str + " pub: " + _endpoint_address + ":" + _endpoint_port + ")"; 
}

readable_ip_info convert_to_readable(const raw_name_data& data)
{
	std::vector<char> buf{ 50, '0', std::allocator<char>() };
	const char* str = inet_ntop(AF_INET, &data.ipv4_addr().sin_addr, buf.data(), buf.size());

	if (!str) {
		throw_new_exception("Failed to convert sockaddr to string: " + get_last_error(), LINE_CONTEXT);
	}

	std::string address = str;

	std::string port = std::to_string(ntohs(data.ipv4_addr().sin_port));
	readable_ip_info out;
	out.ip_address = address;
	out.port = port;
	return out;
}

PtopSocket data_connect_construct(std::string peer_address, std::string peer_port, Protocol ip_proto, std::string name)
{
	std::cout << "[Data] Creating a Linux Data Socket (named " << name << ") connecting to : " << peer_address << ":" << peer_port << std::endl;

	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;

#ifdef WIN32
	ZeroMemory(&hints, sizeof(hints));
#elif defined(__linux__)
	bzero(&hints, sizeof(hints));
#endif
	hints.ai_family = ip_proto.get_ai_family();
	hints.ai_socktype = ip_proto.get_ai_socktype();
	hints.ai_protocol = ip_proto.get_ai_protocol();

	int n = getaddrinfo(peer_address.c_str(), peer_port.c_str(), &hints, &result);

	if (n == SOCKET_ERROR)
		throw_new_exception("Failed to get address info for: (" + name + ") " + peer_address + ":" + peer_port + " with: " + get_last_error(), LINE_CONTEXT);

	auto conn_socket = PtopSocket(ip_proto, name);
	conn_socket.set_socket_reuse();
	conn_socket.connect(result->ai_addr, result->ai_addrlen);

	UDPHandShakeStatus handshake_status{};
	if (ip_proto.is_udp())
	{
		s_time start_time = time_now();
		bool has_connected = false;
		while (has_connected == false)
		{
			has_connected = do_udp_handshake(handshake_status, conn_socket);
			std::this_thread::sleep_for(100ms);

			if (time_now() - start_time > UDPHandShakeStatus::TIMEOUT_HANDSHAKE_TIME)
				throw_new_exception("Failed to UDP handshake: Timeout expired", LINE_CONTEXT);
		}
	}

	return conn_socket;
}

PlatformAnalyser::PlatformAnalyser(std::string peer_address, std::string peer_port, Protocol proto, std::string name)
	: Platform(data_connect_construct(peer_address, peer_port, proto, name))
{
	try_update_endpoint_info();
}

Platform::~Platform()
{
	if (_socket.is_valid())
		std::cout << "Closing socket: " << get_identifier_str() << std::endl;
	else
		std::cout << "Closing Dead socket" << std::endl;
}

bool do_udp_handshake(UDPHandShakeStatus& handshake_status, PtopSocket& socket)
{
	if (handshake_status.has_received_syn() && handshake_status.has_received_ack())
		return true;
	else
	{
		if (socket.has_message())
		{
			auto msgs = data_to_messages(socket.receive_bytes());
			if (std::find_if(msgs.cbegin(), msgs.cend(), [](const Message& m) { return m.Type == MESSAGE_TYPE::UDP_SYN_ACK; }) != msgs.cend())
			{
				handshake_status.last_syn_receive_time = time_now();
				handshake_status.last_ack_receive_time = time_now();
				socket.send_bytes(create_message(MESSAGE_TYPE::UDP_ACK).to_bytes());
				handshake_status.last_ack_send_time = time_now();
				return true;
			}
			else if (std::find_if(msgs.cbegin(), msgs.cend(), [](const Message& m) { return m.Type == MESSAGE_TYPE::UDP_ACK; }) != msgs.cend())
			{
				handshake_status.last_ack_receive_time = time_now();
				return true;
			}
			else if (std::find_if(msgs.cbegin(), msgs.cend(), [](const Message& m) { return m.Type == MESSAGE_TYPE::UDP_SYN; }) != msgs.cend())
			{
				handshake_status.last_syn_receive_time = time_now();
			}
		}
		if (handshake_status.has_received_syn())
		{
			socket.send_bytes(create_message(MESSAGE_TYPE::UDP_SYN_ACK).to_bytes());
			handshake_status.last_ack_send_time = handshake_status.last_syn_send_time = time_now();
		}
		else if (time_now() - handshake_status.last_syn_send_time > UDPHandShakeStatus::RESEND_SYN_TIME)
		{
			socket.send_bytes(create_message(MESSAGE_TYPE::UDP_SYN).to_bytes());
			handshake_status.last_syn_send_time = time_now();
		}
	}
	return false;
}

ConnectionStatus NonBlockingConnector::has_connected()
{
	try
	{
		if (_socket.is_invalid())
			return ConnectionStatus::FAILED;

		if (_socket.is_udp())
		{
			if (do_udp_handshake(_handshake_status, _socket))
				return ConnectionStatus::SUCCESS;
			return ConnectionStatus::PENDING;
		}

		if (_socket.select_for(select_for::WRITE))
		{
			auto sock_error = _socket.get_socket_option<int>(SO_ERROR);
			if (sock_error != 0 && sock_error != EAGAIN && sock_error != EINPROGRESS)
			{
				std::cerr << "[DataReuseNoB] " << LINE_CONTEXT << " Socket '" << get_name() << "' failed to connect with: " << socket_error_to_string(sock_error) << std::endl;
				return ConnectionStatus::FAILED;
			}

			update_endpoint_if_needed();
			return ConnectionStatus::SUCCESS;
		}


		if (!_socket.select_for(select_for::EXCEPT))
			return ConnectionStatus::PENDING;

		auto sock_error = _socket.get_socket_option<int>(SO_ERROR);

		std::cerr << "[DataReuseNoB] " << LINE_CONTEXT << " Socket '" << get_name() << "' failed to connect with: " << socket_error_to_string(sock_error) << std::endl;

		return ConnectionStatus::FAILED;
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

void UDPAcceptedConnector::throw_if_no_listener() const
{
	if (!_listen)
		throw_new_exception("Accepted UDP Connector has no valid listener", LINE_CONTEXT);
}

UDPAcceptedConnector::UDPAcceptedConnector(UDPListener* listen, raw_name_data endpoint) : _listen(listen), _my_endpoint(endpoint)
{
}

UDPAcceptedConnector::~UDPAcceptedConnector()
{
	if (_listen)
		_listen->remove_connector(_my_endpoint, this);
}

Message UDPAcceptedConnector::receive_message()
{
	throw_if_no_listener();

	return _listen->receive_message(_my_endpoint);
}

bool UDPAcceptedConnector::has_message()
{
	throw_if_no_listener();

	return _listen->has_message(_my_endpoint);
}

bool UDPAcceptedConnector::send_data(const Message& message)
{
	throw_if_no_listener();

	return _listen->send_data(message, _my_endpoint);
}

readable_ip_info UDPAcceptedConnector::get_peer_data() const
{
	return convert_to_readable(_my_endpoint);
}

raw_name_data UDPAcceptedConnector::get_peername_raw() const
{
	return _my_endpoint;
}

raw_name_data UDPAcceptedConnector::get_myname_raw() const
{
	throw_if_no_listener();

	return _listen->my_data();
}

readable_ip_info UDPAcceptedConnector::get_peername_readable() const
{
	return convert_to_readable(get_peername_raw());
}

readable_ip_info UDPAcceptedConnector::get_myname_readable() const
{
	return convert_to_readable(get_myname_raw());
}

std::string UDPAcceptedConnector::get_my_ip() const
{
	auto readable = get_myname_readable();

	return readable.ip_address;
}

std::string UDPAcceptedConnector::get_my_port() const
{
	auto readable = get_myname_readable();

	return readable.port;
}

std::string UDPAcceptedConnector::get_endpoint_ip() const
{
	auto readable = get_peername_readable();

	return readable.ip_address;
}

std::string UDPAcceptedConnector::get_endpoint_port() const
{
	auto readable = get_peername_readable();

	return readable.port;
}

std::string UDPAcceptedConnector::get_identifier_str()
{
	return "(UDPAcceptedConnector on pub: " + get_peername_readable().to_string() + ")";
}

const std::string& UDPAcceptedConnector::get_name() const
{
	throw_if_no_listener();

	return "UDPAccepterConnector of: " + _listen->get_name();
}

void UDPAcceptedConnector::set_name(std::string name)
{
}

void process_into_messages(std::queue<Message>& message_queue, const std::vector<char>& data)
{
	auto& recv_data = data;
	if (recv_data.size() > 0)
	{
		std::cout << "Received (UDP) " << recv_data.size() << " bytes" << std::endl;

		int data_read = 0;

		while ((recv_data.size() - data_read) > 0)
		{
			MESSAGE_TYPE type;
			MESSAGE_LENGTH_T length;
			std::vector<char> data;

			if (!try_read_data(recv_data.data(), data_read, recv_data.size(), type))
			{
				return;
			}
			if (!try_read_data(recv_data.data(), data_read, recv_data.size(), length))
			{
				return;
			}
			if (data_read + length > recv_data.size())
			{
				return;
			}
			data = std::vector<char>(recv_data.data() + data_read, recv_data.data() + data_read + length);
			data_read += length;
			auto new_message = Message{ type, length, std::move(data) };
			message_queue.push(new_message);
		}
	}
}

void UDPListener::process_data()
{
	while (_socket.has_message())
	{
		auto received = _socket.receive_udp_bytes();
		auto endpoint = received.endpoint;

		if (_messages.find(received.endpoint) == _messages.end())
		{
			_messages[received.endpoint] = std::queue<Message>();
		}
		auto new_msgs = data_to_messages(received.bytes);

		if (_connectors.find(endpoint) == _connectors.end())
		{
			handle_handshaking(new_msgs, endpoint);
		}

		for (auto& m : new_msgs)
			_messages[endpoint].push(m);
	}
}

bool UDPListener::messages_contains(const std::vector<Message>& msgs, MESSAGE_TYPE type)
{
	return std::find_if(msgs.cbegin(), msgs.cend(), std::bind(message_is_type, type, std::placeholders::_1)) != msgs.cend();
}

UDPListener::vec_it UDPListener::find_conn_by_endpoint(std::vector<UDPAcceptedConnector*>& msgs, const raw_name_data& endpoint)
{
	return std::find_if(msgs.begin(), msgs.end(), [&endpoint](UDPAcceptedConnector* m) { return m->get_peername_raw() == endpoint; });
}

void UDPListener::handle_handshaking(const std::vector<Message>& msgs, const raw_name_data& endpoint)
{
	if (messages_contains(msgs, MESSAGE_TYPE::UDP_SYN))
	{
		decltype(_need_handshake_connectors)::iterator existing_conn = find_conn_by_endpoint(_need_handshake_connectors, endpoint);
		if (existing_conn == _need_handshake_connectors.end())
		{
			auto new_conn = new UDPAcceptedConnector(this, endpoint);
			_need_handshake_connectors.push_back(new_conn);
			new_conn->send_data(create_message(MESSAGE_TYPE::UDP_SYN_ACK));
			new_conn->_handshake_status.last_syn_receive_time = time_now();
			new_conn->_handshake_status.last_syn_send_time = new_conn->_handshake_status.last_ack_send_time = time_now();
		}
	}
	if (messages_contains(msgs, MESSAGE_TYPE::UDP_SYN_ACK))
	{
		decltype(_need_handshake_connectors)::iterator existing_conn = find_conn_by_endpoint(_need_handshake_connectors, endpoint);
		if (existing_conn == _need_handshake_connectors.end())
		{
			auto new_conn = new UDPAcceptedConnector(this, endpoint);
			auto& shake_status = new_conn->_handshake_status;
			new_conn->send_data(create_message(MESSAGE_TYPE::UDP_ACK));
			shake_status.last_ack_send_time = time_now();
			shake_status.last_ack_receive_time = shake_status.last_syn_receive_time = time_now();
			_handshook_connectors.push_back(new_conn);
		}
		else
		{
			auto conn = *existing_conn;
			auto& shake_status = conn->_handshake_status;
			shake_status.last_ack_receive_time = time_now();
			shake_status.last_syn_receive_time = time_now();
			conn->send_data(create_message(MESSAGE_TYPE::UDP_ACK));
			conn->_handshake_status.last_ack_send_time = time_now();
			_need_handshake_connectors.erase(existing_conn);
			_handshook_connectors.push_back(conn);
		}
	}
	if (messages_contains(msgs, MESSAGE_TYPE::UDP_ACK))
	{
		std::vector<UDPAcceptedConnector*>::iterator conn_it;
		if ((conn_it = find_conn_by_endpoint(_need_handshake_connectors, endpoint)) != _need_handshake_connectors.end())
		{
			auto conn = *conn_it;

			if (conn->_handshake_status.has_received_syn())
			{
				conn->_handshake_status.last_ack_receive_time = time_now();
				conn->_handshake_status.handshake_completed_time = time_now();
				_need_handshake_connectors.erase(conn_it);
				_handshook_connectors.push_back(conn);
			}
		}
	}
}

void UDPListener::remove_connector(raw_name_data endpoint, UDPAcceptedConnector* conn)
{
	if (_connectors.find(endpoint) != _connectors.end())
	{
		if (_connectors[endpoint] != conn)
		{
			std::cerr << "Incorrect value for key given from destroying UDPAcceptedConnector" << std::endl;
			return;
		}
		_connectors.erase(endpoint);
	}
}

bool UDPListener::send_data(const Message& message, raw_name_data to)
{
	return _socket.send_udp_bytes(udp_bytes{ message.to_bytes(), to });
}

bool UDPListener::has_message(raw_name_data from)
{
	process_data();

	if (_messages.find(from) == _messages.end())
		return false;
	return _messages[from].size();
}

Message UDPListener::receive_message(raw_name_data from)
{
	process_data();

	if (_messages.find(from) == _messages.end())
		throw_new_exception("Failure receiving message for specific UDP endpoint: " + convert_to_readable(from).to_string() + " could not find any messages for endpoint", LINE_CONTEXT);

	auto& q = _messages[from];
	auto tmp = q.front();
	q.pop();
	return tmp;
}

raw_name_data UDPListener::my_data()
{
	return _socket.get_name_raw();
}

PtopSocket construct_udp_listener(std::string port, Protocol proto, std::string name)
{
	if (!proto.is_udp())
		throw_new_exception("UDP Listener must only be used with UDP", LINE_CONTEXT);

	auto listen_socket = PtopSocket(proto, name);

	struct sockaddr_in serv_addr;

	int portno = atoi(port.c_str());
#ifdef WIN32
	ZeroMemory(&serv_addr, sizeof(serv_addr));
#elif __linux__
	bzero((char*)&serv_addr, sizeof(serv_addr));
#endif
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	std::cout << "[UDPListen] Binding UDP Listener (" << name << ") to port " << port << std::endl;
	listen_socket.bind_socket(raw_name_data{ *(sockaddr*)&serv_addr, sizeof(serv_addr) });

	return listen_socket;
}

UDPListener::UDPListener(std::string port, Protocol proto, std::string name) : Platform(construct_udp_listener(port, proto, name))
{
}

UDPListener::~UDPListener()
{
	for (auto& pair : _connectors)
		if (pair.second)
			pair.second->_listen = nullptr;

	for (auto& conn : _handshook_connectors)
		if (conn)
		{
			conn->_listen = nullptr;
			delete conn;
		}

	for (auto& conn : _need_handshake_connectors)
		if (conn)
		{
			conn->_listen = nullptr;
			delete conn;
		}
}

bool UDPListener::has_connection()
{
	process_data();

	return _handshook_connectors.size();
}

std::unique_ptr<IDataSocketWrapper> UDPListener::accept_connection()
{
	if (!has_connection())
		return nullptr;

	const auto& new_conn_endpoint = _handshook_connectors.back();

	auto new_conn = std::unique_ptr<UDPAcceptedConnector>(new_conn_endpoint);

	_connectors[new_conn_endpoint->_my_endpoint] = new_conn.get();
	_handshook_connectors.pop_back();

	return new_conn;
}
