#include "platform.h"
#include "error.h"
#include "loop.h"

#if defined(__linux__)
#include <arpa/inet.h>
#endif

#include <string>
#include <algorithm>

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
    
    return std::string("(") + name_str + " pub: " + _address + ":" + _port + ")"; 
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

Platform::~Platform()
{
	if (_socket.is_valid())
		std::cout << "Closing socket: " << get_identifier_str() << std::endl;
	else
		std::cout << "Closing Dead socket" << std::endl;
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
		auto received = _socket.recv_udp_bytes();

		if (_messages.find(received.endpoint) == _messages.end())
		{
			_messages[received.endpoint] = std::queue<Message>();
			process_into_messages(_messages[received.endpoint], received.bytes);
		}

		if (_connectors.find(received.endpoint) == _connectors.end())
		{
			if (std::find(_new_connections.begin(), _new_connections.end(), received.endpoint) == _new_connections.end())
				_new_connections.push_back(received.endpoint);
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

PtopSocket construct_udp_listener(std::string port, protocol proto, std::string name)
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

UDPListener::UDPListener(std::string port, protocol proto, std::string name) : Platform(construct_udp_listener(port, proto, name))
{
}

bool UDPListener::has_connection()
{
	process_data();

	return _new_connections.size();
}

std::unique_ptr<IDataSocketWrapper> UDPListener::accept_connection()
{
	if (!has_connection())
		return nullptr;

	const auto& new_conn_endpoint = _new_connections.back();

	auto new_conn = std::unique_ptr<UDPAcceptedConnector>(new UDPAcceptedConnector(this, new_conn_endpoint));

	_connectors[new_conn_endpoint] = new_conn.get();
	_new_connections.pop_back();

	return new_conn;
}
