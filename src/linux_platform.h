#pragma once

#ifdef __linux__
#include <sys/types.h>
#include <sys/socket.h>

#include <string>
#include <queue>

#include "socket_wrapper.h"
#include "protocol.h"
#include "ptop_socket.h"

readable_ip_info convert_to_readable(raw_name_data data);

class LinuxPlatform : virtual public ISocketWrapper
{
protected:
	LinuxPlatform(PtopSocket&& socket);
	PtopSocket _socket;
	std::string _address;
	std::string _port;
	std::string _endpoint_address;
	std::string _endpoint_port;
	bool _endpoint_assigned = false;

	void update_name_info();
	void update_endpoint_info();
	void update_endpoint_if_needed();

	virtual ~LinuxPlatform();

public:
	void shutdown() override;
	readable_ip_info get_peer_data() const override;
	raw_name_data get_peername_raw() const override;
	raw_name_data get_myname_raw() const override;
	readable_ip_info get_peername_readable() const override;
	readable_ip_info get_myname_readable() const override;

	inline std::string get_my_ip() const override { return _address; }
	inline std::string get_my_port() const override { return _port; }
	inline std::string get_endpoint_ip() const override { return _endpoint_address; }
	inline std::string get_endpoint_port() const override { return _endpoint_port; }

	inline std::string get_identifier_str() const override { if (!_endpoint_assigned) return std::string("(priv: ") + _address + ":" + _port + ", pub: N/A)"; return std::string("(pub: ") + _endpoint_address + ":" + _endpoint_port + ")"; }

	inline PtopSocket&& release_socket() { return std::move(_socket); }
};

class LinuxPlatformListener : public LinuxPlatform, public IListenSocketWrapper
{
public:
	LinuxPlatformListener(std::string port, protocol input_protocol);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocketWrapper> accept_connection() override;
};

class LinuxPlatformAnalyser : public LinuxPlatform, public IDataSocketWrapper
{
	std::queue<Message> _stored_messages;

	void process_socket_data();
	public:
	LinuxPlatformAnalyser(std::unique_ptr<INonBlockingConnector>&& old);
	LinuxPlatformAnalyser(PtopSocket&& socket);
	LinuxPlatformAnalyser(std::string peer_address, std::string peer_port, protocol ip_proto);

	Message receive_message() override;
	bool has_message() override;

	bool send_data(const Message& message) override;

	bool has_died();
};

class LinuxReusableListener : public LinuxPlatform, public INonBlockingListener
{
public:
	LinuxReusableListener(raw_name_data data, protocol proto);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocketWrapper> accept_connection() override;
};

class LinuxReusableConnector : public LinuxPlatform, public INonBlockingConnector
{
public:
	LinuxReusableConnector(raw_name_data data, std::string ip_address, std::string port, protocol proto);

	void connect(std::string ip_address, std::string port) override;
	ConnectionStatus has_connected() override;
};
#endif