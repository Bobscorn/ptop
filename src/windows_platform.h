#pragma once

#include "socket_wrapper.h"
#include "ptop_socket.h"

#if defined(WIN32) | defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include <memory>
#include <string>
#include <queue>

#include "message.h"
#include "protocol.h"
#include "windows_platform.h"
#pragma warning( push )
#pragma warning(disable : 4250)

/// <summary>
/// An RAII Wrapper over WSAStartup and WSACleanup, called in constructors and destructors
/// </summary>
class windows_internet
{
	protected:
	WSAData _data;

	public:
	windows_internet(WORD versionRequested);
	~windows_internet();
};

readable_ip_info convert_to_readable(raw_name_data);

class WindowsPlatform : virtual public ISocketWrapper
{
protected:
	WindowsPlatform(PtopSocket&& sock);
	PtopSocket _socket;
	std::string _address;
	std::string _port;
	std::string _endpoint_address;
	std::string _endpoint_port;
	bool _endpoint_assigned = false;

	void update_name_info();
	void update_endpoint_info();
	void update_endpoint_if_needed();

	virtual ~WindowsPlatform() {}

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

	inline std::string get_identifier_str() const override { if (_endpoint_address.empty()) return std::string("(private: ") + _address + ":" + _port + ", pub: N/A)"; return std::string("(public: ") + _endpoint_address + ":" + _endpoint_port + ")"; }

	inline PtopSocket&& release_socket() { return std::move(_socket); }
};

class WindowsPlatformListener : public WindowsPlatform, public IListenSocketWrapper
{
	public:
	WindowsPlatformListener(std::string port, protocol input_protocol);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocketWrapper> accept_connection() override;
};

class WindowsPlatformAnalyser : public WindowsPlatform, public virtual IDataSocketWrapper
{
	std::queue<Message> _stored_messages;

	void process_socket_data();

	public:
	WindowsPlatformAnalyser(std::unique_ptr<INonBlockingConnector>&& old);
	WindowsPlatformAnalyser(PtopSocket&& socket);
	WindowsPlatformAnalyser(std::string peer_address, std::string peer_port, protocol input_protocol);

	Message receive_message() override;
	bool has_message() override;

	bool send_data(const Message& message) override;
};

class WindowsReusableListener : public WindowsPlatform, public INonBlockingListener
{
public:
	WindowsReusableListener(std::string port, protocol input_protocol);

	void listen() override;
	bool has_connection() override;
	std::unique_ptr<IDataSocketWrapper> accept_connection() override;
};

class WindowsReusableConnector : public WindowsPlatform, public INonBlockingConnector
{
public:
	WindowsReusableConnector(raw_name_data private_binding, std::string ip_address, std::string port, protocol input_protocol);

	void connect(std::string ip_address, std::string port) override; // Called in constructor, can be called again if it fails
	ConnectionStatus has_connected() override;
};

#pragma warning(pop)

#endif