#pragma once

#include <string>

#include "ptop_socket.h"
#include "interfaces.h"

class Platform {    
    protected:    
	PtopSocket _socket;
	std::string _address;
	std::string _port;
	std::string _endpoint_address;
	std::string _endpoint_port;
	bool _endpoint_assigned = false;

	void update_name_info();
	void update_endpoint_info();
	void update_endpoint_if_needed();

	public:
    Platform(PtopSocket&& socket);
	static const std::string ServerListenPort;
	static const std::string ClientListenPort;

	static std::unique_ptr<IListenSocketWrapper> CreateListenSocket(std::string port, protocol proto);
	static std::unique_ptr<IDataSocketWrapper> CreateConnectionSocket(std::string peer_ip, std::string port, protocol proto);
	static std::unique_ptr<INonBlockingListener> CreateReusableNonBlockingListenSocket(raw_name_data data, protocol proto);
	static std::unique_ptr<INonBlockingConnector> CreateReusableConnectSocket(raw_name_data name, std::string ip_address, std::string port, protocol proto);
	static std::unique_ptr<IDataSocketWrapper> ConvertToDataSocket(std::unique_ptr<INonBlockingConnector>&& old);
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
    virtual ~Platform();
}