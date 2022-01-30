#pragma once

#include <string>

#include "name_data.h"
#include "message.h"

// BEGIN UDP CRAP

struct udp_Message
{
	Message message;
	raw_name_data from;
};

// END UDP CRAP

class ISocketWrapper
{
	public:
	virtual ~ISocketWrapper() {}

	virtual readable_ip_info get_peer_data() const = 0;
	virtual raw_name_data get_peername_raw() const = 0;
	virtual raw_name_data get_myname_raw() const = 0;
	virtual readable_ip_info get_peername_readable() const = 0;
	virtual readable_ip_info get_myname_readable() const = 0;

	virtual std::string get_my_ip() const = 0;
	virtual std::string get_my_port() const = 0;
	virtual std::string get_endpoint_ip() const = 0;
	virtual std::string get_endpoint_port() const = 0;
	virtual std::string get_identifier_str() = 0;

	virtual const std::string& get_name() const = 0;
	virtual void set_name(std::string name) = 0;
};

class IDataSocketWrapper : virtual public ISocketWrapper
{
	protected:
	size_t _seen_data = 0;
	size_t _sent_bytes = 0;

	public:
	virtual ~IDataSocketWrapper() {}


	virtual Message receive_message() = 0;
	virtual bool has_message() = 0;

	virtual bool send_data(const Message& message) = 0;

	inline size_t bytes_seen() { return _seen_data; }
	inline size_t bytes_sent() { return _sent_bytes; }
};

class IListenSocketWrapper
{
public:
	virtual ~IListenSocketWrapper() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual std::unique_ptr<IDataSocketWrapper> accept_connection() = 0;
};

class IReuseableSocketWrapper : virtual public ISocketWrapper
{
protected:
	IReuseableSocketWrapper() {}

public:
	virtual ~IReuseableSocketWrapper() {}
};

class INonBlockingConnector : public IReuseableSocketWrapper
{
public:
	virtual ~INonBlockingConnector() {}

	virtual void connect(std::string ip_address, std::string port) = 0;
	virtual ConnectionStatus has_connected() = 0;
};

class INonBlockingListener : public IReuseableSocketWrapper
{
public:
	virtual ~INonBlockingListener() {}

	virtual void listen() = 0;
	virtual bool has_connection() = 0;
	virtual std::unique_ptr<IDataSocketWrapper> accept_connection() = 0;
};