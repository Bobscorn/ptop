#include "socket_wrapper.h"
#include "protocol.h"

#include <string>
#include <memory>
#include <exception>
#include <stdexcept>

#if defined(WIN32) | defined(_WIN64)
#include "windows_platform.h"

extern readable_ip_info convert_to_readable(raw_name_data data);
readable_ip_info windows_name_data::as_readable() const { return convert_to_readable(*this); }
#elif __linux__
#include "linux_platform.h"

extern readable_ip_info convert_to_readable(raw_name_data data);
readable_ip_info linux_name_data::as_readable() const { return convert_to_readable(*this); }
#endif

const std::string Sockets::ServerListenPort = "27069";
const std::string Sockets::ClientListenPort = "6969";


std::unique_ptr<IListenSocketWrapper> Sockets::CreateListenSocket(std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<WindowsPlatformListener>(port, input_protocol);
#elif __linux__
		return std::make_unique<LinuxPlatformListener>(port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<IDataSocketWrapper> Sockets::CreateConnectionSocket(std::string peer_ip, std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<WindowsPlatformAnalyser>(peer_ip, port, input_protocol);
#elif __linux__
		return std::make_unique<LinuxPlatformAnalyser>(peer_ip, port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<INonBlockingListener> Sockets::CreateReusableNonBlockingListenSocket(raw_name_data data, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<WindowsReusableListener>(data, input_protocol);
#elif __linux__
		return std::make_unique<LinuxReusableListener>(data, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<INonBlockingConnector> Sockets::CreateReusableConnectSocket(raw_name_data data, std::string ip_address, std::string port, protocol input_protocol)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<WindowsReusableConnector>(data, ip_address, port, input_protocol);
#elif __linux__
		return std::make_unique<LinuxReusableConnector>(data, ip_address, port, input_protocol);
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
}

std::unique_ptr<IDataSocketWrapper> Sockets::ConvertToDataSocket(std::unique_ptr<INonBlockingConnector>&& old)
{
	try
	{
#if defined(WIN32) | defined(_WIN64)
		return std::make_unique<WindowsPlatformAnalyser>(std::move(old));
#elif __linux__
		return std::make_unique<LinuxPlatformAnalyser>(std::move(old));
#endif
	}
	catch (const std::exception& e)
	{
		throw_with_context(e, LINE_CONTEXT);
	}
	throw std::runtime_error("Failed to convert to datasocket");
}
