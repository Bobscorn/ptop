#include "socket.h"

#include <string>
#include <memory>

#ifdef WIN32
#include "windows_socket.h"
#elif __linux__
#include "linux_socket.h"
#endif

using namespace std;

const string Sockets::DefaultPort = "27069";

unique_ptr<IListenSocket> Sockets::CreateListenSocket(string port)
{
#ifdef WIN32
	return make_unique<windows_listen_socket>(port);
#elif __linux__
	return make_unique<linux_listen_socket>(port);
#endif
}

unique_ptr<IDataSocket> Sockets::CreateConnectionSocket(string peer_ip, string port)
{
#ifdef WIN32
	return make_unique<windows_data_socket>(peer_ip, port);
#elif __linux__
	return make_unique<linux_data_socket>(peer_ip, port);
#endif
}

unique_ptr<IReusableNonBlockingListenSocket> Sockets::CreateReusableNonBlockingListenSocket(string port)
{
#ifdef WIN32
	return make_unique<windows_reusable_nonblocking_listen_socket>(port);
#elif __linux__
	return make_unique<linux_reuse_nonblock_listen_socket>(port);
#endif
}

unique_ptr<IReusableNonBlockingConnectSocket> Sockets::CreateReusableConnectSocket(name_data data)
{
#ifdef WIN32
	return make_unique<windows_reusable_nonblocking_connection_socket>(data);
#elif __linux__
	return make_unique<linux_reuse_nonblock_connection_socket>(data);
#endif
}
