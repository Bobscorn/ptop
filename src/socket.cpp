#include "socket.h"

#ifdef WIN32
#include "windows_socket.h"
#elif __linux__

#endif

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
	return make_unique<linux_send_socket>(peer_ip, port);
#endif
}

unique_ptr<IReusableNonBlockingListenSocket> Sockets::CreateReusableNonBlockingListenSocket(string port)
{
#ifdef WIN32
	return make_unique<windows_reusable_nonblocking_listen_socket>(port);
#elif __linux__

#endif
}

unique_ptr<IReusableNonBlockingConnectSocket> Sockets::CreateReusableConnectSocket()
{
#ifdef WIN32
	return make_unique<windows_reusable_nonblocking_connection_socket>();
#elif __linux__

#endif
}
