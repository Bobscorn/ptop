#include "socket.h"

#ifdef WIN32
#include "windows_socket.h"
#endif

std::unique_ptr<IListenSocket> Sockets::CreateListenSocket()
{
#ifdef WIN32
	return make_unique<windows_listen_socket>();
#elif __linux__
	return make_unique<linux_listen_socket>();
#endif
}

std::unique_ptr<ISenderSocket> Sockets::CreateSenderSocket(string peer_ip)
{
#ifdef WIN32
	return make_unique<windows_send_socket>(peer_ip);
#elif __linux__
	return make_unique<linux_send_socket>(peer_ip);
#endif
}
