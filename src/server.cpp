#include <iostream>
#include <thread>

#include "socket.h"
#include "ip.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "wininet.lib")

#include "windows_socket.h"

int create_server(int argc, char** argv)
{
	std::cout << "Starting server! :D" << std::endl;

#ifdef WIN32
	windows_internet epico{ MAKEWORD(2, 2) };
#endif

	try
	{
		auto listen_socket = Sockets::CreateListenSocket();
		auto ip_address = get_external_ip();
		std::cout << "server ip address is: " << ip_address << std::endl;

		auto receive_socket = listen_socket->accept_connection();

		// destroy listen socket
		listen_socket = nullptr;

		do
		{
			if (receive_socket->has_data())
			{
				vector<char> received_data = receive_socket->receive_data();

				cout << "Received data: " << std::string(received_data.begin(), received_data.end()) << endl;

				if (std::string(received_data.begin(), received_data.end()) == "disconnect" || received_data.size() == 0)
				{
					std::cout << "Stopping..." << std::endl;
					break;
				}
			}

			std::this_thread::sleep_for(1000ms);
		} while (true);
	}
	catch (std::exception& e)
	{
		std::cerr << "Caught exception: \"" << e.what() << '\"' << std::endl;
		return -1;
	}
	return 0;
