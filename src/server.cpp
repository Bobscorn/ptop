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
#include <thread>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "wininet.lib")

#include "windows_socket.h"

unique_ptr<IReceiverSocket> create_server()
{
	cout << "Starting server! :D" << endl;

#ifdef WIN32
	windows_internet epico{ MAKEWORD(2, 2) };
#endif

	try
	{
		auto listen_socket = Sockets::CreateListenSocket();
		auto ip_address = get_external_ip();
		cout << "server ip address is: " << ip_address << endl;

		auto receive_socket = listen_socket->accept_connection();
		listen_socket = nullptr; // destroy listen socket

		thread do_server_stuff(func);

		return receive_socket;
	}
	catch (exception& e)
	{
		cerr << "Caught exception: \"" << e.what() << '\"' << endl;
		return NULL;
	}
}

void do_server_stuff(windows_receive_socket receiver) {
	do {
		if (receiver.has_data())
		{
			vector<char> received_data = receive_socket.receive_data();

			cout << "Received data: " << string(received_data.begin(), received_data.end()) << endl;

			if (string(received_data.begin(), received_data.end()) == "disconnect" || received_data.size() == 0)
			{
				cout << "Stopping..." << endl;
				break;
			}
		}

		this_thread::sleep_for(1000ms);
	} while (true);
}