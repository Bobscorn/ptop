#include <iostream>
#include <thread>

#include "socket.h"
#include "ip.h"

#ifdef WIN32
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
#endif

int main(int argc, char** argv)
{
	std::cout << "Starting server! :D" << std::endl;

#ifdef WIN32
	windows_internet epico{ MAKEWORD(2, 2) };
#endif

	try
	{
		auto listen_socket = Sockets::CreateListenSocket();

		//std::cout << "Found ip as: " << get_external_ip() << std::endl;

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

//	std::cout << "Starting MMR Server" << std::endl;
//
//	std::cout << "Initializing Winsock API" << std::endl;
//	// Initialize Winsock
//	WSAData wsaData;
//
//	int iResult;
//
//	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
//	if (iResult != 0)
//	{
//		std::cerr << "Winsock API intialization failed: " << iResult << std::endl;
//		return 1;
//	}
//
//	struct addrinfo* result = NULL, * ptr = NULL, hints;
//
//	ZeroMemory(&hints, sizeof(hints));
//	hints.ai_family = AF_INET;
//	hints.ai_socktype = SOCK_STREAM;
//	hints.ai_protocol = IPPROTO_TCP;
//	hints.ai_flags = AI_PASSIVE;
//
//	std::cout << "Resolving bind address and port" << std::endl;
//	// Resolve local address and port to bind to
//	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
//	if (iResult != 0)
//	{
//		std::cerr << "getaddreinfo failed: " << iResult << std::endl;
//		WSACleanup();
//		return 1;
//	}
//
//	SOCKET ListenSocket = INVALID_SOCKET;
//
//	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
//
//	if (ListenSocket == INVALID_SOCKET)
//	{
//		std::cerr << "Error at socket(): " << WSAGetLastError() << std::endl;
//		freeaddrinfo(result);
//		WSACleanup();
//		return 1;
//	}
//
//	std::cout << "Created socket" << std::endl;
//
//	std::cout << "Binding to socket..." << std::endl;
//
//	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
//	if (iResult == SOCKET_ERROR)
//	{
//		std::cerr << "Failed to bind with error: " << WSAGetLastError() << std::endl;
//		freeaddrinfo(result);
//		closesocket(ListenSocket);
//		WSACleanup();
//		return 1;
//	}
//
//	std::cout << "Successfully bound" << std::endl;
//
//	// No longer need addrinfo result
//	freeaddrinfo(result);
//
//	std::cout << "Start listening on port: " << DEFAULT_PORT << std::endl;
//	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR)
//	{
//		std::cerr << "Failed to list with: " << WSAGetLastError() << std::endl;
//		closesocket(ListenSocket);
//		WSACleanup();
//		return 1;
//	}
//
//	SOCKET ClientSocket = INVALID_SOCKET;
//
//	ClientSocket = accept(ListenSocket, NULL, NULL);
//	if (ClientSocket == INVALID_SOCKET)
//	{
//		std::cerr << "Failed to accept: " << WSAGetLastError() << std::endl;
//		closesocket(ListenSocket);
//		WSACleanup();
//		return 1;
//	}
//
//	// No longer need server socket
//	closesocket(ListenSocket);
//
//#define DEFAULT_BUFLEN 512
//
//	char recvbuf[DEFAULT_BUFLEN];
//	int iSendResult;
//	int recvbuflen = DEFAULT_BUFLEN;
//
//	do
//	{
//		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
//		if (iResult > 0)
//		{
//			std::cout << "Received " << iResult << " bytes" << std::endl;
//
//			// Echo the buffer back to the sender
//			iSendResult = send(ClientSocket, recvbuf, iResult, 0);
//			if (iSendResult == SOCKET_ERROR)
//			{
//				std::cerr << "Failed to echo data back on send(): " << WSAGetLastError() << std::endl;
//				closesocket(ClientSocket);
//				WSACleanup();
//				return 1;
//			}
//			std::cout << "Echoed back " << iSendResult << " bytes" << std::endl;
//		}
//		else if (iResult == 0)
//		{
//			std::cout << "Connection closing..." << std::endl;
//		}
//		else
//		{
//			std::cerr << "Receiving data failed (recv()): " << WSAGetLastError() << std::endl;
//			closesocket(ClientSocket);
//			WSACleanup();
//			return 1;
//		}
//	} while (iResult > 0);
//
//	iResult = shutdown(ClientSocket, SD_SEND);
//	if (iResult == SOCKET_ERROR)
//	{
//		std::cerr << "Shutting down client socket failed with: " << WSAGetLastError() << std::endl;
//		closesocket(ClientSocket);
//		WSACleanup();
//		return 1;
//	}
//
//	closesocket(ClientSocket);
//	WSACleanup();
//
//	return 0;
}