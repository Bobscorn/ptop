#include <iostream>
#include <string>

#include "socket.h"

#ifdef WIN32
#include "windows_socket.h"
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
#endif


int main(int argc, char** argv)
{
    std::cout << "Starting Client (:" << std::endl;

#ifdef WIN32
    windows_internet garbo(MAKEWORD(2,2));
#endif

    std::cout << "Insert Address: ";
    std::string address{};
    std::cin >> address;
    std::cout << std::endl;
    try
    {
        auto send_socket = Sockets::CreateSenderSocket(address);

        std::string input;
        do
        {
            std::cout << "Send a message (enter \"disconnect\" to stop): ";
            std::getline(std::cin, input);
            std::cout << std::endl;

            send_socket->send_data(std::vector<char>(input.begin(), input.end()));

            if (input == "disconnect")
                break;

        } while (true);
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception Caught: \"" << e.what() << '\"' << std::endl;
        return -1;
    }
    return 0;


//    std::cout << "Hello World!" << std::endl;
//
//    // Initialize Winsock
//    std::cout << "Initializing Winsock" << std::endl;
//    WSADATA wsaData;
//
//    int iResult;
//
//    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
//
//    if (iResult != 0)
//    {
//        std::cerr << "WSAStartup failed: " << iResult << std::endl;
//        return 1;
//    }
//
//    // Initialized
//    std::cout << "Winsock Initialized" << std::endl;
//
//    std::cout << "Using port " << DEFAULT_PORT << std::endl;
//
//
//    struct addrinfo* result = NULL,
//        * ptr = NULL,
//        hints;
//
//    ZeroMemory(&hints, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_TCP;
//
//    std::cout << "Resolving server with IP " << argv[1] << '\'' << std::endl;
//
//    // Resolve the server address and port
//    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
//
//    if (iResult != 0) {
//        std::cerr << "Failed to resolve server: " << iResult << std::endl;
//        WSACleanup();
//        return 1;
//    }
//
//    SOCKET ConnectSocket = INVALID_SOCKET;
//
//    // As result is an addrinfo array, we'll just connect to the first
//    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
//    {
//
//        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
//        if (ConnectSocket == INVALID_SOCKET)
//        {
//            std::cerr << "Error creating client socket (socket()):" << WSAGetLastError() << std::endl;
//            freeaddrinfo(result);
//            WSACleanup();
//            return 1;
//        }
//
//        // Connect to server.
//        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
//        if (iResult == SOCKET_ERROR) {
//            closesocket(ConnectSocket);
//            ConnectSocket = INVALID_SOCKET;
//            continue;
//        }
//        break;
//    }
//
//    
//
//    freeaddrinfo(result);
//
//    if (ConnectSocket == INVALID_SOCKET) {
//        printf("Unable to connect to server!\n");
//        WSACleanup();
//        return 1;
//    }
//
//    std::cout << "Connected, now attempting to send data" << std::endl;
//
//#define DEFAULT_BUFLEN 512
//
//    int recvbuflen = DEFAULT_BUFLEN;
//
//    const char* sendbuf = "this is a test";
//    char recvbuf[DEFAULT_BUFLEN];
//
//    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
//    if (iResult == SOCKET_ERROR)
//    {
//        std::cerr << "Sending data failed (send()): " << WSAGetLastError() << std::endl;
//        closesocket(ConnectSocket);
//        WSACleanup();
//        return 1;
//    }
//
//    std::cout << "Sent " << iResult << " bytes of data!" << std::endl;
//
//    iResult = shutdown(ConnectSocket, SD_SEND);
//    if (iResult == SOCKET_ERROR)
//    {
//        std::cerr << "shutdown failed with: " << WSAGetLastError() << std::endl;
//        closesocket(ConnectSocket);
//        WSACleanup();
//        return 1;
//    }
//
//    // Receive data until the server closes the connection
//    do {
//        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
//        if (iResult > 0)
//            printf("Bytes received: %d\n", iResult);
//        else if (iResult == 0)
//            printf("Connection closed\n");
//        else
//            printf("recv failed: %d\n", WSAGetLastError());
//    } while (iResult > 0);
//
//    // cleanup
//    closesocket(ConnectSocket);
//    WSACleanup();

    return 0;
}