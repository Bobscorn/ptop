#include <iostream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <string>
#include <iostream>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <mswsock.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#include "server.h"
#include "client.h"
#include "socket.h"

int main(int argc, char* argv) {
    auto receiver = create_server();
    auto sender = create_client();
    
    while(true) {

        //start server in separate threads

        //print your IP address

        //read terminal message for send command

        //start client in separate thread

        std::string message{};
        std::cin >> message;

        if(message == "") {
            continue;
        }
        string 

        //TransmitFile(socket, file, 0, 0, NULL, NULL, TF_WRITE_BEHIND); //file should be opened with FILE_FLAG_SEQUENTIAL_SCAN option
    
        int last_error = WSAGetLastError();

        if(last_error != 0) {

        }
    }
}

