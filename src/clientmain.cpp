#include <iostream>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mswsock.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "wininet.lib")

#include "windows_socket.h"
#endif // WIN32

#include <string>
#include <iostream>
#include <stdio.h>
#include <thread>
#include <future>
#include <chrono>
#include <shared_mutex>
#include <mutex>
#include <queue>
#include <string.h>

#include "server.h"
#include "client.h"
#include "socket.h"
#include "ip.h"
#include "message.h"

using namespace std::chrono;

void print_exception(const std::exception& e, int level = 0)
{
    std::cerr << std::string(level, ' ') << "exception: " << e.what() << std::endl;
    try
    {
        std::rethrow_if_nested(e);
    }
    catch (const std::exception& e)
    {
        print_exception(e, level + 1);
    }
    catch (...) {}
}

int main(int argc, char** argv) {

#ifdef WIN32
    // windows_internet uses RAII to ensure WSAStartup and WSACleanup get called in the proper order
    windows_internet wsa_wrapper(MAKEWORD(2, 2));
#endif

    try
    {
        std::cout << "Please enter the rendezvous server's IP:" << std::endl;
        std::string message{};

        std::cin >> message;

        do {
            if (message == "") {
                std::this_thread::sleep_for(100ms); //epic optimization
                continue;
            }
        }
        while(false);
            
        client_loop(message);
        


        // std::string message{};
        // std::cin >> message;

        // if (message == "") {
        //     continue;
        // }

        // //TransmitFile(socket, file, 0, 0, NULL, NULL, TF_WRITE_BEHIND); //file should be opened with FILE_FLAG_SEQUENTIAL_SCAN option

        // int last_error = WSAGetLastError();

        // if (last_error != 0) {

        // }
    }
    
    catch (const std::exception& e)
    {
        print_exception(e);
    }
}

