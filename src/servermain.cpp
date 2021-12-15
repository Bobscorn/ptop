#include <iostream>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
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


int main(int argc, char** argv) {

#ifdef WIN32
    // windows_internet uses RAII to ensure WSAStartup and WSACleanup get called in the proper order
    windows_internet wsa_wrapper(MAKEWORD(2, 2));
#endif

    try
    {
        server_loop();
    }
    catch (const std::exception& e)
    {
        std::cout << "Caught exception: " << e.what() << std::endl;
        return -1;
    }
}

