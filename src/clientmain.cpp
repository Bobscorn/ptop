#include "server.h"
#include "client.h"
#include "ip.h"
#include "message.h"
#include "protocol.h"
#include "error.h"

#if defined(WIN32) | defined(_WIN64)
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
#include "windows_internet.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "wininet.lib")
#endif

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

using namespace std::chrono;

int main(int argc, char** argv) {

    try
    {
#if defined(WIN32) | defined(_WIN64)
        // windows_internet uses RAII to ensure WSAStartup and WSACleanup get called in the proper order
        windows_internet wsa_wrapper(MAKEWORD(2, 2));
#endif

        std::cout << "Please enter the rendezvous server's IP:" << std::endl;
        std::string raw_ip{};

        std::cin >> raw_ip;

        if (raw_ip == "") {
            std::this_thread::sleep_for(100ms); //epic optimization
            return 0;
        }

        std::cout << "Please enter your protocol of choice:" << std::endl;
        std::string possible_protocol{};

        std::cin >> possible_protocol;
        Protocol validated{ possible_protocol };

        client_loop(raw_ip, validated);
    }
    catch (const std::exception& e)
    {
        print_exception(e);
        return -1;
    }

    return 0;

    // std::string raw_ip{};
    // std::cin >> raw_ip;

    // if (raw_ip == "") {
    //     continue;
    // }

    // //TransmitFile(socket, file, 0, 0, NULL, NULL, TF_WRITE_BEHIND); //file should be opened with FILE_FLAG_SEQUENTIAL_SCAN option

    // int last_error = WSAGetLastError();

    // if (last_error != 0) {

    // }
}

