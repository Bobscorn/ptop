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

#include "windows_socket.h"
#endif // WIN32

#include <string>
#include <iostream>
#include <stdio.h>

#include "server.h"
#include "client.h"
#include "socket.h"
#include "ip.h"

enum class EXECUTION_STATUS
{
    CONTINUE = 0,
    COMPLETE = 1,
    FAILED = 2,
};

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
T read_data(char* data, int& index, int data_len)
{
    int size = sizeof(T);
    if (index + size >= data_len)
        throw exception("Not enough data to read");

    T* ptr = (T*)data[index];
    index += size;
    return *ptr;
}

template<class T, typename = std::enable_if_t<std::is_pod_v<T>>>
std::vector<T> read_data(char* data, int& index, int data_len, int num_items)
{
    int size = sizeof(T);
    if (index + size * num_items >= data_len)
        throw exception("Not enough data to read");

    T* ptr = (T*)data[index];
    return std::vector<T>(ptr, ptr + num_items);
}

template<class size_T = int>
std::string read_string(char* data, int& index, int data_len)
{
    int size = sizeof(size_T);
    if (index + size >= data_len)
        throw exception("Not enough data to read string length");

    size_T len = read_data<size_T>(data, index, data_len);
    if (index + len * sizeof(char) >= data_len)
        throw exception("Not enough data to read string characters");

    index += len;
    return std::string( data + index - len, data + index );
}

EXECUTION_STATUS process_data(char* data, int data_len, string port, unique_ptr<ISocket>& server_socket, unique_ptr<ISocket>& peer_connect_socket)
{
    if (data_len < 1)
        return EXECUTION_STATUS::CONTINUE;

    int i = 0;

    auto msg_type = read_data<MESSAGE_TYPE>(data, i, data_len);
    switch (msg_type)
    {
    case MESSAGE_TYPE::MSG:
    {
        string msg = read_string(data, i, data_len);
        cout << "Message received: " << msg << std::endl;
        return EXECUTION_STATUS::CONTINUE;
    }
    case MESSAGE_TYPE::FILE:
        // TODO: actually read the file
        return EXECUTION_STATUS::CONTINUE;
        
    case MESSAGE_TYPE::CONNECT_PEER:
        auto peer = read_data<peer_data>(data, i, data_len);
        server_socket = nullptr;

        server_socket = Sockets::CreateReusableNonBlockingListenSocket(port);
        peer_connect_socket = Sockets::CreateReusableConnectSocket(peer.ip_address, peer.port);

        break;

    case MESSAGE_TYPE::NONE:
    default:
        return EXECUTION_STATUS::CONTINUE;
    }

    return EXECUTION_STATUS::CONTINUE;
}

int main(int argc, char* argv) {

#ifdef WIN32
    // windows_internet uses RAII to ensure WSAStartup and WSACleanup get called in the proper order
    windows_internet garbo(MAKEWORD(2, 2));
#endif

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

        //TransmitFile(socket, file, 0, 0, NULL, NULL, TF_WRITE_BEHIND); //file should be opened with FILE_FLAG_SEQUENTIAL_SCAN option
    
        int last_error = WSAGetLastError();

        if(last_error != 0) {

        }
    }
}

