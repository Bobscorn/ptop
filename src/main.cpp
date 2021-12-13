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

#include "server.h"
#include "client.h"
#include "socket.h"
#include "ip.h"
#include "message.h"

struct thread_queue
{
    thread_queue() : messages(), queue_mutex() {}
    thread_queue(const thread_queue& other) = delete;

    queue<string> messages;
    shared_mutex queue_mutex;
};

enum class EXECUTION_STATUS
{
    CONTINUE = 0,
    CONNECTED,
    COMPLETE,
    FAILED,
};

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
T read_data(char* data, int& index, int data_len)
{
    int size = sizeof(T);
    if (index + size >= data_len)
        throw exception("Not enough data to read");

    T* ptr = (T*)&data[index];
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
    if (index + len * sizeof(char) > data_len)
        throw exception("Not enough data to read string characters");

    index += len;
    return std::string( data + index - len, data + index );
}

void hole_punch_clients(IDataSocket*& clientA, IDataSocket*& clientB)
{
    peer_data dataA, dataB;
    dataA = clientA->get_peer_data();
    dataB = clientB->get_peer_data();

    std::cout << "Hole punching clients: A(" << dataA.ip_address << ":" << dataA.port << "), B(" << dataB.ip_address << ":" << dataB.port << ")" << std::endl;

    clientA->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataB.to_bytes()));
    clientB->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataA.to_bytes()));

    clientA = nullptr;
    clientB = nullptr;
}

EXECUTION_STATUS process_data_server(char* data, unique_ptr<IDataSocket>& source, int data_len, string port, IDataSocket*& clientA, IDataSocket*& clientB)
{
    if (data_len < 1)
    {
        cout << "Received empty data from a client, disconnecting client" << endl;
        source = nullptr;
        return EXECUTION_STATUS::CONTINUE;
    }

    int i = 0;

    auto msg_type = read_data<MESSAGE_TYPE>(data, i, data_len);
    switch (msg_type)
    {
    case MESSAGE_TYPE::HELLO:
        if (clientA && clientB)
        {
            hole_punch_clients(clientA, clientB);
            return EXECUTION_STATUS::COMPLETE;
        }

        if (clientA)
        {
            if (source.get() != clientA)
            {
                cout << "Received ClientB hello" << endl;
                clientB = source.get();
                hole_punch_clients(clientA, clientB);
                return EXECUTION_STATUS::COMPLETE;
            }
        }
        else if (clientB)
        {
            if (source.get() != clientB)
            {
                cout << "Received new ClientA hello" << endl;
                clientA = source.get();
                hole_punch_clients(clientA, clientB);
                return EXECUTION_STATUS::COMPLETE;
            }
        }
        else
        {
            cout << "Received ClientA hello" << endl;
            clientA = source.get();
        }
        return EXECUTION_STATUS::CONTINUE;

    case MESSAGE_TYPE::NONE:
    default:
        return EXECUTION_STATUS::CONTINUE;
    }
}

EXECUTION_STATUS process_data(char* data, int data_len, string port, unique_ptr<IDataSocket>& data_socket, unique_ptr<IDataSocket>& peer_connect_socket)
{
    if (data_len < 1)
    {
        cout << "Received empty data, disconnecting" << endl;
        return EXECUTION_STATUS::COMPLETE;
    }

    int i = 0;

    auto msg_type = read_data<MESSAGE_TYPE>(data, i, data_len);
    switch (msg_type)
    {
    case MESSAGE_TYPE::MSG:
    {
        string msg = read_string(data, i, data_len);
        cout << "Message received from server: " << msg << std::endl;
        return EXECUTION_STATUS::CONTINUE;
    }
    case MESSAGE_TYPE::FILE:
        cout << "Received file from server" << endl;
        // TODO: actually read the file
        return EXECUTION_STATUS::CONTINUE;
        
    case MESSAGE_TYPE::CONNECT_PEER:
    {
        auto peer = read_peer_data(data, i, data_len);
        name_data old_name = data_socket->get_sock_data();
        data_socket = nullptr;

        unique_ptr<IReusableNonBlockingListenSocket> listen_sock = Sockets::CreateReusableNonBlockingListenSocket(port);
        listen_sock->listen();
        auto peer_connect = Sockets::CreateReusableConnectSocket(old_name);
        peer_connect->connect(peer.ip_address, peer.port);

        auto start_time = std::chrono::system_clock::now();
        do
        {
            if (listen_sock->has_connection())
            {
                cout << "Successfully accepted peer connection" << endl;
                data_socket = listen_sock->accept_connection();
                return EXECUTION_STATUS::CONNECTED;
            }
            if (peer_connect->has_connected() == ConnectionStatus::SUCCESS)
            {
                cout << "Successfully connected to peer" << endl;
                data_socket = peer_connect->convert_to_datasocket();
                return EXECUTION_STATUS::CONNECTED;
            }
            if (peer_connect->has_connected() == ConnectionStatus::FAILED)
            {
                cout << "Connecting failed, retrying" << endl;
                peer_connect->connect(peer.ip_address, peer.port);
            }
            this_thread::sleep_for(100ms);

            auto cur_time = chrono::system_clock::now();
            if (cur_time - start_time > 10s)
            {
                cerr << "Time out trying to hole punch reached" << endl;
                return EXECUTION_STATUS::FAILED;
            }
        } while (true);

        return EXECUTION_STATUS::CONTINUE;
    }
    case MESSAGE_TYPE::NONE:
    default:
        return EXECUTION_STATUS::CONTINUE;
    }

    return EXECUTION_STATUS::CONTINUE;
}

EXECUTION_STATUS process_data_peer(char* data, int data_len)
{
    if (data_len < 1)
    {
        cout << "Received empty data, disconnecting" << endl;
        return EXECUTION_STATUS::COMPLETE;
    }

    int i = 0;

    auto msg_type = read_data<MESSAGE_TYPE>(data, i, data_len);
    switch (msg_type)
    {
    case MESSAGE_TYPE::MSG:
    {
        string msg = read_string(data, i, data_len);
        cout << "Message received from peer: " << msg << endl;
        return EXECUTION_STATUS::CONTINUE;
    }
    case MESSAGE_TYPE::FILE:
        cout << "Received file from peer" << endl;
        // TODO: actually read the file
        return EXECUTION_STATUS::CONTINUE;

    case MESSAGE_TYPE::CONNECT_PEER:
    {
        cout << "Received Connect Peer message when already connected" << endl;

        return EXECUTION_STATUS::CONTINUE;
    }
    case MESSAGE_TYPE::NONE:
    default:
        return EXECUTION_STATUS::CONTINUE;
    }

    return EXECUTION_STATUS::CONTINUE;
}

string get_message_to_send()
{
    string responce;
    cout << "Send a message! ";
    getline(cin, responce);
    return responce;
}

int main(int argc, char** argv) {

#ifdef WIN32
    // windows_internet uses RAII to ensure WSAStartup and WSACleanup get called in the proper order
    windows_internet wsa_wrapper(MAKEWORD(2, 2));
#endif
    try
    {
        if (argc > 1 && !strcmp(argv[1], "server"))
        {
            cout << "Starting Rendezvous server!" << endl;

            unique_ptr<IDataSocket> clientA{}, clientB{};
            IDataSocket* cA = nullptr, * cB = nullptr;

            auto server_socket = Sockets::CreateListenSocket(Sockets::DefaultPort);

            server_socket->listen();
            std::vector<char> recv_data{};

            EXECUTION_STATUS status = EXECUTION_STATUS::CONTINUE;
            while (status == EXECUTION_STATUS::CONTINUE)
            {
                if ((!clientA || !clientB) && server_socket->has_connection())
                    (clientA ? clientB : clientA) = server_socket->accept_connection();

                if (clientA && clientA->has_data())
                {
                    recv_data = clientA->receive_data();
                    status = process_data_server(recv_data.data(), clientA, recv_data.size(), Sockets::DefaultPort, cA, cB);
                    if (status == EXECUTION_STATUS::COMPLETE)
                    {
                        cout << "Resetting server" << endl;
                        clientA = nullptr;
                        clientB = nullptr;
                        status = EXECUTION_STATUS::CONTINUE;
                    }
                }

                if (clientB && clientB->has_data())
                {
                    recv_data = clientB->receive_data();
                    status = process_data_server(recv_data.data(), clientB, recv_data.size(), Sockets::DefaultPort, cA, cB);
                    if (status == EXECUTION_STATUS::COMPLETE)
                    {
                        cout << "Resetting server" << endl;
                        clientA = nullptr;
                        clientB = nullptr;
                        status = EXECUTION_STATUS::CONTINUE;
                    }
                }
                this_thread::sleep_for(100ms);
            }
        }
        else
        {
            cout << "Starting p2p client!" << endl;
            cout << "Connecting to rendezvous server" << endl;
            unique_ptr<IDataSocket> server_conn = Sockets::CreateConnectionSocket("localhost", Sockets::DefaultPort);

            server_conn->send_data(create_message(MESSAGE_TYPE::HELLO, 0));

            unique_ptr<IDataSocket> peer_socket{};

            EXECUTION_STATUS status = EXECUTION_STATUS::CONTINUE;
            while (status == EXECUTION_STATUS::CONTINUE)
            {
                if (server_conn->has_data())
                {
                    auto data = server_conn->receive_data();
                    status = process_data(data.data(), data.size(), "6969", server_conn, peer_socket);
                }

                this_thread::sleep_for(100ms);
            }
            if (status == EXECUTION_STATUS::CONNECTED)
            {
                status = EXECUTION_STATUS::CONTINUE;
                cout << "Starting connection loop" << endl;
                thread_queue message_queue{};

                thread input_thread = thread([&message_queue]()
                    {
                        std::string input;
                        do
                        {
                            getline(cin, input);

                            {
                                std::unique_lock<shared_mutex> lock(message_queue.queue_mutex);
                                message_queue.messages.push(input);
                            }

                            this_thread::sleep_for(100ms);
                        } while (true);
                    });

                std::unique_lock<shared_mutex> take_message_lock(message_queue.queue_mutex, std::defer_lock);
                do
                {
                    if (server_conn->has_data())
                    {
                        auto data = server_conn->receive_data();
                        status = process_data_peer(data.data(), data.size());
                    }

                    {
                        if (take_message_lock.try_lock())
                        {
                            if (!message_queue.messages.empty())
                            {
                                string input_message = message_queue.messages.front();
                                message_queue.messages.pop();
                                server_conn->send_data(create_message(MESSAGE_TYPE::MSG, input_message));
                            }
                            take_message_lock.unlock();
                        }
                    }

                    this_thread::sleep_for(100ms);
                } while (status == EXECUTION_STATUS::CONTINUE);
                cout << "Closing program" << endl;
            }


            //auto receiver = create_server();
            //auto sender = create_client();

            //while (true) {

            //    //start server in separate threads

            //    //print your IP address

            //    //read terminal message for send command

            //    //start client in separate thread

            //    std::string message{};
            //    std::cin >> message;

            //    if (message == "") {
            //        continue;
            //    }

            //    //TransmitFile(socket, file, 0, 0, NULL, NULL, TF_WRITE_BEHIND); //file should be opened with FILE_FLAG_SEQUENTIAL_SCAN option

            //    int last_error = WSAGetLastError();

            //    if (last_error != 0) {

            //    }
            //}
        }
    }
    catch (const std::exception& e)
    {
        cout << "Caught exception: " << e.what() << std::endl;
        return -1;
    }
}

