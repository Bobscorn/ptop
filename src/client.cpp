#include "client.h"

#include <iostream>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "loop.h"
#include "message.h"
#include "socket.h"

using namespace std;

struct thread_queue
{
    thread_queue() : messages(), queue_mutex() {}
    thread_queue(const thread_queue& other) = delete;

    queue<string> messages;
    shared_mutex queue_mutex;
};

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


void client_loop()
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
}