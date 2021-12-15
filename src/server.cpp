#include "server.h"

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>

#include "loop.h"
#include "message.h"
#include "socket.h"

using namespace std::chrono;

void hole_punch_clients(IDataSocket*& clientA, IDataSocket*& clientB)
{
    readable_ip_info dataA, dataB;
    dataA = clientA->get_peer_data();
    dataB = clientB->get_peer_data();

    std::cout << "Hole punching clients: A(" << dataA.ip_address << ":" << dataA.port << "), B(" << dataB.ip_address << ":" << dataB.port << ")" << std::endl;

    clientA->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataB.to_bytes()));
    clientB->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataA.to_bytes()));

    clientA = nullptr;
    clientB = nullptr;
}

EXECUTION_STATUS process_data_server(char* data, std::unique_ptr<IDataSocket>& source, int data_len, std::string port, IDataSocket*& clientA, IDataSocket*& clientB)
{
    if (data_len < 1)
    {
        std::cout << "Received empty data from a client (" << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << "), disconnecting client" << std::endl;
        source = nullptr;
        return EXECUTION_STATUS::CONTINUE;
    }

    int i = 0;

    auto msg_type = read_data<MESSAGE_TYPE>(data, i, data_len);
    switch (msg_type)
    {
    case MESSAGE_TYPE::READY_FOR_P2P:
        if (clientA && clientB)
        {
            hole_punch_clients(clientA, clientB);
            return EXECUTION_STATUS::COMPLETE;
        }

        if (clientA)
        {
            if (source.get() != clientA)
            {
                std::cout << "Received ClientB hello" << std::endl;
                clientB = source.get();
                hole_punch_clients(clientA, clientB);
                return EXECUTION_STATUS::COMPLETE;
            }
        }
        else if (clientB)
        {
            if (source.get() != clientB)
            {
                std::cout << "Received new ClientA hello" << std::endl;
                clientA = source.get();
                hole_punch_clients(clientA, clientB);
                return EXECUTION_STATUS::COMPLETE;
            }
        }
        else
        {
            std::cout << "Received ClientA hello" << std::endl;
            clientA = source.get();
        }
        return EXECUTION_STATUS::CONTINUE;

    case MESSAGE_TYPE::NONE:
    default:
        return EXECUTION_STATUS::CONTINUE;
    }
}

void init_server() {

}

void server_loop()
{
    std::cout << "Starting Rendezvous server!" << std::endl;

    std::unique_ptr<IDataSocket> clientA{}, clientB{};
    IDataSocket* cA = nullptr, * cB = nullptr;

    auto server_socket = Sockets::CreateListenSocket(Sockets::ServerListenPort);

    server_socket->listen();
    std::vector<char> recv_data{};
    thread_queue message_queue{};

    std::thread input_thread = std::thread([&message_queue]()
        {
            std::string input;
            do
            {
                std::getline(std::cin, input); //waits until cin input
                {
                    std::unique_lock<std::shared_mutex> lock(message_queue.queue_mutex);
                    message_queue.messages.push(input);
                }

                std::this_thread::sleep_for(100ms);
            } while (true);
        });

    std::unique_lock<std::shared_mutex> take_message_lock(message_queue.queue_mutex, std::defer_lock);

    EXECUTION_STATUS status = EXECUTION_STATUS::CONTINUE;
    while (status == EXECUTION_STATUS::CONTINUE)
    {
        // Look for clients
        if (server_socket->has_connection())
        {
            std::cout << "Listen socket has available connection" << std::endl;
            if (!clientA)
            {
                clientA = server_socket->accept_connection();
                std::cout << "Setting ClientA to available connection (" << clientA->get_endpoint_ip() << ":" << clientA->get_endpoint_port() << ")" << std::endl;
            }
            else if (!clientB)
            {
                clientB = server_socket->accept_connection();
                std::cout << "Setting ClientB to available connection (" << clientB->get_endpoint_ip() << ":" << clientB->get_endpoint_port() << ")" << std::endl;
            }
            else
            {
                std::cout << "Found available connection but both ClientA and ClientB already assigned" << std::endl;
            }
        }

        // Look for incoming data
        if (clientA && clientA->has_data())
        {
            recv_data = clientA->receive_data();
            status = process_data_server(recv_data.data(), clientA, recv_data.size(), Sockets::ServerListenPort, cA, cB);
            if (status == EXECUTION_STATUS::COMPLETE)
            {
                std::cout << "Resetting server" << std::endl;
                clientA = nullptr;
                clientB = nullptr;
                status = EXECUTION_STATUS::CONTINUE;
            }
        }

        if (clientB && clientB->has_data())
        {
            recv_data = clientB->receive_data();
            status = process_data_server(recv_data.data(), clientB, recv_data.size(), Sockets::ServerListenPort, cA, cB);
            if (status == EXECUTION_STATUS::COMPLETE)
            {
                std::cout << "Resetting server" << std::endl;
                clientA = nullptr;
                clientB = nullptr;
                status = EXECUTION_STATUS::CONTINUE;
            }
        }

        // Process input from other thread

        if (take_message_lock.try_lock())
        {
            if (!message_queue.messages.empty())
            {
                std::string input_message = message_queue.messages.front();
                message_queue.messages.pop();
                if (input_message == "report" || input_message == "debug")
                {
                    std::cout << "Reporting:" << std::endl;
                    std::cout << "Server Socket " << (server_socket->has_connection() ? "does " : "does NOT ") << "have a connection available" << std::endl;
                    if (!clientA)
                        std::cout << "ClientA: NULL" << std::endl << "ClientA has sent and received 0 bytes (it is NULL)" << std::endl;
                    else
                        std::cout << "ClientA: " << clientA->get_endpoint_ip() << ":" << clientA->get_endpoint_port() << std::endl << "ClientA has seen " << clientA->bytes_seen() << " bytes and sent " << clientA->bytes_sent() << " bytes" << std::endl;
                    if (!clientB)
                        std::cout << "ClientB: NULL" << std::endl << "ClientB has sent and received 0 bytes (is it NULL)" << std::endl;
                    else
                        std::cout << "ClientB: " << clientB->get_endpoint_ip() << ":" << clientB->get_endpoint_port() << std::endl << "ClientB has seen " << clientB->bytes_seen() << " bytes and sent " << clientB->bytes_sent() << " bytes" << std::endl;
                }
            }
            take_message_lock.unlock();
        }

        std::this_thread::sleep_for(100ms);
    }
}