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
    peer_data dataA, dataB;
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
        std::cout << "Received empty data from a client, disconnecting client" << std::endl;
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

    EXECUTION_STATUS status = EXECUTION_STATUS::CONTINUE;
    while (status == EXECUTION_STATUS::CONTINUE)
    {
        if ((!clientA || !clientB) && server_socket->has_connection())
            (clientA ? clientB : clientA) = server_socket->accept_connection();

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
        std::this_thread::sleep_for(100ms);
    }
}