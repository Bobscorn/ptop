#include "server.h"

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <functional>

#include "loop.h"
#include "message.h"
#include "ptop_socket.h"
#include "ip.h"

using namespace std::chrono;

server_init_kit::server_init_kit(protocol ip_proto) : proto(ip_proto) {
    clientA = nullptr;
    clientB = nullptr;
    cA = nullptr;
    cB = nullptr;
    server_socket = std::make_unique<PlatformListener>(ServerListenPort, ip_proto);
    server_socket->listen();
    recv_data = std::vector<char>();
    //dont need to initialize structs. it will default its params by itself
    
    status = EXECUTION_STATUS::CONTINUE;
}

server_init_kit::~server_init_kit() {}

void hole_punch_clients(IDataSocketWrapper*& clientA, IDataSocketWrapper*& clientB, const readable_ip_info& privA, const readable_ip_info& privB) //pointer reference allows changing the underlying data
{
    readable_ip_info dataA, dataB;
    dataA = clientA->get_peer_data();
    dataB = clientB->get_peer_data();

    std::cout << "Hole punching clients: A(" << dataA.ip_address << ":" << dataA.port << "), B(" << dataB.ip_address << ":" << dataB.port << ")" << std::endl;

    clientA->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER_AS_LEADER, dataB.to_bytes(), privB.to_bytes(), 69));
    clientB->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataA.to_bytes(), privA.to_bytes(), 69));

    clientA = nullptr;
    clientB = nullptr;
}

bool hole_punch_if_ready(IDataSocketWrapper*& clientA, IDataSocketWrapper*& clientB, const std::unique_ptr<readable_ip_info>& privA, const std::unique_ptr<readable_ip_info>& privB)
{
    if (clientA && clientB && privA && privB)
    {
        std::cout << "Ready for Hole Punch!" << std::endl;
        hole_punch_clients(clientA, clientB, *privA, *privB);
        return true;
    }
    return false;
}

EXECUTION_STATUS process_data_server(const Message& msg, std::unique_ptr<IDataSocketWrapper>& source, std::string port, IDataSocketWrapper*& clientA, IDataSocketWrapper*& clientB, std::unique_ptr<readable_ip_info>& privA, std::unique_ptr<readable_ip_info>& privB)
{
    const char* data = msg.Data.data();
    auto data_len = msg.Length;
    if (msg == Message::null_message)
    {
        std::cout << "Received empty data from a client (" << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << "), disconnecting client" << std::endl;
        source = nullptr;
        return EXECUTION_STATUS::CONTINUE;
    }

    int i = 0;

    auto msg_type = msg.Type;
    switch (msg_type)
    {
    case MESSAGE_TYPE::MY_DATA:

        if (source.get() == clientA)
        {
            std::cout << "Received ClientA (" << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << ")'s Private :3 data" << std::endl;
            privA = std::make_unique<readable_ip_info>(read_peer_data(data, i, data_len));
            if (hole_punch_if_ready(clientA, clientB, privA, privB))
                return EXECUTION_STATUS::COMPLETE;
        }
        else if (source.get() == clientB)
        {
            std::cout << "Received ClientB (" << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << ")'s Private :3 data" << std::endl;
            privB = std::make_unique<readable_ip_info>(read_peer_data(data, i, data_len));
            if (hole_punch_if_ready(clientA, clientB, privA, privB))
                return EXECUTION_STATUS::COMPLETE;
        }
        else if (!clientA)
        {
            std::cout << "Received Private :3 Data for a new Client (" << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << ") setting them to ClientA" << std::endl;
            clientA = source.get();
            privA = std::make_unique<readable_ip_info>(read_peer_data(data, i, data_len));
            if (hole_punch_if_ready(clientA, clientB, privA, privB))
                return EXECUTION_STATUS::COMPLETE;
        }
        else if (!clientB)
        {
            std::cout << "Received Private :3 Data for a new Client (" << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << ") setting them to ClientB" << std::endl;
            clientB = source.get();
            privB = std::make_unique<readable_ip_info>(read_peer_data(data, i, data_len));
            if (hole_punch_if_ready(clientA, clientB, privA, privB))
                return EXECUTION_STATUS::COMPLETE;
        }
        else
        {
            std::cout << "Received Private :3 Data (from: " << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << ") when both clients already exist(which might be a bug ? )" << std::endl;
        }

        return EXECUTION_STATUS::CONTINUE;
    case MESSAGE_TYPE::READY_FOR_P2P:
        if (clientA && clientB && privA && privB)
        {
            hole_punch_clients(clientA, clientB, *privA, *privB);
            return EXECUTION_STATUS::COMPLETE;
        }

        if (clientA)
        {
            if (source.get() != clientA)
            {
                std::cout << "Received ClientB hello" << std::endl;
                clientB = source.get();
                return EXECUTION_STATUS::CONTINUE;
            }
        }
        else if (clientB)
        {
            if (source.get() != clientB)
            {
                std::cout << "Received new ClientA hello" << std::endl;
                clientA = source.get();
                return EXECUTION_STATUS::CONTINUE;
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
        std::cout << "Ignoring Message (" << mt_to_string(msg_type) << ") from " << source->get_endpoint_ip() << ":" << source->get_endpoint_port() << std::endl;
        return EXECUTION_STATUS::CONTINUE;
    }
}

void print_status(const server_init_kit& protocol_kit)
{
    std::cout << "Server Socket " << (protocol_kit.server_socket->has_connection() ? "does " : "does NOT ") << "have a connection available" << std::endl;
    if (!protocol_kit.clientA)
        std::cout << "ClientA: NULL" << std::endl << "ClientA has sent and received 0 bytes (it is NULL)" << std::endl;
    else
        std::cout << "ClientA: " << protocol_kit.clientA->get_endpoint_ip() << ":" << protocol_kit.clientA->get_endpoint_port() << std::endl << "ClientA has seen " << protocol_kit.clientA->bytes_seen() << " bytes and sent " << protocol_kit.clientA->bytes_sent() << " bytes" << std::endl;
    if (!protocol_kit.clientB)
        std::cout << "ClientB: NULL" << std::endl << "ClientB has sent and received 0 bytes (is it NULL)" << std::endl;
    else
        std::cout << "ClientB: " << protocol_kit.clientB->get_endpoint_ip() << ":" << protocol_kit.clientB->get_endpoint_port() << std::endl << "ClientB has seen " << protocol_kit.clientB->bytes_seen() << " bytes and sent " << protocol_kit.clientB->bytes_sent() << " bytes" << std::endl;
}


void process_user_input(const server_init_kit& tcp_kit, const server_init_kit& udp_kit, thread_queue& queue)
{   
    std::unique_lock<std::shared_mutex> lock = std::unique_lock<std::shared_mutex>(queue.queue_mutex, std::defer_lock);
    if (lock.try_lock())
    {
        if (!queue.messages.empty())
        {
            std::string input_message = queue.messages.front();
            queue.messages.pop();
            if (input_message == "report" || input_message == "debug")
            {
                std::cout << "Reporting:" << std::endl;
                std::cout << "TCP Status: " << std::endl;
                print_status(tcp_kit);
                std::cout << "UDP Status: " << std::endl;
                print_status(udp_kit);
            }
            else if (input_message == "close" || input_message == "quit" || input_message == "shutdown")
            {
                std::cout << "Closing server..." << std::endl;
                lock.unlock();
                return;
            }
        }
        lock.unlock();
    }
}

void input_thread_func(thread_queue& message_queue)
{
    try
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
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

void server_loop()
{
    std::cout << "Starting Rendezvous server!" << std::endl;


    thread_queue user_input_queue{};

    std::thread user_input_thread{ input_thread_func, std::ref(user_input_queue) };
    user_input_thread.detach();

    server_init_kit init_tcp{ protocol{"tcp"} };
    server_init_kit init_udp{ protocol{"udp"} };

    while (true)
    {
        process_server_protocol(init_tcp);
        process_server_protocol(init_udp);

        process_user_input(init_tcp, init_udp, user_input_queue);

        std::this_thread::sleep_for(100ms);
    }
}

void process_server_protocol(server_init_kit& protocol_kit)
{
    // Look for clients
    if (protocol_kit.server_socket->has_connection())
    {
        std::cout << "Listen socket has available connection" << std::endl;
        if (!protocol_kit.clientA)
        {
            protocol_kit.clientA = protocol_kit.server_socket->accept_connection();
            std::cout << "Setting ClientA to available connection (" << protocol_kit.clientA->get_endpoint_ip() << ":" << protocol_kit.clientA->get_endpoint_port() << ")" << std::endl;
        }
        else if (!protocol_kit.clientB)
        {
            protocol_kit.clientB = protocol_kit.server_socket->accept_connection();
            std::cout << "Setting ClientB to available connection (" << protocol_kit.clientB->get_endpoint_ip() << ":" << protocol_kit.clientB->get_endpoint_port() << ")" << std::endl;
        }
        else
        {
            std::cout << "Found available connection but both ClientA and ClientB already assigned" << std::endl;
        }
    }

    // Look for incoming data
    if (protocol_kit.clientA && protocol_kit.clientA->has_message())
    {
        auto msg = protocol_kit.clientA->receive_message();
        protocol_kit.status = process_data_server(msg, protocol_kit.clientA, ServerListenPort, protocol_kit.cA, protocol_kit.cB, protocol_kit.privA, protocol_kit.privB);
        if (protocol_kit.status == EXECUTION_STATUS::COMPLETE)
        {
            std::cout << "Resetting server" << std::endl;
            protocol_kit.clientA = nullptr;
            protocol_kit.clientB = nullptr;
            protocol_kit.status = EXECUTION_STATUS::CONTINUE;
        }
    }

    if (protocol_kit.clientB && protocol_kit.clientB->has_message())
    {
        auto msg = protocol_kit.clientB->receive_message();
        protocol_kit.status = process_data_server(msg, protocol_kit.clientB, ServerListenPort, protocol_kit.cA, protocol_kit.cB, protocol_kit.privA, protocol_kit.privB);
        if (protocol_kit.status == EXECUTION_STATUS::COMPLETE)
        {
            std::cout << "Resetting server" << std::endl;
            protocol_kit.clientA = nullptr;
            protocol_kit.clientB = nullptr;
            protocol_kit.status = EXECUTION_STATUS::CONTINUE;
        }
    }
}
