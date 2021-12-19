#include "server.h"

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <functional>

#include "loop.h"
#include "message.h"
#include "socket.h"

using namespace std::chrono;

server_init_kit::server_init_kit(std::function<void(thread_queue&)> thread_func) : message_queue() {
    clientA = std::unique_ptr<IDataSocket>();
    clientB = std::unique_ptr<IDataSocket>();
    cA = nullptr;
    cB = nullptr;
    server_socket = Sockets::CreateListenSocket(Sockets::ServerListenPort);
    server_socket->listen();
    recv_data = std::vector<char>();
    //dont need to initialize structs. it will default its params by itself

    input_thread = std::thread {
        thread_func,
        std::ref(message_queue)
    };
    input_thread.detach();
    take_message_lock = std::unique_lock<std::shared_mutex>(message_queue.queue_mutex, std::defer_lock);
    status = EXECUTION_STATUS::CONTINUE;
}

server_init_kit::server_init_kit(server_init_kit&& other) noexcept
{
    *this = std::move(other);
}

server_init_kit::~server_init_kit() {}

server_init_kit& server_init_kit::operator=(server_init_kit&& other) noexcept
{
    clientA = std::move(other.clientA);
    clientB = std::move(other.clientB);
    cA = other.cA;
    cB = other.cB;
    server_socket = std::move(other.server_socket);
    recv_data = std::move(other.recv_data);

    input_thread = std::move(other.input_thread);
    take_message_lock = std::move(other.take_message_lock);
    status = other.status;

    other.clientA = nullptr;
    other.clientB = nullptr;
    other.cA = nullptr;
    other.cB = nullptr;
    other.server_socket = nullptr;
    other.recv_data = std::vector<char>();
    other.input_thread = std::thread{};
    other.status = EXECUTION_STATUS::FAILED;

    return *this;
}

void hole_punch_clients(IDataSocket*& clientA, IDataSocket*& clientB, const readable_ip_info& privA, const readable_ip_info& privB) //pointer reference allows changing the underlying data
{
    readable_ip_info dataA, dataB;
    dataA = clientA->get_peer_data();
    dataB = clientB->get_peer_data();

    std::cout << "Hole punching clients: A(" << dataA.ip_address << ":" << dataA.port << "), B(" << dataB.ip_address << ":" << dataB.port << ")" << std::endl;

    clientA->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataB.to_bytes(), privB.to_bytes(), 69));
    clientB->send_data(create_message(MESSAGE_TYPE::CONNECT_PEER, dataA.to_bytes(), privA.to_bytes(), 69));

    clientA = nullptr;
    clientB = nullptr;
}

bool hole_punch_if_ready(IDataSocket*& clientA, IDataSocket*& clientB, const std::unique_ptr<readable_ip_info>& privA, const std::unique_ptr<readable_ip_info>& privB)
{
    if (clientA && clientB && privA && privB)
    {
        std::cout << "Ready for Hole Punch!" << std::endl;
        hole_punch_clients(clientA, clientB, *privA, *privB);
        return true;
    }
    return false;
}

EXECUTION_STATUS process_data_server(char* data, std::unique_ptr<IDataSocket>& source, size_t data_len, std::string port, IDataSocket*& clientA, IDataSocket*& clientB, std::unique_ptr<readable_ip_info>& privA, std::unique_ptr<readable_ip_info>& privB)
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
    catch (std::exception& e)
    {
        std::cerr << "Input Thread encountered exception: " << e.what() << std::endl;
    }
}

void server_loop()
{
    std::cout << "Starting Rendezvous server!" << std::endl;

    auto init = server_init_kit{ input_thread_func };

    while (init.status == EXECUTION_STATUS::CONTINUE)
    {
        // Look for clients
        if (init.server_socket->has_connection())
        {
            std::cout << "Listen socket has available connection" << std::endl;
            if (!init.clientA)
            {
                init.clientA = init.server_socket->accept_connection();
                std::cout << "Setting ClientA to available connection (" << init.clientA->get_endpoint_ip() << ":" << init.clientA->get_endpoint_port() << ")" << std::endl;
            }
            else if (!init.clientB)
            {
                init.clientB = init.server_socket->accept_connection();
                std::cout << "Setting ClientB to available connection (" << init.clientB->get_endpoint_ip() << ":" << init.clientB->get_endpoint_port() << ")" << std::endl;
            }
            else
            {
                std::cout << "Found available connection but both ClientA and ClientB already assigned" << std::endl;
            }
        }

        // Look for incoming data
        if (init.clientA && init.clientA->has_data())
        {
            init.recv_data = init.clientA->receive_data();
            init.status = process_data_server(init.recv_data.data(), init.clientA, init.recv_data.size(), Sockets::ServerListenPort, init.cA, init.cB, init.privA, init.privB);
            if (init.status == EXECUTION_STATUS::COMPLETE)
            {
                std::cout << "Resetting server" << std::endl;
                init.clientA = nullptr;
                init.clientB = nullptr;
                init.status = EXECUTION_STATUS::CONTINUE;
            }
        }

        if (init.clientB && init.clientB->has_data())
        {
            init.recv_data = init.clientB->receive_data();
            init.status = process_data_server(init.recv_data.data(), init.clientB, init.recv_data.size(), Sockets::ServerListenPort, init.cA, init.cB, init.privA, init.privB);
            if (init.status == EXECUTION_STATUS::COMPLETE)
            {
                std::cout << "Resetting server" << std::endl;
                init.clientA = nullptr;
                init.clientB = nullptr;
                init.status = EXECUTION_STATUS::CONTINUE;
            }
        }

        // Process input from other thread

        if (init.take_message_lock.try_lock())
        {
            if (!init.message_queue.messages.empty())
            {
                std::string input_message = init.message_queue.messages.front();
                init.message_queue.messages.pop();
                if (input_message == "report" || input_message == "debug")
                {
                    std::cout << "Reporting:" << std::endl;
                    std::cout << "Server Socket " << (init.server_socket->has_connection() ? "does " : "does NOT ") << "have a connection available" << std::endl;
                    if (!init.clientA)
                        std::cout << "ClientA: NULL" << std::endl << "ClientA has sent and received 0 bytes (it is NULL)" << std::endl;
                    else
                        std::cout << "ClientA: " << init.clientA->get_endpoint_ip() << ":" << init.clientA->get_endpoint_port() << std::endl << "ClientA has seen " << init.clientA->bytes_seen() << " bytes and sent " << init.clientA->bytes_sent() << " bytes" << std::endl;
                    if (!init.clientB)
                        std::cout << "ClientB: NULL" << std::endl << "ClientB has sent and received 0 bytes (is it NULL)" << std::endl;
                    else
                        std::cout << "ClientB: " << init.clientB->get_endpoint_ip() << ":" << init.clientB->get_endpoint_port() << std::endl << "ClientB has seen " << init.clientB->bytes_seen() << " bytes and sent " << init.clientB->bytes_sent() << " bytes" << std::endl;
                }
                else if (input_message == "close" || input_message == "quit" || input_message == "shutdown")
                {
                    std::cout << "Closing server..." << std::endl;
                    init.take_message_lock.unlock();
                    return;
                }
            }
            init.take_message_lock.unlock();
        }

        std::this_thread::sleep_for(100ms);
    }
}

