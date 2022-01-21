#include "client.h"
#include "loop.h"
#include "message.h"
#include "ptop_socket.h"
#include "protocol.h"
#include "platform.h"
#include "ip.h"
#include "error.h"

#include <iostream>

using namespace std::chrono;

client_init_kit::client_init_kit(std::string server_address_pair, ::protocol chosen_protocol) : protocol(chosen_protocol) {
    conn_socket = std::make_unique<PlatformAnalyser>(server_address_pair, ServerListenPort, protocol);
    // Indicate to server we're ready for p2p
    last_send = std::chrono::system_clock::now();
    conn_socket->send_data(create_message(MESSAGE_TYPE::MY_DATA, conn_socket->get_myname_readable().to_bytes()));
    conn_socket->send_data(create_message(MESSAGE_TYPE::READY_FOR_P2P));
    status = EXECUTION_STATUS::CONTINUE;
    //int value types will update themselves
    protocol = chosen_protocol;
}

client_init_kit::~client_init_kit() {}

EXECUTION_STATUS process_auth(const Message& mess, std::unique_ptr<IDataSocketWrapper>& socket, int my_auth)
{
    const char* data = mess.Data.data();
    size_t data_len = mess.Length;
    int i = 0;
    int auth_key = 0;
    MESSAGE_TYPE type = mess.Type;

    switch (type)
    {
        case MESSAGE_TYPE::AUTH_PLS:
            std::cout << "Peer (" << socket->get_endpoint_ip() << ":" << socket->get_endpoint_port() << ") requesting Auth, responding with key" << std::endl;
            socket->send_data(create_message(MESSAGE_TYPE::HERES_YOUR_AUTH, my_auth));
            return EXECUTION_STATUS::CONTINUE;
        case MESSAGE_TYPE::HERES_YOUR_AUTH:
            std::cout << "Peer (" << socket->get_endpoint_ip() << ":" << socket->get_endpoint_port() << ") has replied with key" << std::endl;
            if (!try_read_data<int>(data, i, data_len, auth_key))
            {
                std::cout << "Failed to read key from peer" << std::endl;
                return EXECUTION_STATUS::FAILED;
            }

            if (auth_key == my_auth)
            {
                std::cout << "Key matches, we should be connected!" << std::endl;
                return EXECUTION_STATUS::CONNECTED;
            }
            std::cout << "Key did not match" << std::endl;
            return EXECUTION_STATUS::FAILED;
        default:
            std::cout << __func__ << "(" << __LINE__ << "): Ignoring Message with Type: " << mt_to_string(type) << std::endl;
            return EXECUTION_STATUS::CONTINUE;
    }
}

EXECUTION_STATUS hole_punch(client_init_kit& kit, const char* data, int& auth_key_out, int i, MESSAGE_LENGTH_T data_len) {
    try
    {
        // Server giving us a peer to connect to
        // Attempt to connect to peer by connecting to it and listening for a connection
        // The connect socket must have same local address binding as the socket that connected to the server
        // And we must disconnect the connection to the server

        std::cout << "Attempting to Hole Punch" << std::endl;

        auto peer_public = read_peer_data(data, i, data_len);
        auto peer_private = read_peer_data(data, i, data_len);
        auth_key_out = read_data<int>(data, i, data_len);
        raw_name_data old_privatename = kit.conn_socket->get_myname_raw();
        kit.conn_socket = nullptr;

        std::cout << "Target is: " << peer_private.ip_address << ":" << peer_private.port << "/" << peer_public.ip_address << ":" << peer_public.port << " priv/pub" << std::endl;
        std::this_thread::sleep_for(100ms);

        auto listen_sock = std::make_unique<ReusableListener>(old_privatename, kit.protocol);
        listen_sock->listen();
        auto peer_pub_connect = std::make_unique<ReusableConnector>(old_privatename, peer_public.ip_address, peer_public.port, kit.protocol);
        auto peer_priv_connect = std::make_unique<ReusableConnector>(old_privatename, peer_private.ip_address, peer_private.port, kit.protocol);

        std::vector<std::unique_ptr<IDataSocketWrapper>> unauthed_sockets{};

        auto start_time = std::chrono::system_clock::now();
        auto current_time = start_time;

        do
        {
            for (size_t i = unauthed_sockets.size(); i-- > 0; )
            {
                auto& sock = unauthed_sockets[i];

                if (sock && sock->has_message())
                {
                    auto status = process_auth(sock->receive_message(), sock, auth_key_out);

                    if (status == EXECUTION_STATUS::FAILED)
                    {
                        std::cout << "Socket '" << sock->get_endpoint_ip() << ":" << sock->get_endpoint_port() << "' has failed to authenticate" << std::endl;
                        unauthed_sockets.pop_back();
                    }

                    else if (status == EXECUTION_STATUS::CONNECTED)
                    {
                        std::cout << "Socket '" << sock->get_endpoint_ip() << ":" << sock->get_endpoint_port() << "' has successfully authenticated" << std::endl;
                        kit.conn_socket = std::move(sock); //caused a bug if we dont return immediately after
                        return EXECUTION_STATUS::CONNECTED; //we only care if either private or public sockets got punched, not both
                    }
                }
            }
            if (unauthed_sockets.size())
                continue;

            if (listen_sock->has_connection())
            {
                std::cout << "Successfully accepted peer connection, now authenticating them" << std::endl;
                unauthed_sockets.emplace_back(listen_sock->accept_connection());

                if (kit.is_leader)
                    unauthed_sockets.back()->send_data(create_message(MESSAGE_TYPE::AUTH_PLS));

                std::this_thread::sleep_for(100ms);
                continue;
            }

            if (peer_priv_connect)
            {
                auto status = peer_priv_connect->has_connected();
                if (status == ConnectionStatus::SUCCESS)
                {
                    std::cout << "Private Connection has connected, now attempting to authenticate" << std::endl;
                    auto analyser = std::make_unique<PlatformAnalyser>(std::move(peer_priv_connect));
                    unauthed_sockets.emplace_back(std::move(analyser));
                    peer_priv_connect = nullptr;

                    if (kit.is_leader)
                        unauthed_sockets.back()->send_data(create_message(MESSAGE_TYPE::AUTH_PLS));

                    std::this_thread::sleep_for(100ms);
                    continue;
                }
                else if (status == ConnectionStatus::FAILED)
                {
                    std::cout << "Private Connection attempt failed, retrying..." << std::endl;
                    peer_priv_connect = std::make_unique<ReusableConnector>(old_privatename, peer_private.ip_address, peer_private.port, kit.protocol);
                }
            }

            if (peer_pub_connect)
            {
                auto status = peer_pub_connect->has_connected();
                if (status == ConnectionStatus::SUCCESS)
                {
                    std::cout << "Public Connection has connected, now authenticating" << std::endl;
                    unauthed_sockets.emplace_back(std::make_unique<PlatformAnalyser>(std::move(peer_pub_connect)));

                    if (kit.is_leader)
                        unauthed_sockets.back()->send_data(create_message(MESSAGE_TYPE::AUTH_PLS));

                    std::this_thread::sleep_for(100ms);
                    continue;
                }
                else if (status == ConnectionStatus::FAILED)
                {
                    std::cout << "Public Connection Failed, Retrying connection..." << std::endl;
                    peer_pub_connect = std::make_unique<ReusableConnector>(old_privatename, peer_public.ip_address, peer_public.port, kit.protocol);
                }
            }

            std::this_thread::sleep_for(100ms);
        } while (current_time - start_time < 15s);

        std::cerr << "Time out trying to hole punch reached" << std::endl;
        return EXECUTION_STATUS::FAILED;
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

EXECUTION_STATUS process_server_data(client_init_kit& kit, const Message& message)
{
    try
    {
        const char* data = message.Data.data();
        auto data_len = message.Length;

        if (message == Message::null_message)
        {
            std::cout << "Received empty data, disconnecting" << std::endl;
            return EXECUTION_STATUS::COMPLETE;
        }

        int i = 0;

        auto msg_type = message.Type;
        switch (msg_type)
        {
        case MESSAGE_TYPE::MSG:
        {
            std::string msg = read_string(data, i, data_len);
            std::cout << "Message received from server: " << msg << std::endl;
            return EXECUTION_STATUS::CONTINUE;
        }
        case MESSAGE_TYPE::FILE:
        {
            std::cout << "Received file from server" << std::endl;
            // TODO: actually read the file
            return EXECUTION_STATUS::CONTINUE;
        }
        case MESSAGE_TYPE::CONNECT_PEER:
        {
            return hole_punch(kit, data, kit.auth_key, i, data_len);
        }

        case MESSAGE_TYPE::CONNECT_PEER_AS_LEADER:
        {
            kit.is_leader = true;
            return hole_punch(kit, data, kit.auth_key, i, data_len);
        }

        case MESSAGE_TYPE::NONE:
        default:
            std::cout << __func__ << "(" << __LINE__ << "): Ignoring Message with Type: " << mt_to_string(msg_type) << std::endl;
            return EXECUTION_STATUS::CONTINUE;
        }
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

EXECUTION_STATUS process_peer_data(const Message& mess, const std::unique_ptr<IDataSocketWrapper>& peer, int auth_key)
{  
    const char* data = mess.Data.data();
    auto data_len = mess.Length;
    if (mess == Message::null_message)
    {
        std::cout << "Received empty data, disconnecting" << std::endl;
        return EXECUTION_STATUS::COMPLETE;
    }

    int i = 0;

    auto msg_type = mess.Type;
    switch (msg_type)
    {
        case MESSAGE_TYPE::AUTH_PLS:
        {
            std::cout << "Peer requesting authentication" << std::endl;

            peer->send_data(create_message(MESSAGE_TYPE::HERES_YOUR_AUTH, auth_key));

            return EXECUTION_STATUS::CONTINUE;
        }
        case MESSAGE_TYPE::MSG:
        {
            std::string msg = read_string(data, i, data_len);
            std::cout << "Message received from peer: " << msg << std::endl;
            return EXECUTION_STATUS::CONTINUE;
        }
        case MESSAGE_TYPE::FILE:
        {
            std::cout << "Received file from peer" << std::endl;
            // TODO: actually read the file
            return EXECUTION_STATUS::CONTINUE;
        }
        case MESSAGE_TYPE::CONNECT_PEER:
        {
            std::cout << "Received Connect Peer message when already connected" << std::endl;

            return EXECUTION_STATUS::CONTINUE;
        }
        
        case MESSAGE_TYPE::NONE:
        default:
            std::cout << __func__ << "(" << __LINE__ << "): Ignoring Message with Type: " << mt_to_string(msg_type) << std::endl;
            return EXECUTION_STATUS::CONTINUE;
    }
    return EXECUTION_STATUS::CONTINUE;
}


void client_loop(std::string server_address_pair, protocol input_protocol)
{
    std::cout << "Starting ptop!" << std::endl;
    std::cout << "Connecting to rendezvous server: " << server_address_pair << std::endl;
    client_init_kit kit{ server_address_pair, input_protocol };

    while (kit.status == EXECUTION_STATUS::CONTINUE) //listen at the start of protocol
    {
        auto now = std::chrono::system_clock::now();
        if (now - kit.last_send > 3s)
        {
            kit.conn_socket->send_data(create_message(MESSAGE_TYPE::READY_FOR_P2P));
            kit.last_send = now;
        }
        if (kit.conn_socket->has_message())
        {
            auto message = kit.conn_socket->receive_message();
            kit.status = process_server_data(kit, message);
        }

        std::this_thread::sleep_for(100ms);
    }


    if (kit.status == EXECUTION_STATUS::CONNECTED)
    {
        kit.status = EXECUTION_STATUS::CONTINUE;
        std::cout << "connected to peer. enter your message!" << std::endl;
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
        input_thread.detach();

        std::unique_lock<std::shared_mutex> take_message_lock(message_queue.queue_mutex, std::defer_lock);

        do {
            if (kit.conn_socket->has_message())
            {
                auto message = kit.conn_socket->receive_message();
                kit.status = process_peer_data(message, kit.conn_socket, kit.auth_key);
            }

            {
                if (take_message_lock.try_lock())
                {
                    if (!message_queue.messages.empty())
                    {
                        std::string input_message = message_queue.messages.front();
                        message_queue.messages.pop();
                        kit.conn_socket->send_data(create_message(MESSAGE_TYPE::MSG, input_message));
                    }
                    take_message_lock.unlock();
                }
            }
            std::this_thread::sleep_for(100ms);
            
        } while (kit.status == EXECUTION_STATUS::CONTINUE);

        std::cout << "finished sending to peer" << std::endl;
    }
}