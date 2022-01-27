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
    _server_socket = std::make_unique<PlatformAnalyser>(server_address_pair, ServerListenPort, protocol);
    // Indicate to server we're ready for p2p
    last_send = std::chrono::system_clock::now();
    _server_socket->send_data(create_message(MESSAGE_TYPE::MY_DATA, _server_socket->get_myname_readable().to_bytes()));
    _server_socket->send_data(create_message(MESSAGE_TYPE::READY_FOR_P2P));
    status = EXECUTION_STATUS::CONTINUE;
    //int value types will update themselves
    protocol = chosen_protocol;
}

std::unique_ptr<IDataSocketWrapper>& client_init_kit::get_server_socket() {
    return _server_socket; //yay bug
}

void client_init_kit::set_server_socket(std::unique_ptr<IDataSocketWrapper>&& input) {
    _server_socket = std::move(input);

    if(input == nullptr)
        std::cout << "client_init_kit: connection socket set to nullptr mmk?" << std::endl;
}

client_auth_kit::client_auth_kit(client_init_kit& init_kit, const char* data, int i, MESSAGE_LENGTH_T data_len) {
    peer_public = read_peer_data(data, i, data_len);
    peer_private = read_peer_data(data, i, data_len);
    std::cout << "Target is: " << peer_private.ip_address << ":" << peer_private.port << "/" << peer_public.ip_address << ":" << peer_public.port << " priv/pub" << std::endl;

    auth_key_out = read_data<int>(data, i, data_len);
    old_privatename = init_kit.get_server_socket()->get_myname_raw();
    init_kit.set_conn_socket(nullptr);
        
    listen_sock = std::make_unique<ReusableListener>(old_privatename, init_kit.protocol);
    listen_sock->listen();
    public_connector = std::make_unique<ReusableConnector>(old_privatename, peer_public.ip_address, peer_public.port, init_kit.protocol);
    private_connector = std::make_unique<ReusableConnector>(old_privatename, peer_private.ip_address, peer_private.port, init_kit.protocol);

    std::vector<std::unique_ptr<IDataSocketWrapper>> unauthed_sockets{};
}


EXECUTION_STATUS process_auth(const Message& mess, std::unique_ptr<IDataSocketWrapper>& socket, int my_auth)
{
    if (mess == Message::null_message)
        return EXECUTION_STATUS::FAILED;

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

EXECUTION_STATUS respond_to_auth(client_init_kit& init_kit, client_auth_kit& auth_kit) {
    for (size_t i = auth_kit.unauthed_sockets.size(); i-- > 0; )
    {
        auto& sock = auth_kit.unauthed_sockets[i];

        if (sock && sock->has_message())
        {
            auto status = process_auth(sock->receive_message(), sock, auth_kit.auth_key_out);

            if (status == EXECUTION_STATUS::FAILED)
            {
                std::cout << "Socket '" << sock->get_endpoint_ip() << ":" << sock->get_endpoint_port() << "' has failed to authenticate" << std::endl;
                auth_kit.unauthed_sockets.pop_back();
            }

            else if (status == EXECUTION_STATUS::CONNECTED)
            {
                std::cout << "Socket '" << sock->get_endpoint_ip() << ":" << sock->get_endpoint_port() << "' has successfully authenticated" << std::endl;
                init_kit.set_server_socket(std::move(sock)); //caused a bug if we dont return immediately after
                return EXECUTION_STATUS::CONNECTED; //we only care if either private or public sockets got punched, not both
            }
        }
    }
    return EXECUTION_STATUS::CONTINUE;
}

bool check_for_auth_connection(client_init_kit& init_kit, client_auth_kit& auth_kit) {
    if (auth_kit.unauthed_sockets.size())
        return true;

    if (auth_kit.listen_sock->has_connection())
    {
        std::cout << "Successfully accepted peer connection, now authenticating them" << std::endl;
        auth_kit.unauthed_sockets.emplace_back(auth_kit.listen_sock->accept_connection());

        if (init_kit.is_leader)
            auth_kit.unauthed_sockets.back()->send_data(create_message(MESSAGE_TYPE::AUTH_PLS));

        std::this_thread::sleep_for(100ms);
        return true;
    }

    if (auth_kit.private_connector != nullptr)
    {
        auto status = auth_kit.private_connector->has_connected();
        if (status == ConnectionStatus::SUCCESS)
        {
            std::cout << "Private Connection has connected, now attempting to authenticate" << std::endl;
            auto analyser = std::make_unique<PlatformAnalyser>(std::move(auth_kit.private_connector));
            auth_kit.unauthed_sockets.emplace_back(std::move(analyser));
            auth_kit.private_connector = nullptr;

            if (init_kit.is_leader)
                auth_kit.unauthed_sockets.back()->send_data(create_message(MESSAGE_TYPE::AUTH_PLS));

            std::this_thread::sleep_for(100ms);
            return true;
        }
        else if (status == ConnectionStatus::FAILED)
        {
            std::cout << "Private Connection attempt failed, retrying..." << std::endl;
            auth_kit.private_connector = std::make_unique<ReusableConnector>(auth_kit.old_privatename, auth_kit.peer_private.ip_address, auth_kit.peer_private.port, init_kit.protocol);
        }
    }

    if (auth_kit.public_connector != nullptr)
    {
        auto status = auth_kit.public_connector->has_connected();
        if (status == ConnectionStatus::SUCCESS)
        {
            std::cout << "Public Connection has connected, now authenticating" << std::endl;
            auth_kit.unauthed_sockets.emplace_back(std::make_unique<PlatformAnalyser>(std::move(auth_kit.public_connector))); //add to the list of connected sockets ready to complete authentication

            if (init_kit.is_leader)
                auth_kit.unauthed_sockets.back()->send_data(create_message(MESSAGE_TYPE::AUTH_PLS));

            std::this_thread::sleep_for(100ms);
            return true;
        }
        else if (status == ConnectionStatus::FAILED)
        {
            std::cout << "Public Connection Failed, Retrying connection..." << std::endl;
            auth_kit.public_connector = std::make_unique<ReusableConnector>(auth_kit.old_privatename, auth_kit.peer_public.ip_address, auth_kit.peer_public.port, init_kit.protocol);
        }
    }
}

/// Server giving us a peer to connect to
/// Attempt to connect to peer by connecting to it and listening for a connection
/// The connect socket must have same local address binding as the socket that connected to the server
/// And we must disconnect the connection to the server
EXECUTION_STATUS hole_punch(client_init_kit& init_kit, const char* data, int& auth_key_out, int i, MESSAGE_LENGTH_T data_len) {    
    try
    {        
        std::cout << "Attempting to Hole Punch" << std::endl;
        client_auth_kit auth_kit{init_kit, data, i, data_len};
        auto start_time = std::chrono::system_clock::now();
        auto current_time = start_time;
        bool connection_made = false;

        do
        {
            if(connection_made == false)
                connection_made = check_for_auth_connection(init_kit, auth_kit);

            else
            {
                auto auth_status = respond_to_auth(init_kit, auth_kit);
                
                if (auth_status == EXECUTION_STATUS::CONNECTED)
                    return auth_status;
            }            
            std::this_thread::sleep_for(100ms);
        } 
        
        while (current_time - start_time < 15s);

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
    auto& connection_socket = kit.get_server_socket();

    while (kit.status == EXECUTION_STATUS::CONTINUE) //listen at the start of protocol
    {        
        auto now = std::chrono::system_clock::now();

        if (now - kit.last_send > 3s)
        {
            connection_socket->send_data(create_message(MESSAGE_TYPE::READY_FOR_P2P));
            kit.last_send = now;
        }
        if (connection_socket->has_message())
        {
            auto message = connection_socket->receive_message();
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
            if (connection_socket->has_message())
            {
                auto message = connection_socket->receive_message();
                kit.status = process_peer_data(message, connection_socket, kit.auth_key);
            }

            {
                if (take_message_lock.try_lock())
                {
                    if (!message_queue.messages.empty())
                    {
                        std::string input_message = message_queue.messages.front();
                        message_queue.messages.pop();
                        connection_socket->send_data(create_message(MESSAGE_TYPE::MSG, input_message));
                    }
                    take_message_lock.unlock();
                }
            }
            std::this_thread::sleep_for(100ms);
            
        } while (kit.status == EXECUTION_STATUS::CONTINUE);

        std::cout << "finished sending to peer" << std::endl;
    }
}
