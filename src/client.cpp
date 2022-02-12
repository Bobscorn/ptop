#include "client.h"
#include "loop.h"
#include "message.h"
#include "ptop_socket.h"
#include "protocol.h"
#include "platform.h"
#include "ip.h"
#include "error.h"
#include "commands.h"

#include <iostream>

using namespace std::chrono;

client_init_kit::client_init_kit(std::string server_address_pair, ::Protocol chosen_protocol) : protocol(chosen_protocol) {
    _server_socket = std::make_unique<PlatformAnalyser>(server_address_pair, ServerListenPort, protocol, "Server-Conn");
    // Indicate to server we're ready for p2p
    server_last_send = std::chrono::system_clock::now();
    _server_socket->send_data(create_message(MESSAGE_TYPE::MY_DATA, _server_socket->get_myname_readable().to_bytes()));
    _server_socket->send_data(create_message(MESSAGE_TYPE::READY_FOR_P2P));
    //int value types will update themselves
    protocol = chosen_protocol;
}

std::unique_ptr<IDataSocketWrapper>& client_init_kit::get_server_socket() {
    return _server_socket;
}

void client_init_kit::set_server_socket(std::unique_ptr<IDataSocketWrapper>&& input) {
    _server_socket = std::move(input);

    if(input == nullptr)
        std::cout << "client_init_kit: connection socket set to nullptr mmk?" << std::endl;
}

client_peer_kit::client_peer_kit() {
        
}

void client_peer_kit::set_peer_data(client_init_kit& init_kit, const char* data, int next_data_index, MESSAGE_LENGTH_T data_len) {
    public_info = read_peer_data(data, next_data_index, data_len);
    private_info = read_peer_data(data, next_data_index, data_len);
    std::cout << "Target is: " << private_info.ip_address << ":" << private_info.port << "/" << public_info.ip_address << ":" << public_info.port << " priv/pub" << std::endl;

    old_privatename = init_kit.get_server_socket()->get_myname_raw();
    init_kit.set_server_socket(nullptr); //need to close the server socket HERE to maintain the same session in the peer sockets
    public_connector = std::make_unique<NonBlockingConnector>(old_privatename, public_info.ip_address, public_info.port, init_kit.protocol, "HolePunch-Public");
    private_connector = std::make_unique<NonBlockingConnector>(old_privatename, private_info.ip_address, private_info.port, init_kit.protocol, "HolePunch-Private");
        
    listen_sock = std::make_unique<NonBlockingListener>(old_privatename, init_kit.protocol, "HolePunch-Listen");
    listen_sock->listen();

    peer_connect_start_time = std::chrono::system_clock::now();
}

EXECUTION_STATUS connect_public(client_init_kit& init_kit, client_peer_kit& peer_kit) {
    auto status = peer_kit.public_connector->has_connected();
    if (status == ConnectionStatus::SUCCESS)
    {
        std::cout << "Public Connection has connected" << std::endl;
        peer_kit.peer_socket = std::make_unique<PlatformAnalyser>(std::move(peer_kit.public_connector));
        peer_kit.peer_socket->set_name("Public-Peer");
        
        return EXECUTION_STATUS::PEER_CONNECTED;
    }
    else if (status == ConnectionStatus::FAILED)
    {
        std::cout << "Public Connection Failed, Retrying connection..." << std::endl;
        peer_kit.public_connector = nullptr;
        peer_kit.public_connector = std::make_unique<NonBlockingConnector>(peer_kit.old_privatename, peer_kit.public_info.ip_address, peer_kit.public_info.port, init_kit.protocol, "HolePunch-Public");
    }
    return EXECUTION_STATUS::HOLE_PUNCH;
}

EXECUTION_STATUS connect_private(client_init_kit& init_kit, client_peer_kit& peer_kit) {
    auto status = peer_kit.private_connector->has_connected();
    if (status == ConnectionStatus::SUCCESS)
    {
        std::cout << "Private Connection has connected" << std::endl;
        peer_kit.peer_socket = std::make_unique<PlatformAnalyser>(std::move(peer_kit.private_connector));
        peer_kit.peer_socket->set_name("Private-Peer");

        return EXECUTION_STATUS::PEER_CONNECTED;
    }
    else if (status == ConnectionStatus::FAILED)
    {
        std::cout << "Private Connection attempt failed, retrying..." << std::endl;
        peer_kit.private_connector = nullptr;
        peer_kit.private_connector = std::make_unique<NonBlockingConnector>(peer_kit.old_privatename, peer_kit.private_info.ip_address, peer_kit.private_info.port, init_kit.protocol, "HolePunch-Private");
    }
    return EXECUTION_STATUS::HOLE_PUNCH;
}

EXECUTION_STATUS connect_listener(client_peer_kit& peer_kit) {
    if (peer_kit.listen_sock->has_connection())
    {
        std::cout << "Successfully accepted peer connection" << std::endl;
        peer_kit.peer_socket = peer_kit.listen_sock->accept_connection();

        return EXECUTION_STATUS::PEER_CONNECTED;
    }
    return EXECUTION_STATUS::HOLE_PUNCH;
}

EXECUTION_STATUS connect_peer(client_init_kit& init_kit, client_peer_kit& peer_kit) {
    if(peer_kit.peer_socket)
        return EXECUTION_STATUS::PEER_CONNECTED;

    auto status = connect_listener(peer_kit);
    
    if(status != EXECUTION_STATUS::PEER_CONNECTED)
        status = connect_public(init_kit, peer_kit);

    if(status != EXECUTION_STATUS::PEER_CONNECTED)
        status = connect_private(init_kit, peer_kit);

    return status;
}

EXECUTION_STATUS hole_punch(client_init_kit& init_kit, client_peer_kit& peer_kit) {    
    try
    {    
        EXECUTION_STATUS status = EXECUTION_STATUS::HOLE_PUNCH;

        if(init_kit.status != EXECUTION_STATUS::PEER_CONNECTED)
            status = connect_peer(init_kit, peer_kit);

        auto current_time = std::chrono::system_clock::now();

        if(current_time - peer_kit.peer_connect_start_time > 15s) {
            std::cerr << "Time out trying to hole punch reached" << std::endl;
            return EXECUTION_STATUS::FAILED;
        }
        
        return status;
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

EXECUTION_STATUS process_server_data(client_init_kit& init_kit, client_peer_kit& peer_kit, const Message& message)
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

        int message_data_index = 0;

        auto msg_type = message.Type;
        switch (msg_type)
        {
        case MESSAGE_TYPE::CONNECT_TO_PEER:
        {
            if (init_kit.do_delay)
            {
                std::cout << "Delaying hole punching by 5s..." << std::endl;
                std::this_thread::sleep_for(5s);
            }
            peer_kit.set_peer_data(init_kit, data, message_data_index, data_len);
            return EXECUTION_STATUS::HOLE_PUNCH;
        }

        case MESSAGE_TYPE::NONE:
        default:
            std::cout << __func__ << "(" << __LINE__ << "): Ignoring Message with Type: " << mt_to_string(msg_type) << std::endl;
            return EXECUTION_STATUS::RENDEZVOUS;
        }
    }
    catch (const std::exception& e)
    {
        throw_with_context(e, LINE_CONTEXT);
    }
}

EXECUTION_STATUS process_peer_data(const Message& mess, const std::unique_ptr<IDataSocketWrapper>& peer, client_peer_kit& peer_kit)
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
        case MESSAGE_TYPE::PEER_MSG:
        {
            std::string msg = read_string(data, i, data_len);
            std::cout << "Message received from peer: " << msg << std::endl;
            return EXECUTION_STATUS::PEER_CONNECTED;
        }
        case MESSAGE_TYPE::PEER_FILE:
        {
            if (peer_kit.file_receiver)
                std::cerr << "Already receiving a file from the peer!" << std::endl;

            else {
                std::cout << "Receiving new file from peer" << std::endl;
                peer_kit.file_receiver = FileTransfer::BeginReception(mess);
                peer->send_data(create_message(MESSAGE_TYPE::STREAM_ACKNOWLEDGED));
            }            
            return EXECUTION_STATUS::PEER_CONNECTED;
        }
        
        case MESSAGE_TYPE::STREAM_ACKNOWLEDGED:
        {
            peer_kit.file_sender->sendFile(peer_kit.peer_socket);
            return EXECUTION_STATUS::PEER_CONNECTED;
        }
        
        case MESSAGE_TYPE::STREAM_CHUNK:
        {
            if (!peer_kit.file_receiver)
            {
                std::cerr << "Receiving the chunk of a file we don't have the header for!" << std::endl;
            }

            else
                peer_kit.file_receiver->onChunk(mess, peer_kit.peer_socket);
     
            return EXECUTION_STATUS::PEER_CONNECTED;
        }

        case MESSAGE_TYPE::PEER_FILE_END:
        {
            if (!peer_kit.file_receiver)
            {
                std::cerr << "Receiving file end when we don't have a file header!" << std::endl;
                return EXECUTION_STATUS::PEER_CONNECTED;
            }

            peer_kit.file_receiver->onFileEnd(mess);
            peer_kit.file_receiver = nullptr;

            return EXECUTION_STATUS::PEER_CONNECTED;
        }

        case MESSAGE_TYPE::CHUNK_ERROR:
        {
            if (!peer_kit.file_sender)
            {
                std::cerr << "Our peer is reporting a missing chunk when we're not actively sending a file!" << std::endl;
                return EXECUTION_STATUS::PEER_CONNECTED;
            }

            peer_kit.file_sender->onChunkError(mess, peer_kit.peer_socket);

            return EXECUTION_STATUS::PEER_CONNECTED;
        }
        
        case MESSAGE_TYPE::NONE:
        default:
            std::cout << __func__ << "(" << __LINE__ << "): Ignoring Message with Type: " << mt_to_string(msg_type) << std::endl;
            return EXECUTION_STATUS::PEER_CONNECTED;
    }
    return EXECUTION_STATUS::PEER_CONNECTED;
}

void get_user_input(thread_queue& msg_queue)
{
    std::string input;
    do
    {
        std::getline(std::cin, input); //waits until cin input
        {
            std::unique_lock<std::shared_mutex> lock(msg_queue.queue_mutex);
            msg_queue.messages.push(input);
        }

        std::this_thread::sleep_for(100ms);
    } while (true);
}

// Returns whether to quit or not
bool do_user_input(thread_queue& message_queue, std::unique_lock<std::shared_mutex>& take_message_lock, std::unique_ptr<IDataSocketWrapper>& peer_socket, client_init_kit& i_kit, client_peer_kit& peer_kit)
{
    if (take_message_lock.try_lock())
    {
        if (!message_queue.messages.empty())
        {
            std::string input_message = message_queue.messages.front();
            message_queue.messages.pop();
            take_message_lock.unlock();
            return Commands::get().commandSaidQuit(input_message, peer_socket, i_kit, peer_kit, take_message_lock);
        }
        take_message_lock.unlock();
    }
    return false;
}

void client_loop(std::string server_address_pair, Protocol input_protocol)
{
    std::cout << "Starting ptop!" << std::endl;
    std::cout << "Connecting to rendezvous server: " << server_address_pair << std::endl;
    client_init_kit init_kit{ server_address_pair, input_protocol };
    client_peer_kit peer_kit{};    
    auto& connection_socket = init_kit.get_server_socket();
    
    thread_queue message_queue{};

    std::thread input_thread = std::thread(get_user_input, std::ref(message_queue));
    input_thread.detach();
    std::unique_lock<std::shared_mutex> take_message_lock(message_queue.queue_mutex, std::defer_lock);
    
    init_kit.status = EXECUTION_STATUS::RENDEZVOUS;

    while (init_kit.status != EXECUTION_STATUS::COMPLETE && init_kit.status != EXECUTION_STATUS::FAILED) //listen at the start of protocol
    {
        switch (init_kit.status)
        {
            case EXECUTION_STATUS::RENDEZVOUS:
            {
                auto now = std::chrono::system_clock::now();

                if (now - init_kit.server_last_send > 3s)
                {
                    connection_socket->send_data(create_message(MESSAGE_TYPE::READY_FOR_P2P));
                    init_kit.server_last_send = now;
                }
                if (connection_socket->has_message())
                {
                    auto message = connection_socket->receive_message();
                    init_kit.status = process_server_data(init_kit, peer_kit, message);
                }
                break;
            }   

            case EXECUTION_STATUS::HOLE_PUNCH:
            {
                init_kit.status = hole_punch(init_kit, peer_kit);
                break;
            }
                
            case EXECUTION_STATUS::PEER_CONNECTED:
            {
                if (peer_kit.peer_socket->has_message())
                {
                    auto message = peer_kit.peer_socket->receive_message();
                    init_kit.status = process_peer_data(message, peer_kit.peer_socket, peer_kit);
                }
                break;
            }
        }
        
        if(peer_kit.file_receiver != nullptr) {
            if (do_user_input(message_queue, take_message_lock, peer_kit.peer_socket, init_kit, peer_kit))
                init_kit.status = EXECUTION_STATUS::COMPLETE;
        }        

        else {
            std::cout << "cannot enter commands while file transfer in progress." << std::endl;
        }
        std::this_thread::sleep_for(100ms);
    }
}
