#include "commands.h"

#include "interfaces.h"
#include "client.h"
#include "filetransfer.h"

#include <string.h>

Commands Commands::_singleton = Commands();

bool Commands::commandSaidQuit(
    std::string input_message, 
    std::unique_ptr<IDataSocketWrapper>& peer_socket, 
    client_init_kit& i_kit,
    client_peer_kit& p_kit,
    std::unique_lock<std::shared_mutex>& take_message_lock) {

    auto msg_found = input_message.find(MESSAGE);
    auto file_found = input_message.find(FILE);
    auto delay_found = input_message.find(DELAY);
    auto debug_found = input_message.find(DEBUG);
    auto help_found = input_message.find(HELP);
    auto quit_found = input_message.find(QUIT);

    if(msg_found != std::string::npos) {
        auto text = input_message.substr(msg_found + strlen(MESSAGE));
        return handleMessage(text, peer_socket, i_kit);
    }

    else if(file_found != std::string::npos) {
        auto text = input_message.substr(file_found + strlen(FILE));
        return handleFiles(text, p_kit);
    }

    else if(delay_found != std::string::npos) {
        return handleDelay(i_kit);
    }

    else if (debug_found != std::string::npos) {
        return handleDebug(i_kit, p_kit);
    }

    else if(help_found != std::string::npos) {
        return handleHelp();
    }

    else if(quit_found != std::string::npos) {
        return handleQuit(take_message_lock);
    }

    else {
        std::cout << "Unknown command: " << input_message << std::endl;
        std::cout << "Type 'help' to see available commands" << std::endl;
        return false;
    }    
}

bool Commands::handleMessage(std::string input_message, std::unique_ptr<IDataSocketWrapper>& peer_socket, client_init_kit& i_kit) {
    if (peer_socket)
    {
        std::cout << "Sending string of: " << input_message << std::endl;
        peer_socket->send_data(create_message(MESSAGE_TYPE::PEER_MSG, input_message));
    }
    else
        std::cout << "Can not send to peer, we have no peer connection" << std::endl;

    return false;
}

bool Commands::handleFiles(std::string input_message, client_peer_kit& peer_kit) {
    std::cout << "Starting file transfer" << std::endl;

    if (peer_kit.file_sender)
    {
        std::cout << "Existing file transfer exists!" << std::endl;
        return false;
    }

    FileHeader header;

    size_t last_dot = input_message.find_last_of(".");
    if (last_dot == std::string::npos)
    {
        header.filename = input_message;
        header.extension = "";
    }
    else
    {
        auto filename = input_message.substr(0, last_dot);
        auto extension = input_message.substr(last_dot + 1);
        header.filename = filename;
        header.extension = extension;
    }

    peer_kit.file_sender = FileTransfer::BeginTransfer(header, peer_kit.peer_socket);
    
    std::cout << "Sending file with name: '" << header.filename << "' and extension '" << header.extension << "' (" << header.filename << "." << header.extension << ")" << std::endl;

    return false;
}

bool Commands::handleDelay(client_init_kit& i_kit) {
    if (i_kit.status == EXECUTION_STATUS::RENDEZVOUS)
    {
        std::cout << "Delaying this peer's hole punch" << std::endl;
        i_kit.do_delay = true;
    }
    else
    {
        std::cout << "Too late in execution to delay hole punching" << std::endl;
    }
    return false;
}

bool Commands::handleDebug(client_init_kit& i_kit, client_peer_kit& peer_kit) {
    std::cout << "Protocol: " << (i_kit.protocol.is_tcp() ? "TCP" : (i_kit.protocol.is_udp() ? "UDP" : "Unknown...")) << std::endl;
    std::cout << "Current State: ";
    switch (i_kit.status)
    {
        case EXECUTION_STATUS::RENDEZVOUS:
        {
            std::cout << "Rendezvousing with server" << std::endl;
            auto& server_conn = i_kit.get_server_socket();
            if (!server_conn)
                std::cout << "Connection to server appears to be null" << std::endl;
            else
            {
                std::cout << "Connected to server at: " << server_conn->get_identifier_str() << std::endl;
            }
        }
            break;
        case EXECUTION_STATUS::HOLE_PUNCH:
            std::cout << "Hole punching to peer" << std::endl;
            if (!peer_kit.public_connector)
                std::cout << "Public connector is null" << std::endl;
            else
                std::cout << "Public connector: " << peer_kit.public_connector->get_identifier_str() << std::endl;
            if (!peer_kit.private_connector)
                std::cout << "Private connector is null" << std::endl;
            else
                std::cout << "Private connector: " << peer_kit.private_connector->get_identifier_str() << std::endl;
            if (!peer_kit.listen_sock)
                std::cout << "Listen socket is null" << std::endl;
            else
                std::cout << "Listen socket: " << peer_kit.listen_sock->get_identifier_str() << std::endl;

            break;
        case EXECUTION_STATUS::PEER_CONNECTED:
            std::cout << "Connected to peer" << std::endl;
            if (!peer_kit.peer_socket)
                std::cout << "Peer socket is null (a bug)" << std::endl;
            else
                std::cout << "Peer socket is: " << peer_kit.peer_socket->get_identifier_str() << std::endl;
            break;
        
        default:
            std::cout << es_to_string(i_kit.status) << " Client should not be in this state, potentially a bug" << std::endl;
            break;
    };
    return false;
}

void print_help()
{
    auto space = "\t";
    std::cout << "PTOP Peer v2 is running" << std::endl;
    std::cout << "Runtime commands:" << std::endl;
    std::cout << space << "file: [filename]" << std::endl;
    std::cout << space << space << "sends a file to your peer (not currently implemented)" << std::endl;
    std::cout << std::endl;
    std::cout << space << "msg: [text]" << std::endl;
    std::cout << space << space << "sends plain text message of [text] (without braces) to your peer" << std::endl;
    std::cout << space << space << "example: \"msg: banana\" will send 'banana' to your peer" << std::endl;
    std::cout << std::endl;
    std::cout << space << "delay" << std::endl;
    std::cout << space << space << "delays this peer's hole punch call by a set amount (changes and cbf updating this every time)" << std::endl;
    std::cout << space << space << "this must be called before this peer tries to hole punch" << std::endl;
    std::cout << std::endl;
    std::cout << space << "quit" << std::endl;
    std::cout << space << space << "closes the program" << std::endl;
    std::cout << std::endl;
    std::cout << space << "debug" << std::endl;
    std::cout << space << space << "outputs current status and relevant information" << std::endl;
}


bool Commands::handleHelp() {
    print_help();
    return false;
}

bool Commands::handleQuit(std::unique_lock<std::shared_mutex>& take_message_lock) {
    std::cout << "Quitting..." << std::endl;
    take_message_lock.unlock();
    return true;
}
