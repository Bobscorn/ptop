#pragma once

#include "loop.h"
#include "client.h"

class Commands {
    public:
    static inline Commands& get() { return _singleton; };
    bool commandSaidQuit(
        std::string input_message, 
        std::unique_ptr<IDataSocketWrapper>& peer_socket, 
        client_init_kit& i_kit,
        client_peer_kit& p_kit,
        std::unique_lock<std::shared_mutex>& take_message_lock);
    
    private:
    const char* MESSAGE = "msg:";
    const char* FILE = "file:";
    const char* DELAY = "delay:";
    const char* DEBUG = "debug:";
    const char* HELP = "help:";
    const char* QUIT = "quit:";

    inline Commands() {};
    static Commands _singleton;
    bool handleMessage(std::string input_message, std::unique_ptr<IDataSocketWrapper>& peer_socket, client_init_kit& i_kit);
    bool handleFiles(std::string input_message, client_peer_kit& peer_kit);
    bool handleDelay(client_init_kit& i_kit);
    bool handleDebug(client_init_kit& i_kit, client_peer_kit& peer_kit);
    bool handleHelp();
    bool handleQuit(std::unique_lock<std::shared_mutex>& take_message_lock);
};
