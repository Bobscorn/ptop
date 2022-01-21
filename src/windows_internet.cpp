#include "windows_internet.h"
#include "message.h"
#include "error.h"

#include <iostream>

windows_internet::windows_internet(WORD versionRequested)
{
    int iResult = WSAStartup(versionRequested, &_data);
    
    if (iResult != 0) {
        auto error = "Winsock API initialization failed: " + std::to_string(iResult);        
        throw_new_exception(error, LINE_CONTEXT);
    }
    std::cout << "Winsock has been started" << std::endl;
}

windows_internet::~windows_internet()
{
    WSACleanup();
    std::cout << "Winsock has been cleaned" << std::endl;
}
