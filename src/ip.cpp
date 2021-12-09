#include "ip.h"

#include <windows.h>
#include <wininet.h>
#include <string>
#include <iostream>

string get_external_ip() {

    HINTERNET net = InternetOpen("IP retriever",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0);

    HINTERNET conn = InternetOpenUrl(net,
        "http://myexternalip.com/raw",
        NULL,
        0,
        INTERNET_FLAG_RELOAD,
        0);

    char buffer[4096];
    DWORD read;

    InternetReadFile(conn, buffer, sizeof(buffer) / sizeof(buffer[0]), &read);
    InternetCloseHandle(net);

    return string(buffer, read);
}