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

peer_data read_peer_data(char* data, int& index, int data_len)
{
    if (index + 1 >= data_len)
        throw exception("Not enough data to read a string for peer_data");
    peer_data out_data;
    out_data.ip_address = std::string(data + index);
    index += out_data.ip_address.length() + 1;
    out_data.port = std::string(data + index);
    index += out_data.port.length() + 1;
    return out_data;
}
