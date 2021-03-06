#include "ip.h"

#if defined(WIN32) | defined(_WIN64)
#include <windows.h>
#include <wininet.h>
#endif

#include <string>
#include <iostream>
#include <cstring>

#if defined(WIN32) | defined(_WIN64)
std::string get_external_ip() {

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

    return std::string(buffer, read);
}
#endif

readable_ip_info read_peer_data(const char* data, int& index, size_t data_len)
{
    if ((size_t)index + 1 >= data_len)
        throw std::runtime_error("Not enough data to read a string for readable_ip_info");
    readable_ip_info out_data;
    out_data.ip_address = std::string(data + index);
    index += (int)out_data.ip_address.length() + 1;
    out_data.port = std::string(data + index);
    index += (int)out_data.port.length() + 1;
    return out_data;
}

std::vector<char> readable_ip_info::to_bytes() const
{
    std::vector<char> bytes(ip_address.length() + port.length() + 2);
    memcpy(bytes.data(), ip_address.data(), ip_address.length() + 1);
    memcpy(bytes.data() + ip_address.length() + 1, port.data(), port.length() + 1);
    return bytes;
}
