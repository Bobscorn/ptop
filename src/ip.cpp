#include "ip.h"

#ifdef WIN32
#include <windows.h>
#include <wininet.h>
#endif
#include <string>
#include <iostream>
#include <cstring>

using namespace std;

#ifdef WIN32
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
#endif

peer_data read_peer_data(char* data, int& index, int data_len)
{
    if (index + 1 >= data_len)
        throw runtime_error("Not enough data to read a string for peer_data");
    peer_data out_data;
    out_data.ip_address = std::string(data + index);
    index += out_data.ip_address.length() + 1;
    out_data.port = std::string(data + index);
    index += out_data.port.length() + 1;
    return out_data;
}

vector<char> peer_data::to_bytes()
{
    /*vector<char> bytes(sizeof(size_t) * 2 + ip_address.length() + port.length(), '0');
    size_t i = 0;
    size_t len = ip_address.length();
    memcpy(bytes.data() + i, &len, sizeof(size_t));
    i += sizeof(size_t);
    memcpy(bytes.data() + i, ip_address.data(), len);
    i += len;
    len = port.length();
    memcpy(bytes.data() + i, &len, sizeof(size_t));
    i += sizeof(size_t);
    memcpy(bytes.data() + i, port.data(), len);*/
    vector<char> bytes(ip_address.length() + port.length() + 2);
    memcpy(bytes.data(), ip_address.data(), ip_address.length() + 1);
    memcpy(bytes.data() + ip_address.length() + 1, port.data(), port.length() + 1);
    return bytes;
}
