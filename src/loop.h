#pragma once

#include <exception>
#include <stdexcept>

using namespace std;

enum class EXECUTION_STATUS
{
    CONTINUE = 0,
    CONNECTED,
    COMPLETE,
    FAILED,
};

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
T read_data(char* data, int& index, int data_len)
{
    int size = sizeof(T);
    if (index + size >= data_len)
        throw runtime_error("Not enough data to read");

    T* ptr = (T*)&data[index];
    index += size;
    return *ptr;
}

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
std::vector<T> read_data(char* data, int& index, int data_len, int num_items)
{
    int size = sizeof(T);
    if (index + size * num_items >= data_len)
        throw runtime_error("Not enough data to read");

    T* ptr = (T*)data[index];
    return std::vector<T>(ptr, ptr + num_items);
}

template<class size_T = int>
std::string read_string(char* data, int& index, int data_len)
{
    int size = sizeof(size_T);
    if (index + size >= data_len)
        throw runtime_error("Not enough data to read string length");

    size_T len = read_data<size_T>(data, index, data_len);
    if (index + len * sizeof(char) > data_len)
        throw runtime_error("Not enough data to read string characters");

    index += len;
    return std::string(data + index - len, data + index);
}