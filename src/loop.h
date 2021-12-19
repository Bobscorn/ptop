#pragma once

#include <exception>
#include <stdexcept>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <thread>

enum class EXECUTION_STATUS
{
    CONTINUE = 0,
    CONNECTED,
    COMPLETE,
    FAILED,
};

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>> // Only allow Plain-old-data to use this method
T read_data(const char* data, int& index, size_t data_len)
{
    int size = sizeof(T);
    if (index + size > data_len)
        throw std::runtime_error("Not enough data to read");

    T* ptr = (T*)&(data[index]);
    index += size;
    return *ptr;
}

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>> 
bool try_read_data(const char* data, int& index, size_t data_len, T& val)
{
    int size = sizeof(T);
    if (index + size > data_len)
        return false;

    T* ptr = (T*)&(data[index]);
    index += size;
    val = *ptr;
    return true;
}

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>> //only compile if T is plain old data type
std::vector<T> read_data(const char* data, int& index, size_t data_len, int num_items)
{
    int size = sizeof(T);
    if (index + size * num_items > data_len)
        throw std::runtime_error("Not enough data to read");

    T* ptr = (T*)data[index];
    return std::vector<T>(ptr, ptr + num_items);
}

template<class size_T = int>
std::string read_string(const char* data, int& index, size_t data_len)
{
    int size = sizeof(size_T);
    if (index + size > data_len)
        throw std::runtime_error("Not enough data to read string length");

    size_T len = read_data<size_T>(data, index, data_len);
    if (index + len * sizeof(char) > data_len)
        throw std::runtime_error("Not enough data to read string characters");

    index += len;
    return std::string(data + index - len, data + index);
}

struct thread_queue
{
    thread_queue() : messages(), queue_mutex() {}
    thread_queue(const thread_queue& other) = delete; // Removes the default copy constructor

    std::queue<std::string> messages;
    std::shared_mutex queue_mutex;
};