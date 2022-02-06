#pragma once

#include "message.h"
#include "protocol.h"
#include "ptop_socket.h"

#include <string>
#include <vector>
#include <memory>
#include <fstream>

/// Messages:
/// MESSAGE_TYPE::PEER_FILE:
/// Contains the FileHeader
/// 
/// MESSAGE_TYPE::STREAM_CHUNK:
/// Contains a StreamChunk
/// 
/// MESSAGE_TYPE::MISSING_CHUNK:
/// Contains an int describing which chunk is missing
/// 
/// MESSAGE_TYPE::PEER_FILE_END:
/// Contains nothing, sent once a file has been fully sent

// Number of bytes stored in a StreamChunk's data vector
const int CHUNK_SIZE = 1000;

uint32_t crc_data(const std::vector<char>& data);

struct FileHeader {
    std::string filename;
    std::string extension;
    int num_chunks;
    int file_id;
};

struct StreamChunk {
    int file_id;
    int chunk_id;
    uint64_t chunk_crc;
    int data_length;
    std::vector<char> data;
};

class FileSender {
    friend class FileTransfer;
    public:
        StreamChunk IterateNextChunk();
        StreamChunk GetTargetChunk(int index);

        StreamChunk onMissingChunk(const Message& mess);

    private:
        FileSender(const FileHeader& header, PtopSocket& socket) : _header(header), _file(header.filename + "." + header.extension, std::ios::binary) { beginSending(socket); }
        FileHeader _header;
        std::ifstream _file;
        std::vector<StreamChunk> _chunks;

        int _next_chunk_send = 0;

        void beginSending(PtopSocket& socket);
        void processFileToChunks(std::ifstream& ifs, std::vector<StreamChunk>& chunks);
};

class FileReceiver {
    friend class FileTransfer;
    public:
        void onChunk(const Message& message);
        void onFileEnd(const Message& message);

    private:
        FileReceiver(const Message& message);

        void checksum();
        void order_chunk();

        std::vector<StreamChunk> _chunks;
};

class FileTransfer {
public:
    static std::unique_ptr<FileSender> BeginTransfer(const FileHeader& header, PtopSocket& socket);
    static std::unique_ptr<FileReceiver> BeginReception(const Message& message);
};

template<>
struct to_message<StreamChunk>
{
    Message operator()(const StreamChunk& val)
    {
        return create_message(MESSAGE_TYPE::STREAM_CHUNK, val.chunk_id, val.chunk_crc, val.data_length, val.data);
    }
};

template<>
struct to_message<FileHeader>
{
    Message operator()(const FileHeader& val)
    {
        return create_message(MESSAGE_TYPE::PEER_FILE, val.filename, val.extension, val.num_chunks);
    }
};

template<>
struct from_message<StreamChunk>
{
    StreamChunk operator()(const Message& mess)
    {
        int read_index = 0;
        StreamChunk chunk;
        chunk.chunk_id = mess.read_type<decltype(chunk.chunk_id)>(read_index);
        chunk.chunk_crc = mess.read_type<uint64_t>(read_index);
        chunk.data_length = mess.read_type<decltype(chunk.data_length)>(read_index);
        chunk.data = std::vector<char>(mess.Data.begin() + read_index, mess.Data.begin() + read_index + chunk.data_length);
        return chunk;
    }
};

template<>
struct from_message<FileHeader>
{
    FileHeader operator()(const Message& mess)
    {
        int read_index = 0;
        FileHeader header;
        header.extension = mess.read_type<std::string>(read_index);
        header.filename = mess.read_type<std::string>(read_index);
        header.num_chunks = mess.read_type<decltype(header.num_chunks)>(read_index);
        return header;
    }
};