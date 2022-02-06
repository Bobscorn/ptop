#pragma once

#include "message.h"
#include "protocol.h"
#include "ptop_socket.h"

#include <string>
#include <vector>

const int CHUNK_SIZE = 1000;

class FileTransfer {
    public:
        static FileSender BeginTransfer(FileHeader header, Protocol protocol, PtopSocket socket);
        static FileReceiver BeginReception(Message message, Protocol protocol, PtopSocket socket);
};

class FileSender {
    friend class FileTransfer;
    public:
        StreamChunk IterateNextChunk();

    private:
        FileSender(FileHeader header, Protocol protocol, PtopSocket socket) : _header(header), _protocol(protocol), _socket(socket) {}
        FileHeader _header;
        Protocol _protocol;
        PtopSocket _socket;

};

class FileReceiver {
    public:
        FileReceiver();
        void onChunk(Message message, StreamChunk chunk);

    private:
        void checksum();
        void order_chunk();
};

struct FileHeader {
    std::string filename;
    std::string extension;
    int num_chunks;
};

struct StreamChunk {
    int chunk_id;
    std::string chunk_hash;
    std::vector<char> data;
    int data_length;
};
