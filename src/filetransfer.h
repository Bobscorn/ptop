#pragma once

#include "message.h"
#include "protocol.h"
#include "interfaces.h"
#include "time.h"
#include "negotiation.h"

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <chrono>

/// Messages:
/// MESSAGE_TYPE::PEER_FILE:
/// Contains the FileHeader
/// 
/// MESSAGE_TYPE::STREAM_CHUNK:
/// Contains a StreamChunk
/// 
/// MESSAGE_TYPE::CHUNK_ERROR:
/// Contains an int describing which chunk is missing
/// 
/// MESSAGE_TYPE::PEER_FILE_END:
/// Contains nothing, sent once a file has been fully sent

// Number of bytes stored in a StreamChunk's data vector
// Must be able to fit into a single packet, so at most 64 kilobytes, but to account for the header we subtract 256 bytes
// Even more reliable would be to ensure a chunk is under the MTU (Maximum Transmission Unit), of which the minimum is 576 bytes (https://en.wikipedia.org/wiki/Maximum_transmission_unit)
//constexpr int CHUNK_SIZE = 576 - 80;
constexpr int CHUNK_SIZE = 4096;

using namespace std::chrono;

struct FileHeader {
    std::string filename;
    std::string extension;
    int num_chunks;
    int file_id = 0;
};

struct FileProgress
{
    std::string filename;
    int received_chunks;
    int sent_chunks;
    int acknowledged_chunks;
    int total_chunks;
};

constexpr int StreamChunk_OVERHEAD = sizeof(int32_t) * 3;
struct StreamChunk {
    int32_t file_id;
    int32_t chunk_id;
    int32_t data_length;
    std::vector<char> data;

    bool operator==(const StreamChunk& other) const;
    inline bool operator!=(const StreamChunk& other) const { return !(this->operator==(other)); }

    static const StreamChunk empty;
};

enum class StreamChunkAcknowledge
{
    NONE = 0,
    SENT,
    ACKNOWLEDGED,
};

struct StreamChunkState
{
    StreamChunk chunk;
    s_time last_send_time;
    StreamChunkAcknowledge acknowledge_state;
    int times_sent = 0;

    inline bool is_empty() const { return chunk == StreamChunk::empty; }
    static const StreamChunkState empty;
};

class FileSender {
    friend class FileTransfer;
    public:
        inline void startSending() { _last_activity = time_now(); _received_initial_ack = true; }

        void sendFile(std::unique_ptr<IDataSocketWrapper>& socket);
        StreamChunkState GetTargetChunk(int index);

        void onChunkError(const Message& mess, std::unique_ptr<IDataSocketWrapper>& socket);
        bool onChunkAck(const Message& mess); // Returns whether to destroy this file sender

        bool hasExpired() const;

        int numChunksSent() const;
        int numChunksAcked() const;
        int numFileChunks() const;

        FileProgress getProgress() const;
        std::string getProgressString() const;

        static const s_duration ResendChunkInterval;
        static const s_duration MaxIdleWaitTime;

    private:
        Negotiator _negotiator;

        typedef std::vector<StreamChunkState>::iterator chunk_iter;

        FileSender(std::ifstream file, const FileHeader& header, std::unique_ptr<IDataSocketWrapper>& socket);     

        void processFileToChunks(std::ifstream& ifs, std::vector<StreamChunkState>& chunks);
        chunk_iter IterateNextChunk();

        void sendChunk(StreamChunkState& chunk, std::unique_ptr<IDataSocketWrapper>& socket);

        void update_progress_print();

        FileHeader _header;
        std::vector<StreamChunkState> _chunks;
        s_time _last_send;
        s_time _last_activity;

        int _next_chunk_send = 0;
        int _last_chunk_scan = 0;
        int _num_acked_chunks = 0;

        bool _received_initial_ack = false;
};

class FileReceiver {
    friend class FileTransfer;
    public:
        // Returns whether this file reception has succeeded
        bool onChunk(const Message& message, std::unique_ptr<IDataSocketWrapper>& socket);
        void write_to_file();        
        std::chrono::system_clock::time_point get_deadman() { return _deadmanswitch; };

        int numReceived() const;
        int numFileChunks() const;

        FileProgress getProgress() const;
        std::string getProgressString() const;

    private:
        FileReceiver(const Message& message);

        inline void relieve_deadman() { _deadmanswitch = std::chrono::system_clock::now(); };

        FileHeader _header;
        std::vector<StreamChunk> _chunks;            
        std::chrono::system_clock::time_point _deadmanswitch;
        int _num_good_chunks = 0;
};

class FileTransfer {
public:
    static std::unique_ptr<FileSender> BeginTransfer(const FileHeader& header, std::unique_ptr<IDataSocketWrapper>& socket);
    static std::unique_ptr<FileReceiver> BeginReception(const Message& message);
    static bool timeout_expired(std::chrono::system_clock::time_point deadmanswitch);

    static const std::chrono::seconds MaximumIdleWaitTime;
};

template<>
struct to_message<StreamChunk>
{
    Message operator()(const StreamChunk& val)
    {
        return create_message(MESSAGE_TYPE::STREAM_CHUNK, val.file_id, val.chunk_id, val.data_length, val.data);
        // std::vector<char> data{};
        // copy_to_message_struct::copy_to_message(data, val.chunk_id, val.data_length, val.data);
        // return create_streammessage(MESSAGE_TYPE::STREAM_CHUNK, data);
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
        chunk.file_id = mess.read_type<decltype(chunk.file_id)>(read_index);
        chunk.chunk_id = mess.read_type<decltype(chunk.chunk_id)>(read_index);
        chunk.data_length = mess.read_type<decltype(chunk.data_length)>(read_index);
        chunk.data = std::vector<char>(mess.Data.begin() + read_index, mess.Data.begin() + read_index + chunk.data_length);
        read_index += chunk.data_length;
        return chunk;
    }
};

template<>
struct from_message_with_crc<StreamChunk>
{
    StreamChunk operator()(const Message& mess, uint32_t& crc)
    {
        int read_index = 0;
        StreamChunk chunk;
        chunk.chunk_id = mess.read_type<decltype(chunk.chunk_id)>(read_index);
        chunk.data_length = mess.read_type<decltype(chunk.data_length)>(read_index);
        chunk.data = std::vector<char>(mess.Data.begin() + read_index, mess.Data.begin() + read_index + chunk.data_length);
        read_index += chunk.data_length;
        crc = mess.read_type<uint32_t>(read_index);
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
        header.filename = mess.read_type<std::string>(read_index);
        header.extension = mess.read_type<std::string>(read_index);
        header.num_chunks = mess.read_type<decltype(header.num_chunks)>(read_index);
        return header;
    }
};