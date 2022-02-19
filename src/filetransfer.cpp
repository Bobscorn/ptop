#include "filetransfer.h"
#include "interfaces.h"
#include "time.h"

#include <cstdint>
#include <array>
#include <limits>
#include <thread>
#include <iostream>
#include <chrono>

const StreamChunk StreamChunk::empty = StreamChunk{ -1, -1, -1, std::vector<char>() };

bool StreamChunk::operator==(const StreamChunk& other) const
{
	return file_id == other.file_id
		&& chunk_id == other.chunk_id
		&& data_length == other.data_length
		&& data == other.data;
}

FileSender::FileSender(std::ifstream file, const FileHeader& header, std::unique_ptr<IDataSocketWrapper>& socket) : _header(header) {
	processFileToChunks(file, _chunks);
	_header.num_chunks = _chunks.size();
	auto mess = to_message<FileHeader>()(_header);
	socket->send_data(mess);
}

void FileSender::sendFile(std::unique_ptr<IDataSocketWrapper>& socket) {
	std::cout << "Sending " << _chunks.size() << " chunks to peer" << std::endl;
	bool sending = true;

	while(sending) {
		const auto& chunk = IterateNextChunk();
		
		if(chunk == StreamChunk::empty) {
			sending = false;
			break;
		}
		
		socket->send_message(chunk);
	}
	
	socket->send_data(create_message(MESSAGE_TYPE::PEER_FILE_END));
}

const StreamChunk& FileSender::IterateNextChunk()
{	
	if (_next_chunk_send >= _chunks.size())	
		return StreamChunk::empty;

	auto index = _next_chunk_send++;
	return _chunks[index];
}

StreamChunk FileSender::GetTargetChunk(int index)
{
	if (index < 0 || index >= _chunks.size())
		return StreamChunk::empty;
	return _chunks[index];
}

bool FileSender::onChunkError(const Message& mess, std::unique_ptr<IDataSocketWrapper>& socket)
{
	int read_index = 0;
	int missing_id = mess.read_type<int>(read_index);

	if (missing_id < 0 || missing_id >= _header.num_chunks)
	{
		std::cerr << "Received CHUNK_ERROR on chunk id: " << missing_id << std::endl;
	}

	if(FileTransfer::timeout_expired(_deadmanswitch)) {
		return true;
	}
	auto chunk = _chunks[missing_id];
	socket->send_message(chunk);
	relieve_deadman();
	return false;
}

void FileSender::processFileToChunks(std::ifstream& ifs, std::vector<StreamChunk>& chunks)
{
	std::streamsize last_read_count = 0;
#ifdef max
#define dumb_tmp max
#undef max
#endif
	constexpr auto max_size = std::numeric_limits<std::streamsize>::max();
#ifdef dumb_tmp
#define max dumb_tmp
#undef dumb_tmp
#endif
	int running_id = 0;
	while (last_read_count != max_size)
	{
		StreamChunk chunk;
		chunk.chunk_id = running_id++;
		chunk.data = std::vector<char>(CHUNK_SIZE, (char)0);
		ifs.read(chunk.data.data(), CHUNK_SIZE);

		last_read_count = ifs.gcount();
		if (last_read_count == max_size || last_read_count == 0)
			break;

		chunk.data_length = last_read_count;
		chunk.data.resize(last_read_count);

		chunks.push_back(chunk);
	}
}

FileReceiver::FileReceiver(const Message& message)
{
	from_message<FileHeader> from_msg;
	FileHeader header = from_msg(message);
	_header = header;

	std::cout << "Receiving file: '" << header.filename << "." << header.extension << "' with " << header.num_chunks << " chunks" << std::endl;
	int file_size = header.num_chunks * CHUNK_SIZE / KILOBYTE;
	std::cout << "file size: " << file_size << "KB" << std::endl;

	_chunks.resize(_header.num_chunks, StreamChunk::empty);
}

void FileReceiver::onChunk(const Message& message, std::unique_ptr<IDataSocketWrapper>& socket)
{
	// auto from_msg_wc = from_message_with_crc<StreamChunk>();
	// uint32_t incoming_crc;
	// auto chunk = from_msg_wc(message, incoming_crc);

	// uint32_t my_crc = 0;
	// {
	// 	auto crc_check_msg = to_message<StreamChunk>()(chunk);
	// 	my_crc = crc_data(crc_check_msg.Data);
	// }

	// if (my_crc != incoming_crc)
	// {
	// 	socket->send_message(create_message(MESSAGE_TYPE::CHUNK_ERROR, chunk.chunk_id));
	// 	return;
	// }
	relieve_deadman();

	auto chunk = from_message<StreamChunk>()(message);
	std::cout << "received chunk, chunk id: " << chunk.chunk_id << std::endl;
	
	auto index = chunk.chunk_id;
	if (index < 0 || index >= _chunks.size())
		return;

	_chunks[index] = chunk;
}

void FileReceiver::onFileEnd(const Message& message)
{
	std::cout << "Received File End for '" << _header.filename << "." << _header.extension << "' " << std::endl;	
}

bool FileTransfer::timeout_expired(std::chrono::system_clock::time_point deadmanswitch) // Returns whether we have written and should be destroyed
{
	auto new_now = std::chrono::system_clock::now();

	if (deadmanswitch.time_since_epoch().count() > 0 && new_now - deadmanswitch <= LAST_CHUNK_TIME)
	{
		return true;
	}
	std::cout << "ERROR: " << duration_to_str(LAST_CHUNK_TIME) << " since last chunk received." << std::endl;
	return false;
}

void FileReceiver::write_to_file() {
	bool file_good = true;
	for (int i = 0; i < _chunks.size() && file_good; ++i)
	{
		const auto& chunk = _chunks[i];

		if (chunk == StreamChunk::empty)
			file_good = false;
	}

	if (file_good)
		std::cout << "Fully received the file" << std::endl;
	else
		std::cout << "One or more chunks were corrupted or weren't received" << std::endl;

	if (file_good)
	{
		// Write the chunks to a file
		std::ofstream file_write(_header.filename + "." + _header.extension, std::ios::binary);
		for (int i = 0; i < _chunks.size() && file_write.good(); ++i)
		{
			const auto& c = _chunks[i];
			file_write.write(c.data.data(), c.data_length);
		}
		if (file_write.fail())
			std::cout << "Failed to write to disk" << std::endl;
		else
			std::cout << "Successfully wrote file to disk" << std::endl;
	}
}

std::unique_ptr<FileSender> FileTransfer::BeginTransfer(const FileHeader& header, std::unique_ptr<IDataSocketWrapper>& socket)
{
	std::ifstream file{ header.filename + "." + header.extension, std::ios::binary };

	if(!file.good()) {
		std::cout << "ERROR: file not found." << std::endl;
		return nullptr;
	}
	return std::unique_ptr<FileSender>(new FileSender(std::move(file), header, socket));
}

std::unique_ptr<FileReceiver> FileTransfer::BeginReception(const Message& message)
{
	return std::unique_ptr<FileReceiver>(new FileReceiver(message));
}
