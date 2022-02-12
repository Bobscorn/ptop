#include "filetransfer.h"
#include "interfaces.h"

#include <cstdint>
#include <array>
#include <limits>

const StreamChunk StreamChunk::empty = StreamChunk{ -1, -1, -1, std::vector<char>() };

bool StreamChunk::operator==(const StreamChunk& other) const
{
	return file_id == other.file_id
		&& chunk_id == other.chunk_id
		&& data_length == other.data_length
		&& data == other.data;
}

FileSender::FileSender(const FileHeader& header, std::unique_ptr<IDataSocketWrapper>& socket) : _header(header), _file(header.filename + "." + header.extension, std::ios::binary) {
	processFileToChunks(_file, _chunks);
	_header.num_chunks = _chunks.size();
	auto mess = to_message<FileHeader>()(_header);
	socket->send_data(mess);
}

void FileSender::sendFile(std::unique_ptr<IDataSocketWrapper>& socket) {
	bool sending = true;

	while(sending) {
		const auto& chunk = IterateNextChunk();
		
		if(chunk == StreamChunk::empty) {
			sending = false;
			return;
		}
		
		socket->send_message(chunk);
	}
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

void FileSender::onChunkError(const Message& mess, std::unique_ptr<IDataSocketWrapper>& socket)
{
	int read_index = 0;
	int missing_id = mess.read_type<int>(read_index);

	if (missing_id < 0 || missing_id >= _header.num_chunks)
	{
		std::cerr << "Received CHUNK_ERROR on chunk id: " << missing_id << std::endl;
	}	
	auto chunk = _chunks[missing_id];
	socket->send_message(chunk);
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
		if (last_read_count == max_size)
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

	auto chunk = from_message<StreamChunk>()(message);
	
	if (chunk.file_id != _header.file_id)
		return;

	auto index = chunk.chunk_id;
	if (index < 0 || index >= _chunks.size())
		return;

	_chunks[index] = chunk;
}

void FileReceiver::onFileEnd(const Message& message)
{
	std::cout << "Received File End for '" << _header.filename << "." << _header.extension << "' " << std::endl;

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
	return std::unique_ptr<FileSender>(new FileSender(header, socket));
}

std::unique_ptr<FileReceiver> FileTransfer::BeginReception(const Message& message)
{
	return std::unique_ptr<FileReceiver>(new FileReceiver(message));
}
