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
const StreamChunkState StreamChunkState::empty = StreamChunkState{ StreamChunk::empty, s_time(), StreamChunkAcknowledge::NONE };

const s_duration FileSender::ResendChunkInterval = 10s;
const s_duration FileSender::MaxIdleWaitTime = 20s;

const std::chrono::seconds FileTransfer::MaximumIdleWaitTime = 15s;


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
	_negotiator = Negotiator{};
}

void FileSender::sendFile(std::unique_ptr<IDataSocketWrapper>& socket) {
	if (!_received_initial_ack)
		return;

	constexpr s_duration consecutive_sending_timeout = 2s;

	std::vector<int32_t> sent_chunks{};

	s_time start_sending = time_now();
	const int data_size = MESSAGE_OVERHEAD + StreamChunk_OVERHEAD + CHUNK_SIZE;
	bool should_send = false;

	do {
		auto iter = IterateNextChunk();
		
		// chunk will be empty if have sent all chunks
		if(iter == _chunks.end()) {
			// Look for an unacknowledged chunk instead

			bool any_left_chunks = false;

			auto initial_scan = _last_chunk_scan; // Use cached _last_chunk_scan to resume where we last left off
			bool is_initial_scan = true;
			for (; _last_chunk_scan != initial_scan || is_initial_scan; ++_last_chunk_scan, is_initial_scan = false) 
			{
				if (_last_chunk_scan >= _chunks.size()) // Stop searching if we have reached the end, reset _last_chunk_scan so it will start from the beginning again
				{
					_last_chunk_scan = -1;
					continue;
				}

				auto& chunk = _chunks[_last_chunk_scan];

				if (chunk.acknowledge_state != StreamChunkAcknowledge::ACKNOWLEDGED && chunk.times_sent < 3)
				{
					any_left_chunks = true;
					if (time_now() - chunk.last_send_time > ResendChunkInterval)
					{
						sendChunk(chunk, socket);
						sent_chunks.push_back(_last_chunk_scan);
						break;
					}
				}
			}

			// Stop trying to send if all chunks have been acknowledged
			if (!any_left_chunks)
				break;

			// Continue sending if aren't sure all chunks have been acknowledged
			continue;
		}
		
		auto& chunk = *iter;
		sendChunk(chunk, socket);
		sent_chunks.push_back(iter - _chunks.begin());
		should_send = (time_now() - start_sending < consecutive_sending_timeout);
	}
	while(socket->can_send_data() && _negotiator.should_send_data(data_size) && should_send);

	if (_num_acked_chunks >= _header.num_chunks)
		std::cout << "\rProgress: 100%" << std::endl;
	else
		std::cout << "\rProgress: " << (float)_num_acked_chunks / (float)_header.num_chunks * 100.f << "%";
}

FileSender::chunk_iter FileSender::IterateNextChunk()
{
	auto index = _next_chunk_send++;
	if (index >= _chunks.size())
		return _chunks.end();
	return _chunks.begin() + index;
}

FileProgress FileSender::getProgress() const
{
	FileProgress prog;
	prog.filename = _header.filename + "." + _header.extension;
	prog.acknowledged_chunks = _num_acked_chunks;
	prog.sent_chunks = numChunksSent();
	prog.total_chunks = _header.num_chunks;

	prog.received_chunks = 0;
	return prog;
}

void FileSender::sendChunk(StreamChunkState& chunk, std::unique_ptr<IDataSocketWrapper>& socket)
{
	socket->send_message(chunk.chunk);
	_negotiator.sent_data();
	chunk.acknowledge_state = StreamChunkAcknowledge::SENT;
	_last_send = chunk.last_send_time = time_now();
	chunk.times_sent++;
}

std::string FileSender::getProgressString() const
{
	auto prog = getProgress();

	return "File: " + prog.filename + " sent " + std::to_string(prog.sent_chunks) + " chunks, acknowledged " + std::to_string(prog.acknowledged_chunks) + " chunks out of " + std::to_string(prog.total_chunks) + " chunks";
}

StreamChunkState FileSender::GetTargetChunk(int index)
{
	if (index < 0 || index >= _chunks.size())
		return StreamChunkState::empty;
	return _chunks[index];
}

void FileSender::onChunkError(const Message& mess, std::unique_ptr<IDataSocketWrapper>& socket)
{
	_last_activity = time_now();
	int read_index = 0;
	int missing_id = mess.read_type<int32_t>(read_index);

	if (missing_id < 0 || missing_id >= _header.num_chunks)
	{
		std::cerr << "Received CHUNK_ERROR on chunk id: " << missing_id << std::endl;
		return;
	}

	auto chunk = _chunks[missing_id];
	sendChunk(chunk, socket);
}

bool FileSender::onChunkAck(const Message& mess)
{
	_last_activity = time_now();

	int read_index = 0;
	auto chunk_id = mess.read_type<int32_t>(read_index);

	if (chunk_id < 0 || chunk_id >= _chunks.size())
	{
		std::cout << "Received acknowledgement with an invalid chunk index" << std::endl;
		return false;
	}

	if (_chunks[chunk_id].acknowledge_state != StreamChunkAcknowledge::ACKNOWLEDGED)
	{
		_num_acked_chunks++;
		_chunks[chunk_id].acknowledge_state = StreamChunkAcknowledge::ACKNOWLEDGED;
		return _num_acked_chunks >= _chunks.size();
	}

	_chunks[chunk_id].acknowledge_state = StreamChunkAcknowledge::ACKNOWLEDGED;

	return false;
}

bool FileSender::hasExpired() const
{
	return is_real_time(_last_activity) && (time_now() - _last_activity > MaxIdleWaitTime);
}

int FileSender::numChunksSent() const
{
	int num = 0;
	for (int i = 0; i < _chunks.size(); ++i)
	{
		if (_chunks[i].acknowledge_state != StreamChunkAcknowledge::NONE)
			num++;
	}
	return num;
}

int FileSender::numChunksAcked() const
{
	int num = 0;
	for (int i = 0; i < _chunks.size(); ++i)
	{
		if (_chunks[i].acknowledge_state == StreamChunkAcknowledge::ACKNOWLEDGED)
			num++;
	}
	return num;
}

int FileSender::numFileChunks() const
{
	return _chunks.size();
}

void FileSender::processFileToChunks(std::ifstream& ifs, std::vector<StreamChunkState>& chunks)
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
		StreamChunkState state{};
		auto& chunk = state.chunk;
		chunk.chunk_id = running_id++;
		chunk.data = std::vector<char>(CHUNK_SIZE, (char)0);
		ifs.read(chunk.data.data(), CHUNK_SIZE);

		last_read_count = ifs.gcount();
		if (last_read_count == max_size || last_read_count == 0)
			break;

		chunk.data_length = last_read_count;
		chunk.data.resize(last_read_count);

		chunks.push_back(state);
	}
}

FileReceiver::FileReceiver(const Message& message)
{
	from_message<FileHeader> from_msg;
	FileHeader header = from_msg(message);
	_header = header;

	std::cout << "Receiving file: '" << header.filename << "." << header.extension << "' with " << header.num_chunks << " chunks" << std::endl;
	if (header.num_chunks < 1)
	{
		std::cout << "It is an empty file" << std::endl;
	}
	else
	{
		int file_size_upper = header.num_chunks * CHUNK_SIZE / KILOBYTE;
		int file_size_lower = (header.num_chunks - 1) * CHUNK_SIZE / KILOBYTE;
		std::cout << "file is between: " << file_size_lower << "KB and " << file_size_upper << "KB" << std::endl;
	}

	_chunks.resize(_header.num_chunks, StreamChunk::empty);
}

FileProgress FileReceiver::getProgress() const
{
	FileProgress prog;
	prog.filename = _header.filename + "." + _header.extension;
	prog.received_chunks = _num_good_chunks;
	prog.total_chunks = _header.num_chunks;

	prog.sent_chunks = 0;
	prog.acknowledged_chunks = 0;
	return prog;
}

std::string FileReceiver::getProgressString() const
{
	auto prog = getProgress();

	return "File " + prog.filename + " received " + std::to_string(prog.received_chunks) + " out of " + std::to_string(prog.total_chunks) + " chunks";
}

bool FileReceiver::onChunk(const Message& message, std::unique_ptr<IDataSocketWrapper>& socket)
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
	std::cout << "Received chunk: " << chunk.chunk_id << std::endl;
	
	auto index = chunk.chunk_id;
	if (index < 0 || index >= _chunks.size())
		return false;

	if (_chunks[index] == StreamChunk::empty)
	{
		_num_good_chunks++;
		socket->send_data(create_message(MESSAGE_TYPE::CHUNK_ACKNOWLEDGED, chunk.chunk_id));
		if (_num_good_chunks >= _header.num_chunks)
		{
			_chunks[index] = chunk;
			write_to_file();
			return true;
		}
	}
	_chunks[index] = chunk;
	return false;
}

bool FileTransfer::timeout_expired(std::chrono::system_clock::time_point deadmanswitch) // Returns whether we have written and should be destroyed
{
	auto new_now = std::chrono::system_clock::now();

	if (is_real_time(deadmanswitch) && new_now - deadmanswitch > MaximumIdleWaitTime)
	{
		return true;
	}

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

int FileReceiver::numReceived() const
{
	return _num_good_chunks;
}

int FileReceiver::numFileChunks() const
{
	return _header.num_chunks;
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
