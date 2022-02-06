#include "filetransfer.h"

#include <cstdint>
#include <array>

StreamChunk FileSender::IterateNextChunk()
{
	return StreamChunk();
}

StreamChunk FileSender::GetTargetChunk(int index)
{
	return StreamChunk();
}

StreamChunk FileSender::onMissingChunk(const Message& mess)
{
	int read_index = 0;
	int missing_id = mess.read_type<int>(read_index);

	if (missing_id < 0 || missing_id >= _header.num_chunks)
	{
		std::cerr << "Received MISSING_CHUNK message with invalid chunk id" << std::endl;
		
	}
	return StreamChunk{};// ....for now
}

void FileSender::beginSending(PtopSocket& socket)
{
	processFileToChunks(_file, _chunks);
	_header.num_chunks = _chunks.size();
	auto mess = to_message<FileHeader>()(_header);
	socket.send_bytes(mess.to_bytes());
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

		chunk.chunk_crc = crc_data(chunk.data);

		chunks.push_back(chunk);
	}
}

void FileReceiver::onChunk(const Message& message)
{
}

void FileReceiver::onFileEnd(const Message& message)
{
}

FileReceiver::FileReceiver(const Message& message)
{
	from_message<FileHeader> from_msg;
	FileHeader header = from_msg(message);

	std::cout << "Receiving file: '" << header.filename << "." << header.extension << "' with " << header.num_chunks << " chunks" << std::endl;
}

void FileReceiver::checksum()
{
}

void FileReceiver::order_chunk()
{
}

std::unique_ptr<FileSender> FileTransfer::BeginTransfer(const FileHeader& header, PtopSocket& socket)
{
	return std::make_unique<FileSender>(header, socket);
}

std::unique_ptr<FileReceiver> FileTransfer::BeginReception(const Message& message)
{
	return std::make_unique<FileReceiver>(message);
}

constexpr uint32_t crc_polynomial = 0xBA0DC66Bu; // stole this polynomial from like.... somewhere

constexpr auto crc_table = [] {
	auto width = sizeof(uint32_t) * 8;
	auto topbit = 1u << ((uint32_t)(width - 1));
    std::array<uint32_t, 256> tbl{};
    for (int dividend = 0; dividend < 256; ++dividend) {
        uint32_t remainder = dividend << (width - 8);
        for (uint8_t bit = 8; bit > 0; --bit) {
            if (remainder & topbit) {
                remainder = (remainder << 1) ^ crc_polynomial;
            } else {
                remainder = (remainder << 1);
            }
        }
        tbl[dividend] = remainder;
    }
    return tbl;
}();

// Supposedly some CRC implementations 'reflect' some if not all parts of this algorithm
// Screw that
// Calculates a Cyclic Redundancy Checksum value (CRC) of an arbitrary length of data
// Utilizes the crc_table computed with the polynomial in crc_polynomial
uint32_t crc_data(const std::vector<char>& data)
{
	uint32_t remainder = 0xFFFFFFFF;
	size_t len = data.size();

	auto iter = data.begin();
	for (; len; --len, ++iter)
	{
		remainder = crc_table[((*iter) ^ (remainder)) & 0xff] ^ ((remainder) >> 8);
	}

	return ~remainder;
}
