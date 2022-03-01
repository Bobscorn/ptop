#include "message.h"

#include <iostream>
#include <string>
#include <array>

#include "loop.h"

const Message Message::null_message = Message{ MESSAGE_TYPE::NONE, (MESSAGE_LENGTH_T)-1, std::vector<char>() };

std::vector<char> Message::to_bytes() const
{
	std::vector<char> out_data{ sizeof(Type) + sizeof(Length) + Data.size(), '0', std::allocator<char>() };
	std::memcpy(out_data.data(), this, sizeof(Type) + sizeof(Length));
	auto offset = sizeof(Type) + sizeof(Length);
	for (int i = 0; i < Data.size(); ++i)
		out_data[i + offset] = Data[i];
	return out_data;
}

std::vector<Message> data_to_messages(const std::vector<char>& data)
{
    std::vector<Message> messages;
    if (data.size() > 0)
    {
        int data_read = 0;

        while ((data.size() - data_read) > 0)
        {
            MESSAGE_TYPE type;
            MESSAGE_LENGTH_T length;
            std::vector<char> msg_data;

            if (!try_read_data(data.data(), data_read, data.size(), type))
            {
                break;
            }
            if (!try_read_data(data.data(), data_read, data.size(), length))
            {
                break;
            }
            if ((size_t)data_read + length > data.size())
            {
                break;
            }
            msg_data = std::vector<char>(data.data() + data_read, data.data() + data_read + length);
            data_read += length;
            auto new_message = Message{ type, length, std::move(msg_data) };
            messages.push_back(new_message);
        }
    }

    return messages;
}

StreamMessage create_streammessage(MESSAGE_TYPE input_type, std::vector<char> data) {
	auto length = (MESSAGE_LENGTH_T) data.size();
	StreamMessage output;
	output.Type = input_type;
	output.Length = length;
	output.Data = std::move(data);
	auto to_crc = output.to_bytes();
	//auto crc = crc_data(to_crc);
	// new_size = length + sizeof(crc);
	//output.Data.resize(new_size);
	//output.chunk_crc = crc;
	return output;
}
