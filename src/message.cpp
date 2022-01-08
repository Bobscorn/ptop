#include "message.h"
#include <iostream>
#include <string>



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

std::nested_exception print_new_exception(std::string input, std::string line_context) {
	auto together = (line_context + input);
	std::cout << together << std::endl;
	return std::nested_exception();
}
