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

void throw_new_exception(std::string input, std::string line_context) {
	auto together = (line_context + " " + input);
	std::cerr << together << std::endl;
	std::throw_with_nested(std::runtime_error(together));
}

void throw_with_context(const std::exception &e, std::string context)
{
	if (dynamic_cast<const std::nested_exception*>(&e) != nullptr)
		std::throw_with_nested(std::runtime_error(context));

	else
		throw e;
}

void print_exception(const std::exception& e, int level)
{
	std::cerr << std::string(level, ' ') << "exception: " << e.what() << "\n";
	try
	{
		std::rethrow_if_nested(e);
	}
	catch (const std::exception& e)
	{
		print_exception(e, level + 1);
	}
	catch (...) {}
}
