#pragma once

#include <string>

#ifndef LINE_CONTEXT
#define LINE_CONTEXT (std::string("(") +  __func__ + ", " + std::to_string(__LINE__) + ")")
#endif

[[noreturn]] void throw_new_exception(std::string input, std::string line_context);
void throw_with_context(const std::exception& e, std::string context);

void print_exception(const std::exception& e, int level = 0);