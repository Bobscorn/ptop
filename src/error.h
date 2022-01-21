#pragma once

#include <string>

#ifndef LINE_CONTEXT
#define LINE_CONTEXT std::string("(" + std::to_string(__LINE__) + ", " + __func__ + ")")
#endif

void throw_new_exception(std::string input, std::string line_context);
void throw_with_context(const std::exception& e, std::string context);

void print_exception(const std::exception& e, int level = 0);