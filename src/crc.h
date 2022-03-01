#pragma once


#include <cinttypes>
#include <vector>

uint32_t crc_data(const std::vector<char>& data);

bool compare_crc(const std::vector<char>& data, uint32_t existing_crc);