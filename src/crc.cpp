#include "crc.h"

#include <array>

constexpr uint32_t crc_polynomial = 0xBA0DC66Bu; // stole this polynomial from like.... somewhere

constexpr std::array<uint32_t, 256> calculate_table(uint32_t polynomial)
{
    auto width = sizeof(uint32_t) * 8;
    auto topbit = 1u << ((uint32_t)(width - 1));
    std::array<uint32_t, 256> tbl{};
    for (int dividend = 0; dividend < 256; ++dividend) {
        uint32_t remainder = dividend << (width - 8);
        for (uint8_t bit = 8; bit > 0; --bit) {
            if (remainder & topbit) {
                remainder = (remainder << 1) ^ crc_polynomial;
            }
            else {
                remainder = (remainder << 1);
            }
        }
        tbl[dividend] = remainder;
    }
    return tbl;
}

constexpr auto crc_table = calculate_table(crc_polynomial);

//Supposedly some CRC implementations 'reflect' some if not all parts of this algorithm
//Screw that
//Calculates a Cyclic Redundancy Checksum value (CRC) of an arbitrary length of data
//Utilizes the crc_table computed with the polynomial in crc_polynomial
//Don't ask how this works
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

bool compare_crc(const std::vector<char>& data, uint32_t existing_crc)
{
    uint32_t my_crc = crc_data(data);
    return my_crc == existing_crc;
}
