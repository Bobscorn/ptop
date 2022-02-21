#pragma once

#include <chrono>
#include <string>

typedef std::chrono::time_point<std::chrono::system_clock> s_time;
typedef std::chrono::duration<float> s_duration;

inline decltype(auto) time_now() { return std::chrono::system_clock::now(); }
inline bool is_real_time(const s_time& t) { return t.time_since_epoch().count(); }
std::string time_to_str(const s_time& time);

std::string duration_to_str(const s_duration& dur);