#include "time.h"

#include <stdio.h>
#include <tgmath.h>

std::string time_to_str(const s_time& time)
{
    char buffer[80];

    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count() % 1000;

    std::time_t tt;
    tt = std::chrono::system_clock::to_time_t(time);
    auto timeinf = localtime(&tt);
    strftime(buffer, 80, "%D %H:%M:%S", timeinf);
    sprintf(buffer, "%s.%03d", buffer, (int)millis);

    return std::string(buffer);
}

std::string duration_to_str(const s_duration& dur)
{
    using namespace std::chrono;
    auto hours_d = duration_cast<hours>(dur);
    auto minutes_d = duration_cast<minutes>(dur - hours_d);
    auto seconds_d = duration_cast<seconds>((dur - hours_d) - minutes_d);
    auto millis_d = duration_cast<std::chrono::duration<double, std::milli>>(((dur - hours_d) - minutes_d) - seconds_d);

    auto num_hours = hours_d.count();
    auto num_minutes = minutes_d.count();
    auto num_seconds = seconds_d.count();
    auto num_millis = millis_d.count();

    std::string dur_string = "";
    bool did_prev = false;
    if (num_hours)
    {
        char buf[80];
        std::snprintf(buf, 80, "%u:%0u:%0u.%00u h", num_hours, num_minutes, (int)num_seconds, (int)num_millis);
        return std::string(buf);
    }
    if (num_minutes)
    {
        char buf[60];
        std::snprintf(buf, 60, "%0u:%0u.%00u min", num_minutes, (int)num_seconds, (int)num_millis);
        return std::string(buf);
    }
    if (num_seconds)
    {
        char buf[40];
        std::snprintf(buf, 40, "%0u.%00u s", (int)num_seconds, (int)roundf(num_millis));
        return std::string(buf);
    }
    char buf[20];
    std::snprintf(buf, 20, "%1.3f ms", num_millis);
    return std::string(buf);
}