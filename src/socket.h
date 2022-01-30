#pragma once

#ifdef WIN32
#include <WinSock2.h>

#elif defined(__linux__)
#include <sys/types.h>
using SOCKET = int;
const int SOCKET_ERROR = -1;
#endif

