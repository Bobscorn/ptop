#pragma once

#include <winsock2.h>

/// <summary>
/// An RAII Wrapper over WSAStartup and WSACleanup, called in constructors and destructors
/// </summary>
class windows_internet
{
	private:
	WSAData _data;

	public:
	windows_internet(WORD versionRequested);
	~windows_internet();
};
