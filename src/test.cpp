
#include <memory>
#include <iostream>
#include <thread>
#include <chrono>

#include "socket.h"
#include "message.h"
#include "loop.h"

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mswsock.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "wininet.lib")

#include "windows_socket.h"
#endif // WIN32

using namespace std::chrono;

void print_exception(const std::exception& e, int level = 0)
{
	std::cerr << std::string(level, ' ') << "exception: " << e.what() << std::endl;
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

int main(int argc, char** argv)
{
	try
	{
#ifdef WIN32
		windows_internet wsa_wrapper{ MAKEWORD(2,2) };
#endif

		std::string test_port = "7987";

		auto test_listen = Sockets::CreateReusableNonBlockingListenSocket(test_port);

		auto test_connect = Sockets::CreateConnectionSocket("localhost", test_port);

		std::cout << "Successfully connected (Regular C -> ReNonB Listen) to self :D" << std::endl;

		int loops = 0;
	listen:
		if (test_listen->has_connection())
		{
			std::cout << "Test Listen (ReNonB Listen) has a connection" << std::endl;
			auto test_accept = test_listen->accept_connection();

			std::cout << "Successfully accepted connection" << std::endl;
		}
		else
		{
			std::cout << "Test Listen (ReNonB Listen) has no connection on its " << loops + 1 << "th/nd/st check" << std::endl;
			std::this_thread::sleep_for(100ms);
			if (loops++ > 5)
				goto not_listen;
			goto listen;
		not_listen:
			std::cout << "Test Listen (ReNonB) failed and sucks" << std::endl;
		}

		std::cout << "Now gonna try create reusable connect socket" << std::endl;

		auto name = test_connect->get_myname_raw();
		test_connect = nullptr;

		auto test_connect_2 = Sockets::CreateReusableConnectSocket(name);

		test_connect_2->connect("localhost", test_port);

		auto start_time = std::chrono::system_clock::now();
		auto duration = 10s;

		while (std::chrono::system_clock::now() - start_time < duration)
		{
			auto epic = test_connect_2->has_connected();
			if (epic == ConnectionStatus::SUCCESS)
			{
				std::cout << "Test ReNonB connection success!" << std::endl;
				break;
			}
			else if (epic == ConnectionStatus::FAILED)
			{
				std::cout << "Test ReNonB connection failed" << std::endl;
				break;
			}
		}

		std::cout << "Test completed with no exceptions" << std::endl;
	}
	catch (const std::exception& e)
	{
		print_exception(e);
		throw e;
	}
}