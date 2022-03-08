cmake_minimum_required(VERSION 3.13.4)
project(ptop)

set(srcs "src/ptop_socket.cpp" "src/ip.cpp" "src/server.cpp" "src/client.cpp" "src/message.cpp" "src/protocol.cpp" "src/platform.cpp" "src/error.cpp" "src/time.cpp" "src/filetransfer.cpp" "src/commands.cpp" "src/crc.cpp" "src/negotiation.cpp")

if (WIN32)
set(srcs ${srcs} "src/windows_socket.cpp" "src/windows_platform.cpp" "src/windows_internet.cpp")
elseif(UNIX)
set(srcs ${srcs} "src/linux_socket.cpp" "src/linux_platform.cpp")
endif(WIN32)

option(PTOP_PRINT_DEBUG "Print extra debugging information to the standard output" OFF)
option(PTOP_SPOOF_IP "Insert fake ip addresses into the terminal instead of actual ones" OFF)

if(PTOP_PRINT_DEBUG)
	add_compile_definitions(DATA_COUT=1)
endif()

if(PTOP_SPOOF_IP)
	add_compile_definitions(PTOP_SPOOF_IP=1 PTOP_SPOOF_SERVER="111.111.111.111" PTOP_SPOOF_PUBLIC="123.456.789.101" PTOP_SPOOF_PRIVATE="10.0.0.1" PTOP_SPOOF_ME="1.0.0.1")
else()
	add_compile_definitions(PTOP_SPOOF_SERVER="" PTOP_SPOOF_PUBLIC="" PTOP_SPOOF_PRIVATE="")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)
add_executable(ptop ${PROJECT_SOURCE_DIR}/src/clientmain.cpp ${srcs})
add_executable(ptop_rendezvous ${PROJECT_SOURCE_DIR}/src/servermain.cpp ${srcs})


if(UNIX)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(ptop PRIVATE Threads::Threads)
target_link_libraries(ptop_rendezvous PRIVATE Threads::Threads)
endif(UNIX)
