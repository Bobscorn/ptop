cmake_minimum_required(VERSION 3.13.4)
project(ptop)

set(srcs "src/socket.cpp" "src/ip.cpp" "src/server.cpp" "src/client.cpp" "src/message.cpp")

if (WIN32)
set(srcs ${srcs} "src/windows_socket.cpp")
#else()
#set(srcs ${srcs} "src/linux_socket.cpp")
endif(WIN32)

add_executable(ptop ${PROJECT_SOURCE_DIR}/src/main.cpp ${srcs})
