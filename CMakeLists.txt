cmake_minimum_required(VERSION 3.13.4)
project(ptop)

set(srcs "src/socket.cpp" "src/ip.cpp" "src/server.cpp" "src/client.cpp" "src/message.cpp" "src/protocol.cpp" "src/sock.cpp")

if (WIN32)
set(srcs ${srcs} "src/windows_socket.cpp" "src/windows_sock.cpp")
elseif(UNIX)
set(srcs ${srcs} "src/linux_socket.cpp" "src/linux_sock.cpp")
endif(WIN32)

set(CMAKE_CXX_STANDARD 17)
add_executable(ptop ${PROJECT_SOURCE_DIR}/src/clientmain.cpp ${srcs})
add_executable(ptop_rendezvous ${PROJECT_SOURCE_DIR}/src/servermain.cpp ${srcs})

if(UNIX)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(ptop PRIVATE Threads::Threads)
target_link_libraries(ptop_rendezvous PRIVATE Threads::Threads)
endif(UNIX)
