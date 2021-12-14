cmake_minimum_required(VERSION 3.13.4)
project(ptop)

set(srcs "src/socket.cpp" "src/ip.cpp" "src/server.cpp" "src/client.cpp" "src/message.cpp")

if (WIN32)
set(srcs ${srcs} "src/windows_socket.cpp")
elseif(UNIX)
set(srcs ${srcs} "src/linux_socket.cpp")
endif(WIN32)

set(CMAKE_CXX_STANDARD 17)
add_executable(ptop ${PROJECT_SOURCE_DIR}/src/main.cpp ${srcs})

if(UNIX)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(ptop PRIVATE Threads::Threads)
endif(UNIX)
