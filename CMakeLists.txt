cmake_minimum_required(VERSION 3.13.4)
project(mmr)

set(srcs "")

add_executable(mmr_client ${PROJECT_SOURCE_DIR}/src/main.cpp ${srcs})
add_executable(mmr_server ${PROJECT_SOURCE_DIR}/src/server.cpp ${srcs})
