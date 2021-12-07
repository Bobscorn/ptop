cmake_minimum_required(VERSION 3.13.4)
project(ptop)

set(srcs "" "src/ip.cpp")

add_executable(ptop ${PROJECT_SOURCE_DIR}/src/main.cpp ${srcs})
