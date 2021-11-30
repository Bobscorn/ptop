cmake_minimum_required(VERSION 3.13.4)
project(mmr)

file(GLOB sourceglob
    "${PROJECT_SOURCE_DIR}/src/*.h" "${PROJECT_SOURCE_DIR}/src/*.cpp"
)

add_executable(mmr ${sourceglob})

