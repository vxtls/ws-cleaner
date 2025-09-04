cmake_minimum_required(VERSION 3.15)
project(ws-cleaner)

set(CMAKE_CXX_STANDARD 20)

add_executable(ws-cleaner main.cpp)
add_subdirectory(vendor/spdlog)
include_directories(${CMAKE_SOURCE_DIR}/vendor)

target_include_directories(ws-cleaner PRIVATE ${CMAKE_SOURCE_DIR}/vendor)
#target_link_libraries(ws-cleaner pthread)
target_link_libraries(ws-cleaner PRIVATE spdlog::spdlog pthread)
