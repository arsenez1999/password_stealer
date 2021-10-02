cmake_minimum_required(VERSION 3.8.0)
project(chrome)

file(GLOB CPPS "*.cpp")
add_library(${PROJECT_NAME} ${CPPS} sqlite3.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_CXX_STANDART 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)