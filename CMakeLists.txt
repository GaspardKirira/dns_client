cmake_minimum_required(VERSION 3.20)
project(dns_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(dns_client INTERFACE)
add_library(dns_client::dns_client ALIAS dns_client)

target_include_directories(dns_client INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(dns_client INTERFACE /W4 /permissive-)
else()
  target_compile_options(dns_client INTERFACE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
enable_testing()

add_executable(dns_client_basic_test tests/test_basic.cpp)
target_link_libraries(dns_client_basic_test PRIVATE dns_client::dns_client)
add_test(NAME dns_client.basic COMMAND dns_client_basic_test)
