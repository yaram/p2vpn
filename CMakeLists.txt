cmake_minimum_required(VERSION 3.8)

project(P2PVPN LANGUAGES CXX)

add_subdirectory(thirdparty/libjuice)

add_executable(vpn src/main.cpp)

target_compile_features(vpn PRIVATE cxx_std_11)
target_link_libraries(vpn PRIVATE juice-static)
target_include_directories(vpn PRIVATE thirdparty)

if(WIN32)
    target_link_libraries(vpn PRIVATE iphlpapi)
endif()