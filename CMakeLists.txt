cmake_minimum_required(VERSION 3.8)

include(ExternalProject)

project(P2PVPN LANGUAGES CXX)

add_subdirectory(thirdparty/libjuice)
add_subdirectory(thirdparty/libui)

add_executable(vpn src/main.cpp)

target_compile_features(vpn PRIVATE cxx_std_11)
target_link_libraries(vpn PRIVATE juice-static libui)
target_include_directories(vpn PRIVATE thirdparty)

if(WIN32)
    target_link_libraries(vpn PRIVATE iphlpapi)
    target_compile_definitions(vpn PRIVATE $<$<NOT:$<CONFIG:Debug>>:WINDOWS_SUBSYSTEM>)
    set_target_properties(vpn PROPERTIES WIN32_EXECUTABLE $<NOT:$<CONFIG:Debug>>)
endif()