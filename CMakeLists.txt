cmake_minimum_required(VERSION 3.22)

if(WIN32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(ExternalProject)

project(P2VPN LANGUAGES CXX)

add_subdirectory(thirdparty/libjuice)
add_subdirectory(thirdparty/qtbase)

set(SOURCES
    src/main.h
    src/main.cpp
)

qt6_wrap_cpp(SOURCES src/main.h TARGET p2vpn)

add_executable(p2vpn ${SOURCES})

target_compile_features(p2vpn PRIVATE cxx_std_11)
target_link_libraries(p2vpn PRIVATE juice-static Qt::Core Qt::Gui Qt::Widgets Qt::QWindowsIntegrationPlugin)
target_include_directories(p2vpn PRIVATE thirdparty)

if(WIN32)
    target_link_libraries(p2vpn PRIVATE iphlpapi)
    target_include_directories(p2vpn PRIVATE thirdparty/wintun/include)

    target_compile_definitions(p2vpn PRIVATE $<$<NOT:$<CONFIG:Debug>>:WINDOWS_SUBSYSTEM>)
    set_target_properties(
        p2vpn
        PROPERTIES
        WIN32_EXECUTABLE $<NOT:$<CONFIG:Debug>>
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )

    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/wintun.dll"
        COMMAND cmake -E copy
            "\"${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/wintun/bin/${CMAKE_SYSTEM_PROCESSOR}/wintun.dll\""
            "\"${CMAKE_CURRENT_BINARY_DIR}/wintun.dll\""
        MAIN_DEPENDENCY "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/wintun/bin/${CMAKE_SYSTEM_PROCESSOR}/wintun.dll"
    )
    add_custom_target(copy_wintun_dll DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/wintun.dll")
    add_dependencies(p2vpn copy_wintun_dll)
endif()