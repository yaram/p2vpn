cmake_minimum_required(VERSION 3.8)

include(ExternalProject)

project(P2VPN LANGUAGES CXX)

add_subdirectory(thirdparty/libjuice)
add_subdirectory(thirdparty/qtbase)

add_executable(p2vpn src/main.cpp)

target_compile_features(p2vpn PRIVATE cxx_std_11)
target_link_libraries(p2vpn PRIVATE juice-static Qt::Core Qt::Gui Qt::Widgets Qt::QWindowsIntegrationPlugin)
target_include_directories(p2vpn PRIVATE thirdparty)

if(WIN32)
    target_link_libraries(p2vpn PRIVATE iphlpapi)
    target_compile_definitions(p2vpn PRIVATE $<$<NOT:$<CONFIG:Debug>>:WINDOWS_SUBSYSTEM>)
    set_target_properties(
        p2vpn
        PROPERTIES
        WIN32_EXECUTABLE $<NOT:$<CONFIG:Debug>>
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()