cmake_minimum_required(VERSION 3.16)
project(TraceNet VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(TraceNet
    src/main.cpp
    src/repl.cpp

    # cli
    src/cli/cmd_ping.cpp
    src/cli/cmd_dns.cpp
    src/cli/cmd_traceroute.cpp

    # core
    src/core/icmp.cpp
    src/core/ping.cpp
    src/core/portscan.cpp
    src/core/traceroute.cpp
    src/core/dns.cpp
    src/core/validate.cpp
)

target_link_libraries(TraceNet PRIVATE
    readline
    pcap
    nl-3
    nl-route-3
    ftxui::screen
    ftxui::dom
    ftxui::component
    pthread
    resolv
    ssl
    crypto
)

target_include_directories(TraceNet PRIVATE
    src
    src/core
    src/cli
    src/ui
    /usr/include/libnl3
)