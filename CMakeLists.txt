cmake_minimum_required(VERSION 3.16)
project(Tracert VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

# ftxui - pobiera samo podczas cmake
include(FetchContent)
FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(Tracert
    src/main.cpp
    src/icmp.cpp
    src/ping.cpp
    src/portscan.cpp
    src/traceroute.cpp
    src/dns.cpp
    src/iface.cpp
    src/sniffer.cpp
    src/validate.cpp
    src/ssl.cpp
)

# podpięcie bibliotek
target_link_libraries(Tracert PRIVATE
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

target_include_directories(Tracert PRIVATE
    src
    /usr/include/libnl3
)