#pragma once
#include <string>
#include <pcap.h>

struct SnifferOptions {
    std::string iface;
    std::string filter;
    int count = 0; // 0 = nieskończoność
};

void sniff_start(const SnifferOptions& opts);