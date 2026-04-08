#pragma once
#include <string>
#include <vector>

struct HopResult {
    int hop;
    std::string ip;
    double rtt_ms;
    bool timeout;
    bool reached; // czy to cel
};

struct TracerouteOptions {
    int maxHops   = 30;
    int timeoutMs = 3000;
    int probes    = 3; // ile razy pingujemy każdy hop
};

std::vector<HopResult> traceroute(const std::string& host, const TracerouteOptions& opts);