#pragma once
#include <string>
#include <vector>

struct PortResult {
    int port;
    bool open;
};

struct PortScanOptions {
    std::string host;
    int startPort;
    int endPort;
    int timeoutMs = 100;
};

std::vector<PortResult> scanPorts(const PortScanOptions& opts);