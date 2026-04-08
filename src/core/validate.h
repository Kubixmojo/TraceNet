#pragma once
#include <string>

enum class HostType { IPV4, IPV6, HOSTNAME, INVALID };

struct HostValidation {
    HostType type;
    std::string error;
};

HostValidation validate_host(const std::string& host);