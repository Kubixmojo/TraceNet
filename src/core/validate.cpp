#include "validate.h"
#include <arpa/inet.h>

HostValidation validate_host(const std::string& host) {
    
    struct in_addr addr4;
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1)
        return { HostType::IPV4, "" };

    
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1)
        return { HostType::IPV6, "" };

    
        if (host.empty())
            return { HostType::INVALID, "pusty host" };

        
        for (char c : host) {
            if (!isalnum(c) && c != '-' && c != '.')
                return { HostType::INVALID, "niedozwolony znak: " + std::string(1, c) };
        }

        
        if (host.find('.') == std::string::npos)
            return { HostType::INVALID, "niepoprawny host: " + host };

        return { HostType::HOSTNAME, "" };

    
    return { HostType::INVALID, "niepoprawny host: " + host };
}
