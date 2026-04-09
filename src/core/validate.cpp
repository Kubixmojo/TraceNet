#include "validate.h"
#include <arpa/inet.h>

// TODO: IPv4 octet colorization
// - Add `int bad_octet = -1` to HostValidation struct (validate.h)
// - Replace inet_pton IPv4 check with manual parser (split by '.', 4 parts, each 0-255)
// - Track which octet (0-3) is invalid, store in bad_octet
// - In main.cpp: print each octet green/red based on bad_octet index

HostValidation validate_host(const std::string& host) {
    // IPv4
    struct in_addr addr4;
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1)
        return { HostType::IPV4, "" };

    // IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1)
        return { HostType::IPV6, "" };

    // hostname
        if (host.empty())
            return { HostType::INVALID, "pusty host" };

        // dozwolone znaki: litery, cyfry, myślnik, kropka
        for (char c : host) {
            if (!isalnum(c) && c != '-' && c != '.')
                return { HostType::INVALID, "niedozwolony znak: " + std::string(1, c) };
        }

        // musi mieć kropkę (google.com, nie samo "google")
        if (host.find('.') == std::string::npos)
            return { HostType::INVALID, "niepoprawny host: " + host };

        return { HostType::HOSTNAME, "" };

    // jeśli nic nie pasuje
    return { HostType::INVALID, "niepoprawny host: " + host };
}
