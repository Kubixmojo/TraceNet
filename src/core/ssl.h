#pragma once
#include <string>
#include <vector>

struct SslSan {
    std::string value; // np. "cloud.arternis.com"
};

struct SslResult {
    std::string host;
    int port = 443;

    std::string subject;   // CN=...
    std::string issuer;    // np. "Let's Encrypt"
    std::string valid_from;
    std::string valid_to;

    std::vector<SslSan> sans;

    int days_left = 0;     // ile dni do wygaśnięcia (ujemne = wygasł)
    bool expired  = false;
    bool success  = false;
    std::string error;
};

SslResult ssl_check(const std::string& host, int port = 443);