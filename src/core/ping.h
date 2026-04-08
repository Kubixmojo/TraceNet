// ping.h

#pragma once
#include <string>
#include <cstdint>

// ─── opcje pinga ─────────────────────────────────────────────
struct PingOptions {
    int     count       = 4;      // -c  ile pakietów (0 = nieskończoność)
    int     interval_ms = 1000;   // -i  przerwa między pakietami [ms]
    int     timeout_ms  = 1000;   // -W  timeout na odpowiedź [ms]
    int     payload     = 56;     // -s  rozmiar payload [bytes]
    int     ttl         = 64;     // -t  TTL wychodzący
    bool    ipv6        = false;  // -6  wymuś IPv6
    bool    ipv4        = false;  // -4  wymuś IPv4
    uint8_t tos         = 0;      // -Q  Type of Service / DSCP
    bool    dont_frag   = false;  // -M do  nie fragmentuj (DF bit)
};

// ─── wynik jednego pinga ──────────────────────────────────────
struct PingResult {
    bool        success = false;
    double      rtt_ms;
    std::string from_ip;
    int         bytes   = 0;       // bytes odebranych (payload + nagłówki)
    int         ttl     = -1;         // TTL z odpowiedzi
    int         seq     = 0;         // numer sekwencji
    bool        timeout = false;
    std::string error;       // opis błędu jeśli !success && !timeout
};

// ─── API ─────────────────────────────────────────────────────
// pojedynczy ping z pełnymi opcjami
PingResult ping(const char* host, const PingOptions& opts = {}, int seq = 1);