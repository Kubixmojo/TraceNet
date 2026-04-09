#pragma once
#include <string>
#include <cstdint>

struct PingOptions {
    int     count       = 4;      
    int     interval_ms = 1000;   
    int     timeout_ms  = 1000;   
    int     payload     = 56;     
    int     ttl         = 64;     
    bool    ipv6        = false;  
    bool    ipv4        = false;  
    uint8_t tos         = 0;      
    bool    dont_frag   = false;  
};

struct PingResult {
    bool        success = false;
    double      rtt_ms;
    std::string from_ip;
    int         bytes   = 0;       
    int         ttl     = -1;         
    int         seq     = 0;         
    bool        timeout = false;
    std::string error;       
};

PingResult ping(const char* host, const PingOptions& opts = {}, int seq = 1);