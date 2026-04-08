#pragma once
#include <cstdint>

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

uint16_t calculate_checksum(void* data, int length);