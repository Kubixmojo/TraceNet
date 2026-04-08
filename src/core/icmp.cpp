#include <cstdint>


uint16_t calculate_checksum(void* data, int length) {
    uint16_t* ptr = (uint16_t*)data;
    uint32_t sum = 0;

    for (int i = 0; i < length / 2; i++) {
        sum += ptr[i];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}