#include "traceroute.h"
#include "icmp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <cstring>
#include <chrono>


std::vector<HopResult> traceroute(const std::string& host, const TracerouteOptions& opts) {
    std::vector<HopResult> results;

    // resolwuj cel
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) return results;

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));

    std::string dest_ip = inet_ntoa(dest.sin_addr);

    for (int ttl = 1; ttl <= opts.maxHops; ttl++) {
        HopResult hop;
        hop.hop     = ttl;
        hop.timeout = true;
        hop.reached = false;

        // send socket z TTL
        int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (send_sock < 0) break;

        setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        // recv socket
        int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (recv_sock < 0) { close(send_sock); break; }

        struct timeval tv;
        tv.tv_sec  = opts.timeoutMs / 1000;
        tv.tv_usec = (opts.timeoutMs % 1000) * 1000;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // buduj pakiet ICMP Echo Request
        uint8_t packet[64];
        memset(packet, 0, sizeof(packet));
        icmp_header* icmp = (icmp_header*)packet;
        icmp->type     = 8; // Echo Request
        icmp->code     = 0;
        icmp->id       = htons(getpid() & 0xFFFF);
        icmp->sequence = htons(ttl);
        icmp->checksum = calculate_checksum(packet, sizeof(packet));

        auto t_start = std::chrono::high_resolution_clock::now();
        sendto(send_sock, packet, sizeof(packet), 0,
               (struct sockaddr*)&dest, sizeof(dest));

        // odbierz odpowiedź
        uint8_t buf[512];
        struct sockaddr_in from{};
        socklen_t fromlen = sizeof(from);

        int n = recvfrom(recv_sock, buf, sizeof(buf), 0,
                         (struct sockaddr*)&from, &fromlen);

        if (n > 0) {
            auto t_end = std::chrono::high_resolution_clock::now();
            hop.rtt_ms  = std::chrono::duration<double, std::milli>(t_end - t_start).count();
            hop.ip      = inet_ntoa(from.sin_addr);
            hop.timeout = false;

            // sprawdź typ odpowiedzi
            icmp_header* resp = (icmp_header*)(buf + 20); // skip IP header
            if (resp->type == 0) // Echo Reply — dotarliśmy do celu
                hop.reached = true;
        }

        close(send_sock);
        close(recv_sock);
        results.push_back(hop);

        if (hop.reached) break;
    }

    return results;
}