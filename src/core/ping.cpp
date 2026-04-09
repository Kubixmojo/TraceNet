#include "ping.h"
#include "icmp.h"

#include <ctime>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <vector>
#include <cstdint>

static long elapsed_ms(const timespec& start, const timespec& now)
{
    long sec  = now.tv_sec - start.tv_sec;
    long nsec = now.tv_nsec - start.tv_nsec;

    if (nsec < 0) {
        --sec;
        nsec += 1000000000L;
    }

    return sec * 1000L + nsec / 1000000L;
}


static bool resolve(const char* host, const PingOptions& opts,
                    sockaddr_storage& out, int& family)
{
    addrinfo hints{};
    addrinfo* res = nullptr;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = 0;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;

    if (opts.ipv6)      hints.ai_family = AF_INET6;
    else if (opts.ipv4) hints.ai_family = AF_INET;

    const int rc = getaddrinfo(host, nullptr, &hints, &res);
    if (rc != 0 || !res)
        return false;

    family = res->ai_family;
    std::memset(&out, 0, sizeof(out));
    std::memcpy(&out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return true;
}


static uint32_t checksum_accumulate(const uint8_t* data, size_t len, uint32_t sum = 0)
{
    while (len > 1) {
        sum += (static_cast<uint16_t>(data[0]) << 8) |
               static_cast<uint16_t>(data[1]);
        data += 2;
        len  -= 2;
    }

    if (len == 1)
        sum += static_cast<uint16_t>(data[0]) << 8;

    return sum;
}

static uint16_t checksum_finalize(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}


static uint16_t icmpv4_checksum(const void* data, size_t len)
{
    const auto* p = static_cast<const uint8_t*>(data);
    uint32_t sum = checksum_accumulate(p, len);
    return checksum_finalize(sum);
}

static uint16_t icmpv6_checksum(const sockaddr_in6& src,
                                const sockaddr_in6& dst,
                                const void* data,
                                size_t len)
{
    uint32_t sum = 0;

    sum = checksum_accumulate(
        reinterpret_cast<const uint8_t*>(&src.sin6_addr),
        sizeof(src.sin6_addr),
        sum
    );

    sum = checksum_accumulate(
        reinterpret_cast<const uint8_t*>(&dst.sin6_addr),
        sizeof(dst.sin6_addr),
        sum
    );

    uint8_t pseudo[40]{};

    
    pseudo[0] = static_cast<uint8_t>((len >> 24) & 0xff);
    pseudo[1] = static_cast<uint8_t>((len >> 16) & 0xff);
    pseudo[2] = static_cast<uint8_t>((len >> 8) & 0xff);
    pseudo[3] = static_cast<uint8_t>(len & 0xff);

    
    pseudo[7] = 58;

    sum = checksum_accumulate(pseudo, sizeof(pseudo), sum);
    sum = checksum_accumulate(static_cast<const uint8_t*>(data), len, sum);

    return checksum_finalize(sum);
}


static std::vector<uint8_t> build_packet(int family, int seq,
                                         int payload_size, pid_t id,
                                         const sockaddr_storage* local_src = nullptr,
                                         const sockaddr_storage* dst = nullptr)
{
    const size_t total = 8u + static_cast<size_t>(payload_size);
    std::vector<uint8_t> pkt(total, 0);

    if (family == AF_INET) {
        pkt[0] = 8;   
        pkt[1] = 0;
    } else {
        pkt[0] = 128; 
        pkt[1] = 0;
    }

    
    pkt[4] = static_cast<uint8_t>((id >> 8) & 0xff);
    pkt[5] = static_cast<uint8_t>(id & 0xff);
    pkt[6] = static_cast<uint8_t>((seq >> 8) & 0xff);
    pkt[7] = static_cast<uint8_t>(seq & 0xff);

    for (size_t i = 8; i < total; ++i)
        pkt[i] = static_cast<uint8_t>(i & 0xff);

    if (family == AF_INET) {
        uint16_t csum = icmpv4_checksum(pkt.data(), pkt.size());
        pkt[2] = static_cast<uint8_t>((csum >> 8) & 0xff);
        pkt[3] = static_cast<uint8_t>(csum & 0xff);
    } else if (family == AF_INET6) {
        if (!local_src || !dst)
            return pkt;

        const auto& src6 = *reinterpret_cast<const sockaddr_in6*>(local_src);
        const auto& dst6 = *reinterpret_cast<const sockaddr_in6*>(dst);

        uint16_t csum = icmpv6_checksum(src6, dst6, pkt.data(), pkt.size());
        pkt[2] = static_cast<uint8_t>((csum >> 8) & 0xff);
        pkt[3] = static_cast<uint8_t>(csum & 0xff);
    }

    return pkt;
}


PingResult ping(const char* host, const PingOptions& opts, int seq)
{
    PingResult result{};
    result.success = false;
    result.seq = seq;

    sockaddr_storage addr{};
    int family = AF_UNSPEC;
    if (!resolve(host, opts, addr, family)) {
        result.error = "nie można rozwiązać hosta";
        return result;
    }

    const int proto = (family == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
    int sock = socket(family, SOCK_RAW, proto);
    if (sock < 0) {
        result.error = "brak uprawnień (spróbuj sudo lub setcap)";
        return result;
    }

    auto fail = [&](const char* msg) -> PingResult {
        close(sock);
        result.error = msg;
        return result;
    };

    if (family == AF_INET6) {
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                       &opts.ttl, sizeof(opts.ttl)) < 0) {
            return fail(strerror(errno));
        }
    } else {
        if (setsockopt(sock, IPPROTO_IP, IP_TTL,
                       &opts.ttl, sizeof(opts.ttl)) < 0) {
            return fail(strerror(errno));
        }
    }

    if (family == AF_INET && opts.tos) {
        if (setsockopt(sock, IPPROTO_IP, IP_TOS,
                       &opts.tos, sizeof(opts.tos)) < 0) {
            return fail(strerror(errno));
        }
    }

    if (family == AF_INET && opts.dont_frag) {
        int val = IP_PMTUDISC_DO;
        if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER,
                       &val, sizeof(val)) < 0) {
            return fail(strerror(errno));
        }
    }

    if (family == AF_INET6) {
        int on = 1;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                       &on, sizeof(on)) < 0) {
            return fail(strerror(errno));
        }
    }

    
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr),
                (family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in)) < 0) {
        return fail(strerror(errno));
    }

    sockaddr_storage local_src{};
    socklen_t local_len = sizeof(local_src);
    if (family == AF_INET6) {
        if (getsockname(sock, reinterpret_cast<sockaddr*>(&local_src), &local_len) < 0) {
            return fail(strerror(errno));
        }
    }

    pid_t id = getpid() & 0xffff;
    auto pkt = build_packet(
        family,
        seq,
        opts.payload,
        id,
        (family == AF_INET6) ? &local_src : nullptr,
        &addr
    );

    timespec t0{}, t1{};
    clock_gettime(CLOCK_MONOTONIC, &t0);

    const ssize_t sent = send(sock, pkt.data(), pkt.size(), 0);
    if (sent < 0) {
        return fail(strerror(errno));
    }
    if (static_cast<size_t>(sent) != pkt.size()) {
        return fail("nie wysłano całego pakietu");
    }

    uint8_t buf[1500];
    sockaddr_storage sender{};
    iovec iov{ buf, sizeof(buf) };
    uint8_t cmsg_buf[256];
    msghdr msg{};

    msg.msg_name = &sender;
    msg.msg_namelen = sizeof(sender);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;

    while (true) {
        timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);

        long used = elapsed_ms(t0, now);
        long left = static_cast<long>(opts.timeout_ms) - used;
        if (left <= 0) {
            close(sock);
            result.timeout = true;
            result.error = "timeout";
            return result;
        }

        int ready = poll(&pfd, 1, static_cast<int>(left));
        if (ready < 0) {
            if (errno == EINTR)
                continue;

            close(sock);
            result.error = strerror(errno);
            return result;
        }

        if (ready == 0) {
            close(sock);
            result.timeout = true;
            result.error = "timeout";
            return result;
        }

        if (!(pfd.revents & POLLIN))
            continue;

        
        msg.msg_namelen = sizeof(sender);
        msg.msg_controllen = sizeof(cmsg_buf);

        const ssize_t received = recvmsg(sock, &msg, 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;

            close(sock);
            result.error = strerror(errno);
            return result;
        }

        bool matched = false;

        if (family == AF_INET) {
            if (received < static_cast<ssize_t>(sizeof(struct ip)))
                continue;

            auto* iph = reinterpret_cast<struct ip*>(buf);
            const int iphdr_len = iph->ip_hl * 4;

            if (iphdr_len < static_cast<int>(sizeof(struct ip)))
                continue;

            if (received < iphdr_len + 8)
                continue;

            auto* icmp = reinterpret_cast<struct icmphdr*>(buf + iphdr_len);

            if (icmp->type != ICMP_ECHOREPLY)
                continue;

            if (ntohs(icmp->un.echo.id) != id)
                continue;

            if (ntohs(icmp->un.echo.sequence) != seq)
                continue;

            result.ttl = iph->ip_ttl;
            result.bytes = static_cast<int>(received - iphdr_len);
            matched = true;
        } else {
            if (received < static_cast<ssize_t>(sizeof(struct icmp6_hdr)))
                continue;

            auto* icmp = reinterpret_cast<struct icmp6_hdr*>(buf);

            if (icmp->icmp6_type != ICMP6_ECHO_REPLY)
                continue;

            if (ntohs(icmp->icmp6_id) != id)
                continue;

            if (ntohs(icmp->icmp6_seq) != seq)
                continue;

            result.bytes = static_cast<int>(received);
            result.ttl = -1;

            for (cmsghdr* cm = CMSG_FIRSTHDR(&msg);
                 cm != nullptr;
                 cm = CMSG_NXTHDR(&msg, cm)) {
                if (cm->cmsg_level == IPPROTO_IPV6 &&
                    cm->cmsg_type == IPV6_HOPLIMIT &&
                    cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
                    result.ttl = *reinterpret_cast<int*>(CMSG_DATA(cm));
                    break;
                }
            }

            matched = true;
        }

        if (matched) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            break;
        }
    }

    char ip_str[INET6_ADDRSTRLEN]{};
    if (family == AF_INET) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&sender);
        if (!inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str))) {
            close(sock);
            result.error = strerror(errno);
            return result;
        }
    } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&sender);
        if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str))) {
            close(sock);
            result.error = strerror(errno);
            return result;
        }
    }

    close(sock);

    result.rtt_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
                  + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    double rtt = result.rtt_ms;
        if (rtt < 1.0)
            rtt = 1.0;

    result.from_ip = ip_str;
    result.success = true;
    return result;
}