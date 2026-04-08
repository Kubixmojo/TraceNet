#include "iface.h"
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <net/if.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>

static std::string gen_suffix() {
    // 4 znaki hex losowe
    static bool seeded = false;
    if (!seeded) { srand(time(nullptr)); seeded = true; }
    std::ostringstream ss;
    ss << std::hex << std::setw(4) << std::setfill('0') << (rand() & 0xFFFF);
    return ss.str();
}

std::string iface_create(const std::string& display_name,
                          const std::string& ip,
                          const std::string& gw) {
    std::string real_name = "nt_" + display_name + "_" + gen_suffix();

    if (real_name.size() > 15)
        real_name = real_name.substr(0, 15);

    struct nl_sock* sk = nl_socket_alloc();
    if (!sk) return "";

    if (nl_connect(sk, NETLINK_ROUTE) < 0) {
        nl_socket_free(sk);
        return "";
    }

    struct rtnl_link* link = rtnl_link_alloc();
    if (!link) {
        nl_socket_free(sk);
        return "";
    }
    rtnl_link_set_type(link, "dummy");
    rtnl_link_set_name(link, real_name.c_str());

    int err = rtnl_link_add(sk, link, NLM_F_CREATE);
    rtnl_link_put(link);

    if (err < 0) {
        nl_socket_free(sk);
        return "";
    }

    // włącz kartę
    struct rtnl_link* change = rtnl_link_alloc();
    struct rtnl_link* orig   = rtnl_link_alloc();
    rtnl_link_set_name(orig, real_name.c_str());
    rtnl_link_set_flags(change, IFF_UP);
    rtnl_link_change(sk, orig, change, 0);
    rtnl_link_put(change);
    rtnl_link_put(orig);

    nl_socket_free(sk);
    return real_name;
}

bool iface_delete(const std::string& real_name) {
    // bezpieczeństwo — tylko nasze karty
    if (real_name.substr(0, 3) != "nt_") return false;

    struct nl_sock* sk = nl_socket_alloc();
    if (!sk) return false;

    if (nl_connect(sk, NETLINK_ROUTE) < 0) {
        nl_socket_free(sk);
        return false;
    }

    struct rtnl_link* link = rtnl_link_alloc();
    rtnl_link_set_name(link, real_name.c_str());

    int err = rtnl_link_delete(sk, link);
    rtnl_link_put(link);
    nl_socket_free(sk);

    return err >= 0;
}

std::vector<IfaceInfo> iface_list_all() {
    std::vector<IfaceInfo> result;

    struct nl_sock* sk = nl_socket_alloc();
    if (!sk) return result;
    if (nl_connect(sk, NETLINK_ROUTE) < 0) { nl_socket_free(sk); return result; }

    struct nl_cache* cache;
    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache) < 0) {
        nl_socket_free(sk);
        return result;
    }

    struct rtnl_link* link = (struct rtnl_link*)nl_cache_get_first(cache);
    while (link) {
        IfaceInfo info;
        info.real_name    = rtnl_link_get_name(link);
        info.display_name = info.real_name;
        info.up           = (rtnl_link_get_flags(link) & IFF_UP) != 0;

        // jeśli to nasza karta — wyciągnij display_name
        if (info.real_name.substr(0, 3) == "nt_") {
            // format: nt_<display>_<suffix4>
            std::string middle = info.real_name.substr(3); // "test_a3f9"
            auto last_us = middle.rfind('_');
            if (last_us != std::string::npos)
                info.display_name = middle.substr(0, last_us);
        }

        result.push_back(info);
        link = (struct rtnl_link*)nl_cache_get_next((struct nl_object*)link);
    }

    nl_cache_free(cache);
    nl_socket_free(sk);
    return result;
}

std::vector<IfaceInfo> iface_list_own() {
    std::vector<IfaceInfo> all = iface_list_all();
    std::vector<IfaceInfo> own;
    for (auto& i : all)
        if (i.real_name.substr(0, 3) == "nt_")
            own.push_back(i);
    return own;
}

IfaceDetails iface_info(const std::string& real_name) {
    IfaceDetails details{};
    details.name = real_name;

    struct nl_sock* sk = nl_socket_alloc();
    if (!sk) return details;
    if (nl_connect(sk, NETLINK_ROUTE) < 0) { nl_socket_free(sk); return details; }

    struct nl_cache* cache;
    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache) < 0) {
        nl_socket_free(sk);
        return details;
    }

    struct rtnl_link* link = rtnl_link_get_by_name(cache, real_name.c_str());
    if (link) {
        details.up  = (rtnl_link_get_flags(link) & IFF_UP) != 0;
        details.mtu = rtnl_link_get_mtu(link);

        // MAC
        struct nl_addr* addr = rtnl_link_get_addr(link);
        if (addr) {
            char mac[64];
            nl_addr2str(addr, mac, sizeof(mac));
            details.mac = mac;
        }

        rtnl_link_put(link);
    }

    // IP — osobny cache adresów
    struct nl_cache* addr_cache;
    if (rtnl_addr_alloc_cache(sk, &addr_cache) == 0) {
        int ifindex = rtnl_link_name2i(cache, real_name.c_str());

        struct rtnl_addr* raddr = (struct rtnl_addr*)nl_cache_get_first(addr_cache);
        while (raddr) {
            if (rtnl_addr_get_ifindex(raddr) == ifindex) {
                // tylko IPv4
                if (rtnl_addr_get_family(raddr) == AF_INET) {
                    struct nl_addr* local = rtnl_addr_get_local(raddr);
                    if (local) {
                        char ip[64];
                        nl_addr2str(local, ip, sizeof(ip));
                        details.ip = ip;
                    }
                }
            }
            raddr = (struct rtnl_addr*)nl_cache_get_next((struct nl_object*)raddr);
        }
        nl_cache_free(addr_cache);
    }

    nl_cache_free(cache);
    nl_socket_free(sk);
    return details;
}