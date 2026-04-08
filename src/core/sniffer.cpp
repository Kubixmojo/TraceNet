#include "sniffer.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <ctime>

#define CLR_RESET   "\033[0m"
#define CLR_GRAY    "\033[90m"
#define CLR_CYAN    "\033[36m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_RED     "\033[31m"
#define CLR_BLUE    "\033[94m"
#define CLR_ORANGE  "\033[38;5;214m"

static void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    // timestamp
    time_t t = header->ts.tv_sec;
    struct tm* tm_info = localtime(&t);
    char timebuf[16];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm_info);

    // ethernet header
    struct ether_header* eth = (struct ether_header*)packet;
    uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != ETHERTYPE_IP && eth_type != ETHERTYPE_IPV6) return;

    // IP header
    struct ip* iph = (struct ip*)(packet + sizeof(struct ether_header));
    std::string src = inet_ntoa(iph->ip_src);
    std::string dst = inet_ntoa(iph->ip_dst);
    int proto = iph->ip_p;
    int len   = ntohs(iph->ip_len);

    std::string proto_str;
    std::string color;

    switch (proto) {
        case IPPROTO_TCP:  proto_str = "TCP ";  color = CLR_CYAN;   break;
        case IPPROTO_UDP:  proto_str = "UDP ";  color = CLR_GREEN;  break;
        case IPPROTO_ICMP: proto_str = "ICMP";  color = CLR_YELLOW; break;
        default:
            proto_str = "IP  ";
            color = CLR_GRAY;
    }

    // port info dla TCP/UDP
    std::string port_info = "";
    int ip_header_len = iph->ip_hl * 4;

    if (proto == IPPROTO_TCP) {
        struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        int sport = ntohs(tcph->source);
        int dport = ntohs(tcph->dest);

        // flagi TCP
        std::string flags = "";
        if (tcph->syn) flags += "S";
        if (tcph->ack) flags += "A";
        if (tcph->fin) flags += "F";
        if (tcph->rst) flags += "R";
        if (tcph->psh) flags += "P";
        if (flags.empty()) flags = "-";

        port_info = " " + std::to_string(sport) + " -> " + std::to_string(dport) + " [" + flags + "]";
    } else if (proto == IPPROTO_UDP) {
        struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        int sport = ntohs(udph->source);
        int dport = ntohs(udph->dest);
        port_info = " " + std::to_string(sport) + " -> " + std::to_string(dport);
    }

    std::cout << CLR_GRAY << timebuf << "  "
              << color << proto_str << CLR_RESET << "  "
              << CLR_BLUE << std::setw(15) << src << CLR_RESET
              << CLR_GRAY << " -> " << CLR_RESET
              << CLR_BLUE << std::setw(15) << dst << CLR_RESET
              << CLR_ORANGE << port_info << CLR_RESET
              << CLR_GRAY << "  " << len << " B" << CLR_RESET
              << "\n";
}

void sniff_start(const SnifferOptions& opts) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // znajdź domyślny interfejs jeśli nie podano
    std::string iface = opts.iface;
    if (iface.empty()) {
        pcap_if_t* devs;
        if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
            iface = devs->name;
            pcap_freealldevs(devs);
        }
    }

    std::cout << "Sniffing on " << iface;
    if (!opts.filter.empty())
        std::cout << "  filter: " << opts.filter;
    std::cout << "\nCtrl+C to stop\n\n";

    pcap_t* handle = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cout << "Błąd: " << errbuf << " (sudo?)\n";
        return;
    }

    // ustaw filtr BPF
    if (!opts.filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, opts.filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(handle, &fp) < 0) {
            std::cout << "Błąd filtra: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
    }

    pcap_loop(handle, opts.count, packet_handler, nullptr);
    pcap_close(handle);
}