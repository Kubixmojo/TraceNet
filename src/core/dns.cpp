#include "dns.h"
#include <resolv.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <sstream>

static std::string type_to_str(DnsRecordType t) {
    switch(t) {
        case DnsRecordType::A:     return "A";
        case DnsRecordType::AAAA:  return "AAAA";
        case DnsRecordType::MX:    return "MX";
        case DnsRecordType::CNAME: return "CNAME";
        case DnsRecordType::TXT:   return "TXT";
        case DnsRecordType::PTR:   return "PTR";
        case DnsRecordType::NS:    return "NS";
        case DnsRecordType::SOA:   return "SOA";
        default:                   return "UNKNOWN";
    }
}

static DnsResult query_type(const std::string& host, int qtype, DnsRecordType rtype) {
    DnsResult result;
    result.query = host;

    uint8_t buf[4096];
    int len = res_query(host.c_str(), C_IN, qtype, buf, sizeof(buf));
    if (len < 0) {
        result.error = "Brak odpowiedzi";
        return result;
    }

    ns_msg msg;
    if (ns_initparse(buf, len, &msg) < 0) {
        result.error = "Błąd parsowania";
        return result;
    }

    int count = ns_msg_count(msg, ns_s_an);
    for (int i = 0; i < count; i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) continue;

        DnsRecord rec;
        rec.type     = rtype;
        rec.type_str = type_to_str(rtype);
        rec.ttl      = ns_rr_ttl(rr);

        switch (qtype) {
            case T_A: {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof(ip));
                rec.value = ip;
                break;
            }
            case T_AAAA: {
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, ns_rr_rdata(rr), ip, sizeof(ip));
                rec.value = ip;
                break;
            }
            case T_MX: {
                rec.priority = ns_get16(ns_rr_rdata(rr));
                char name[NS_MAXDNAME];
                dn_expand(ns_msg_base(msg), ns_msg_end(msg),
                          ns_rr_rdata(rr) + 2, name, sizeof(name));
                rec.value = name;
                break;
            }
            case T_CNAME:
            case T_PTR:
            case T_NS: {
                char name[NS_MAXDNAME];
                dn_expand(ns_msg_base(msg), ns_msg_end(msg),
                          ns_rr_rdata(rr), name, sizeof(name));
                rec.value = name;
                break;
            }
            case T_TXT: {
                const uint8_t* rdata = ns_rr_rdata(rr);
                int rdlen = ns_rr_rdlen(rr);
                int pos = 0;
                std::string txt;
                while (pos < rdlen) {
                    int slen = rdata[pos++];
                    txt += std::string((char*)rdata + pos, slen);
                    pos += slen;
                }
                rec.value = txt;
                break;
            }
            case T_SOA: {
                char mname[NS_MAXDNAME], rname[NS_MAXDNAME];
                const uint8_t* rdata = ns_rr_rdata(rr);
                int off = dn_expand(ns_msg_base(msg), ns_msg_end(msg), rdata, mname, sizeof(mname));
                dn_expand(ns_msg_base(msg), ns_msg_end(msg), rdata + off, rname, sizeof(rname));
                uint32_t serial  = ns_get32(rdata + off + dn_skipname(rdata + off, ns_msg_end(msg)));
                std::ostringstream ss;
                ss << mname << " " << rname << " serial=" << serial;
                rec.value = ss.str();
                break;
            }
            default:
                rec.value = "?";
        }

        result.records.push_back(rec);
    }

    result.success = true;
    return result;
}

DnsResult dns_lookup(const std::string& host, const std::string& type) {
    DnsResult combined;
    combined.query = host;

    auto merge = [&](DnsResult r) {
        for (auto& rec : r.records)
            combined.records.push_back(rec);
        if (r.success) combined.success = true;
    };

    if (type == "ALL" || type == "A")     merge(query_type(host, T_A,     DnsRecordType::A));
    if (type == "ALL" || type == "AAAA")  merge(query_type(host, T_AAAA,  DnsRecordType::AAAA));
    if (type == "ALL" || type == "MX")    merge(query_type(host, T_MX,    DnsRecordType::MX));
    if (type == "ALL" || type == "CNAME") merge(query_type(host, T_CNAME, DnsRecordType::CNAME));
    if (type == "ALL" || type == "TXT")   merge(query_type(host, T_TXT,   DnsRecordType::TXT));
    if (type == "ALL" || type == "NS")    merge(query_type(host, T_NS,    DnsRecordType::NS));
    if (type == "ALL" || type == "SOA")   merge(query_type(host, T_SOA,   DnsRecordType::SOA));

    return combined;
}

std::string dns_reverse(const std::string& ip) {
    // zamień IP na format reverse: 8.8.8.8 → 8.8.8.8.in-addr.arpa
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        return "Nieprawidłowy IP";

    uint8_t* b = (uint8_t*)&addr;
    char reverse[128];
    snprintf(reverse, sizeof(reverse), "%d.%d.%d.%d.in-addr.arpa",
             b[3], b[2], b[1], b[0]);

    auto r = query_type(reverse, T_PTR, DnsRecordType::PTR);
    if (!r.records.empty()) return r.records[0].value;
    return "Brak rekordu PTR";
}