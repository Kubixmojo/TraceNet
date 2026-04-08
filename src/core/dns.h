#pragma once
#include <string>
#include <vector>

enum class DnsRecordType {
    A, AAAA, MX, CNAME, TXT, PTR, NS, SOA, UNKNOWN
};

struct DnsRecord {
    DnsRecordType type;
    std::string type_str;
    std::string value;
    int priority = 0; // dla MX
    int ttl      = 0;
};

struct DnsResult {
    std::string query;
    std::vector<DnsRecord> records;
    std::string error;
    bool success = false;
};

DnsResult dns_lookup(const std::string& host, const std::string& type = "ALL");
std::string dns_reverse(const std::string& ip); // PTR lookup