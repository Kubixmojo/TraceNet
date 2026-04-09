#include "cmd_dns.h"
#include "../core/dns.h"
#include "../core/validate.h"
#include "../colors.h"
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

void cmd_dns(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "użycie: dns <host> [A|AAAA|MX|CNAME|TXT|NS|SOA|PTR]\n";
        std::cout << "  domyślnie: wszystkie rekordy\n";
        return;
    }

    auto v = validate_host(args[1]);
    if (v.type == HostType::INVALID) {
        std::cout << CLR_ERROR << "błąd: " << v.error << CLR_RESET << "\n";
        return;
    }

    std::string type = (args.size() >= 3) ? args[2] : "ALL";

    
    struct in_addr tmp;
    if (inet_pton(AF_INET, args[1].c_str(), &tmp) == 1) {
        std::cout << "PTR " << args[1] << " → " << dns_reverse(args[1]) << "\n";
        return;
    }

    std::cout << "DNS lookup: " << args[1] << " [" << type << "]\n\n";

    DnsResult result = dns_lookup(args[1], type);

    if (!result.success || result.records.empty()) {
        std::cout << "Brak rekordów\n";
        return;
    }

    for (auto& rec : result.records) {
        std::cout << std::left << std::setw(8) << rec.type_str;
        if (rec.type == DnsRecordType::MX)
            std::cout << std::setw(5) << rec.priority << " ";
        std::cout << rec.value << "  (TTL=" << rec.ttl << ")\n";
    }
}