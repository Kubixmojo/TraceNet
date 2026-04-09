#include "cmd_traceroute.h"
#include "../core/traceroute.h"
#include "../core/validate.h"
#include "../colors.h"
#include <iostream>
#include <iomanip>
#include <cmath>

void cmd_traceroute(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "użycie: traceroute <host>\n";
        return;
    }

    auto v = validate_host(args[1]);
    if (v.type == HostType::INVALID) {
        std::cout << CLR_ERROR << "błąd: " << v.error << CLR_RESET << "\n";
        return;
    }

    std::cout << "Traceroute to " << args[1] << " max 30 hops:\n";

    TracerouteOptions opts;
    auto results = traceroute(args[1], opts);

    for (auto& hop : results) {
        std::cout << CLR_GRAY << std::setw(3) << hop.hop << " | " << CLR_RESET;
        if (hop.timeout) {
            std::cout << std::setw(3) << "" << CLR_GRAY << "************" << CLR_RESET << "\n";
        } else {
            int rtt = static_cast<int>(std::round(std::max(1.0, hop.rtt_ms)));
            std::cout << std::setw(15) << hop.ip << "  "
                      << CLR_ORANGE << std::setw(2) << rtt
                      << CLR_GRAY << "ms" << CLR_RESET;
            if (hop.reached) std::cout << CLR_GREEN << "  (Target)" << CLR_RESET;
            std::cout << "\n";
        }
    }
}