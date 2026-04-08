// main.cpp

#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <cmath>
#include <iomanip>
#include <csignal>
#include <algorithm>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ping.h"
#include "portscan.h"
#include "traceroute.h"
#include "dns.h"
#include "iface.h"
#include "sniffer.h"
#include "validate.h"
#include "ssl.h"

#define CLR_RESET   "\033[0m"
#define CLR_ERROR   "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_CYAN    "\033[36m"
#define CLR_BOLD    "\033[1m"
#define CLR_GRAY    "\033[90m" 
#define CLR_ORANGE  "\033[38;5;214m"

static pid_t ping_pid = -1;

void sigint_handler(int) {
    if (ping_pid > 0) {
        kill(ping_pid, SIGINT);
        ping_pid = -1;
    }
}

void run_ping(const char* host, const PingOptions& opts);
void run_scan(const std::string& host, const std::string& range, int timeoutMs);
void run_traceroute(const std::string& host);
void run_dns(const std::string& host, const std::string& type);
void run_sniff(const std::string& iface, const std::string& filter);
void run_ssl(const std::string& host, int port); 

static std::map<std::string, std::string> own_ifaces;

std::vector<std::string> split(const std::string& input) {
    std::istringstream iss(input);
    std::vector<std::string> tokens;
    std::string word;
    while (iss >> word)
        tokens.push_back(word);
    return tokens;
}

// lista komend do autocomplete
static const char* commands[] = {
    "ping", "scan", "traceroute", "use", "back", "help", "exit", nullptr
};

// funkcja completera
char* command_completer(const char* text, int state) {
    static int idx;
    if (state == 0) idx = 0;

    while (commands[idx]) {
        const char* cmd = commands[idx++];
        if (strncmp(cmd, text, strlen(text)) == 0)
            return strdup(cmd);
    }
    return nullptr;
}

struct CommandInfo {
    std::string usage;
    std::string description;
    std::string details;
};

static const std::map<std::string, CommandInfo> help_map = {
    {"ping", {
        "ping <host> [-c <n>]",
        "Wysyła pakiety ICMP do hosta",
        "  -c <n>    liczba pakietów (domyślnie: nieskończoność)\n"
        "  Ctrl+C    przerywa\n"
        "  Przykład: ping 8.8.8.8 -c 4\n"
    }},
    {"scan", {
        "scan <host> [porty] [-t <ms>]",
        "Skanuje porty TCP na hoście",
        "  [porty]   pojedynczy: 80\n"
        "            zakres:     1-1024\n"
        "            lista:      80,443,22\n"
        "            mix:        1-100,443,8080\n"
        "            domyślnie:  1-1024\n"
        "  -t <ms>   timeout w ms (domyślnie: 100)\n"
        "  Przykład: scan 192.168.1.1 1-1024 -t 200\n"
    }},
    {"traceroute", {
        "traceroute <host>",
        "Śledzi trasę pakietów do hosta",
        "  Wymaga sudo (raw sockety)\n"
        "  Przykład: traceroute 8.8.8.8\n"
    }},
    {"use", {
        "use <nazwa>",
        "Ustawia aktywny workspace",
        "  Przykład: use eth0\n"
    }},
    {"back", {
        "back",
        "Wychodzi z workspace'u",
        ""
    }},
    {"exit", {
        "exit",
        "Zamyka program",
        ""
    }},
};

int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    signal(SIGTSTP, sigint_handler);

    std::cout << "nettools v0.3 - wpisz 'help' lub 'exit'\n";

    std::string current_workspace = "";

    rl_attempted_completion_function = nullptr;
    rl_completion_entry_function = command_completer;

    while (true) {
        std::string prompt = current_workspace.empty()
            ? "nettools> "
            : "[" + current_workspace + "]> ";

        char* raw = readline(prompt.c_str());
        if (!raw) break; // ctrl+d

        std::string line(raw);
        free(raw);

        if (line.empty()) continue;
        add_history(line.c_str());

        if (line == "exit") break;
        else if (line == "help") {
            std::cout << "Dostępne komendy:\n\n";
            for (auto& [name, info] : help_map)
                std::cout << "  " << std::left << std::setw(20) << info.usage
                        << "  " << info.description << "\n";
            std::cout << "\nwpisz 'help <komenda>' aby uzyskać więcej informacji\n";
        }
        else if (line.substr(0, 5) == "help ") {
            std::string cmd = line.substr(5);
            auto it = help_map.find(cmd);
            if (it != help_map.end()) {
                std::cout << "Użycie: " << it->second.usage << "\n";
                std::cout << it->second.description << "\n\n";
                if (!it->second.details.empty())
                    std::cout << it->second.details;
            } else {
                std::cout << "Nieznana komenda: " << cmd << "\n";
            }
        }
        else if (line == "back") current_workspace = "";
        else if (line.substr(0, 4) == "use ") current_workspace = line.substr(4);
        else if (line.substr(0, 4) == "ping") {
            auto args = split(line);

            if (args.size() < 2) {
                std::cout << "użycie: ping <host> [-c <n>]\n";
                continue;
            }

            std::string host_str = args[1];

            //Walidation
            auto v = validate_host(host_str);
            if (v.type == HostType::INVALID) {
                std::cout << "błąd: " << v.error << "\n";
                continue; // wracamy do pętli readline, fork nigdy nie odpala
            }

            PingOptions opts;
            for (size_t i = 2; i < args.size(); i++) {
                if (args[i] == "-c" && i + 1 < args.size()) {
                    opts.count = std::stoi(args[i + 1]);
                    i++;
                }
            }

            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL); // child ginie na Ctrl+C
                run_ping(host_str.c_str(), opts);
                exit(0);
            } else if (pid > 0) {
                ping_pid = pid;
                int status;
                waitpid(pid, &status, 0);
                if (WIFSIGNALED(status) && WTERMSIG(status) != SIGINT && WTERMSIG(status) != SIGTERM)
                    std::cout << "błąd: niepoprawny host\n";
                ping_pid = -1;
                std::cout << "\n";
            } else {
                std::cout << "fork error\n";
            }
        }
        else if (line.substr(0, 4) == "scan") {
            auto args = split(line);

            if (args.size() < 2) {
                std::cout << "użycie: scan <host> [port/zakres/lista] [-t <ms>]\n";
                std::cout << "  przykłady: scan 192.168.1.1\n";
                std::cout << "             scan 192.168.1.1 80\n";
                std::cout << "             scan 192.168.1.1 1-1024\n";
                std::cout << "             scan 192.168.1.1 80,443,53\n";
                std::cout << "             scan 192.168.1.1 1-100 -t 500\n";
                continue;
            }

            std::string host_str = args[1];

            auto v = validate_host(host_str);
            if (v.type == HostType::INVALID) {
                std::cout << "błąd: " << v.error << "\n";
                continue;
            }

            std::string range = "";
            int timeoutMs = 100; // domyślny timeout

            // parsuj opcje
            for (size_t i = 2; i < args.size(); i++) {
                if (args[i] == "-t" && i + 1 < args.size()) {
                    timeoutMs = std::stoi(args[i + 1]);
                    i++;
                } else {
                    range = args[i];
                }
            }

            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL);
                run_scan(host_str, range, timeoutMs);
                exit(0);
            } else if (pid > 0) {
                ping_pid = pid;
                waitpid(pid, nullptr, 0);
                ping_pid = -1;
                std::cout << "\n";
            } else {
                std::cout << "fork error\n";
            }
        }

        else if (line.substr(0, 3) == "ssl") {
            auto args = split(line);
            if (args.size() < 2) {
                std::cout << "użycie: ssl <host> [port]\n";
                continue;
            }
            int port = 443;
            if (args.size() >= 3) {
                try { port = std::stoi(args[2]); }
                catch (...) { std::cout << "błąd: nieprawidłowy port\n"; continue; }
            }
 
            auto v = validate_host(args[1]);
            if (v.type == HostType::INVALID) {
                std::cout << "błąd: " << v.error << "\n";
                continue;
            }
 
            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL);
                run_ssl(args[1], port);
                exit(0);
            } else if (pid > 0) {
                ping_pid = pid;
                waitpid(pid, nullptr, 0);
                ping_pid = -1;
                std::cout << "\n";
            } else {
                std::cout << "fork error\n";
            }
        }

        else if (line.substr(0, 11) == "traceroute ") {
            auto args = split(line);

            if (args.size() < 2) {
                std::cout << "użycie: traceroute <host>\n";
                continue;
            }

            std::string host_str = args[1];
            auto v = validate_host(host_str);
            if (v.type == HostType::INVALID) {
                std::cout << "błąd: " << v.error << "\n";
                continue;
            }

            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL);
                run_traceroute(host_str);
                exit(0);
            } else if (pid > 0) {
                ping_pid = pid;
                waitpid(pid, nullptr, 0);
                ping_pid = -1;
                std::cout << "\n";
            } else {
                std::cout << "fork error\n";
            }
        }
        
        else if (line.substr(0, 3) == "dns") {
            auto args = split(line);
            if (args.size() < 2) {
                std::cout << "użycie: dns <host> [A|AAAA|MX|CNAME|TXT|NS|SOA|PTR]\n";
                std::cout << "  domyślnie: wszystkie rekordy\n";
                continue;
            }
            std::string type = (args.size() >= 3) ? args[2] : "ALL";

            auto v = validate_host(args[1]);
            if (v.type == HostType::INVALID) {
                std::cout << "błąd: " << v.error << "\n";
                continue;
            }

            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL);
                run_dns(args[1], type);
                exit(0);
            } else if (pid > 0) {
                ping_pid = pid;
                waitpid(pid, nullptr, 0);
                ping_pid = -1;
                std::cout << "\n";
            } else {
                std::cout << "fork error\n";
            }
        }
        else if (line == "list network") {
            auto ifaces = iface_list_all();
            std::cout << "\n";
            for (auto& i : ifaces) {
                // ukryj nasze karty z prawdziwą nazwą, pokaż display_name
                if (i.real_name.substr(0, 3) == "nt_") {
                    std::cout << (i.up ? "  UP  " : " DOWN ")
                            << std::left << std::setw(16) << i.display_name
                            << "  [nettools]\n";
                } else {
                    std::cout << (i.up ? "  UP  " : " DOWN ")
                            << i.real_name << "\n";
                }
            }
            std::cout << "\n";
        }

        else if (line.substr(0, 11) == "add network") {
            auto args = split(line);
            if (args.size() < 3) {
                std::cout << "użycie: add network <nazwa>\n";
                continue;
            }
            std::string dname = args[2];

            // kreator
            char* raw;

            raw = readline("  IP (np. 192.168.10.1/24, enter=pomiń): ");
            std::string ip = raw ? std::string(raw) : ""; free(raw);

            raw = readline("  Brama (np. 192.168.10.254, enter=pomiń): ");
            std::string gw = raw ? std::string(raw) : ""; free(raw);

            std::cout << "Tworzę interfejs '" << dname << "'...\n";
            std::string real = iface_create(dname, ip, gw);
            if (real.empty()) {
                std::cout << "Błąd — spróbuj z sudo\n";
            } else {
                own_ifaces[dname] = real;
                current_workspace = dname;
                std::cout << "Gotowe.\n";
            }
        }

        else if (line.substr(0, 4) == "del ") {
            auto args = split(line);
            if (args.size() < 2) {
                std::cout << "użycie: del <nazwa>\n";
                continue;
            }
            std::string dname = args[1];
            std::string real = "";

            // szukaj w mapie sesji
            if (own_ifaces.count(dname)) {
                real = own_ifaces[dname];
            } else {
                // szukaj w systemie po display_name
                for (auto& i : iface_list_own()) {
                    if (i.display_name == dname) {
                        real = i.real_name;
                        break;
                    }
                }
            }

            if (real.empty()) {
                std::cout << "Nie mogę usunąć '" << dname << "' — nie jest moją kartą\n";
            } else if (iface_delete(real)) {
                own_ifaces.erase(dname);
                if (current_workspace == dname) current_workspace = "";
                std::cout << "Usunięto: " << dname << "\n";
            } else {
                std::cout << "Błąd usuwania — spróbuj z sudo\n";
            }
        }
        else if (line == "info") {
            if (current_workspace.empty()) {
                // pokaż wszystkie karty hosta (bez naszych nt_)
                auto ifaces = iface_list_all();
                std::cout << "\n";
                for (auto& i : ifaces) {
                    if (i.real_name.substr(0, 3) == "nt_") continue;
                    auto d = iface_info(i.real_name);
                    std::cout << "  " << std::left << std::setw(12) << i.real_name
                            << (d.up ? " UP  " : " DOWN")
                            << "  IP: "  << std::setw(20) << (d.ip.empty()  ? "brak" : d.ip)
                            << "  MAC: " << (d.mac.empty() ? "brak" : d.mac)
                            << "\n";
                }
                std::cout << "\n";
            } else {
                // info o aktualnym workspace
                std::string real = "";
                if (own_ifaces.count(current_workspace)) {
                    real = own_ifaces[current_workspace];
                } else {
                    for (auto& i : iface_list_own()) {
                        if (i.display_name == current_workspace) {
                            real = i.real_name;
                            break;
                        }
                    }
                    if (real.empty()) real = current_workspace;
                }

                auto d = iface_info(real);
                std::cout << "\n";
                std::cout << "  Nazwa:   " << current_workspace << "\n";
                std::cout << "  Status:  " << (d.up ? "UP" : "DOWN") << "\n";
                std::cout << "  IP:      " << (d.ip.empty()  ? "brak" : d.ip)  << "\n";
                std::cout << "  MAC:     " << (d.mac.empty() ? "brak" : d.mac) << "\n";
                std::cout << "  MTU:     " << d.mtu << "\n";
                std::cout << "\n";
            }
        }
        else if (line.substr(0, 5) == "sniff") {
            auto args = split(line);
            std::string filter = "";
            std::string iface  = current_workspace.empty() ? "" : 
                (own_ifaces.count(current_workspace) ? own_ifaces[current_workspace] : current_workspace);

            for (size_t i = 1; i < args.size(); i++) {
                if (args[i] == "-f" && i + 1 < args.size()) {
                    filter = args[i + 1];
                    i++;
                }
            }

            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL);
                run_sniff(iface, filter);
                exit(0);
            } else if (pid > 0) {
                ping_pid = pid;
                waitpid(pid, nullptr, 0);
                ping_pid = -1;
                std::cout << "\n";
            } else {
                std::cout << "fork error\n";
            }
        }
        else std::cout << "nieznana komenda: " << line << "\n";
    }
    return 0;
}

void run_ping(const char* host, const PingOptions& opts) {
    int seq = 1;

    while (opts.count == 0 || seq <= opts.count) {
        PingResult result = ping(host, opts, seq);

        if (result.success) {
            std::cout << std::setw(3) << seq << " "
                      << result.from_ip << " "
                      << std::max(1.0, std::round(result.rtt_ms)) << " ms "
                      << result.bytes << " bytes\n";
        } else if (result.timeout) {
            std::cout << std::setw(3) << seq << " timeout\n";
        } else {
            std::cout << std::setw(3) << seq << " error: " << result.error << "\n";
        }

        seq++;
        if (opts.count == 0 || seq <= opts.count)
            sleep(1);
    }
}

void run_scan(const std::string& host, const std::string& range, int timeoutMs) {
    std::vector<int> ports;

    if (range.empty()) {
        // domyślny zakres
        for (int i = 1; i <= 1024; i++) ports.push_back(i);

    } else if (range.find(',') != std::string::npos) {
        // lista: "80,443,53" lub "1-4,7" lub "7,8,1-4"
        std::istringstream ss(range);
        std::string token;
        while (std::getline(ss, token, ',')) {
            auto dash = token.find('-');
            if (dash != std::string::npos) {
                int start = std::stoi(token.substr(0, dash));
                int end   = std::stoi(token.substr(dash + 1));
                for (int i = start; i <= end; i++) ports.push_back(i);
            } else {
                ports.push_back(std::stoi(token));
            }
        }

    } else if (range.find('-') != std::string::npos) {
        // zakres: "1-1024"
        std::string r = range;
        r.erase(std::remove(r.begin(), r.end(), ' '), r.end());
        auto dash = r.find('-');
        int start = std::stoi(r.substr(0, dash));
        int end   = std::stoi(r.substr(dash + 1));
        for (int i = start; i <= end; i++) ports.push_back(i);

    } else {
        // pojedynczy port: "80"
        ports.push_back(std::stoi(range));
    }

    std::cout << "Scan Start " << host << " (" << ports.size() << " portów) timeout=" << timeoutMs << "ms\n";

    PortScanOptions opts;
    opts.host      = host;
    opts.timeoutMs = timeoutMs;

    int openCount = 0;
    for (int port : ports) {
        opts.startPort = port;
        opts.endPort   = port;
        auto results = scanPorts(opts);
        for (auto& r : results) {

            static const std::map<int, std::string> services = {
                {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
                {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
                {443, "HTTPS"}, {445, "SMB"}, {135, "RPC"}, {139, "NetBIOS"},
                {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
                {8080, "HTTP-alt"}, {8443, "HTTPS-alt"}, {6379, "Redis"},
                {27017, "MongoDB"}, {5900, "VNC"}
            };

            if (r.open) {
                auto it = services.find(r.port);
                std::string svc = (it != services.end()) ? "  " + it->second : "";
                // ADD UDP LATER
                std::cout << std::setw(5) << r.port << "|tcp" << "  open" << svc << "\n";
                openCount++;
            }
        }
    }

    std::cout << "Gotowe. Otwarte: " << openCount << "/" << ports.size() << "\n";
}

void run_traceroute(const std::string& host) {
    std::cout << "Traceroute to " << host << " max 30 hops:\n";

    TracerouteOptions opts;
    auto results = traceroute(host, opts);

    for (auto& hop : results) {
        std::cout << CLR_GRAY << std::setw(3) << hop.hop << " | " << CLR_RESET;
        if (hop.timeout) {
            std::cout << std::setw(3) << "" << CLR_GRAY << "************" << CLR_RESET << "\n";
        } else {
            int rtt_display = static_cast<int>(std::round(std::max(1.0, hop.rtt_ms)));
            std::cout << std::setw(15) << hop.ip << "  "
                      << CLR_ORANGE << std::setw(2) << rtt_display 
                      << CLR_GRAY << "ms" << CLR_RESET;
            if (hop.reached) std::cout << CLR_GREEN << "  (Target)" << CLR_RESET;
            std::cout << "\n";
        }
    }
}

void run_dns(const std::string& host, const std::string& type) {
    // sprawdź czy to reverse lookup (IP)
    struct in_addr tmp;
    if (inet_pton(AF_INET, host.c_str(), &tmp) == 1) {CLR_YELLOW;
        std::cout << "PTR " << host << " → " << dns_reverse(host) << "\n";
        return;
    }

    std::cout << "DNS lookup: " << host << " [" << type << "]\n\n";

    DnsResult result = dns_lookup(host, type);

    if (!result.success || result.records.empty()) {
        std::cout << "Brak rekordów\n";
        return;
    }

    for (auto& rec : result.records) {
        std::cout << std::left << std::setw(8) << rec.type_str;
        if (rec.type == DnsRecordType::MX)
            std::cout << std::setw(5) << rec.priority << " ";
        std::cout << rec.value
                  << "  (TTL=" << rec.ttl << ")\n";
    }
}

void run_sniff(const std::string& iface, const std::string& filter) {
    SnifferOptions opts;
    opts.iface  = iface;
    opts.filter = filter;
    sniff_start(opts);
}

void run_ssl(const std::string& host, int port) {
    std::cout << "SSL check: " << host << ":" << port << "\n\n";
 
    SslResult r = ssl_check(host, port);
 
    if (!r.success) {
        std::cout << CLR_ERROR << "  Błąd: " << r.error << CLR_RESET << "\n";
        return;
    }
 
    std::cout << "  Podmiot:  " << r.subject    << "\n";
    std::cout << "  Wystawca: " << r.issuer     << "\n";
    std::cout << "  Ważny od: " << r.valid_from << "\n";
    std::cout << "  Ważny do: " << r.valid_to   << "\n";
 
    if (!r.sans.empty()) {
        std::cout << "  SANs:     ";
        for (size_t i = 0; i < r.sans.size(); i++) {
            if (i > 0) std::cout << "            ";
            std::cout << r.sans[i].value << "\n";
        }
    }
 
    std::cout << "  Status:   ";
    if (r.expired) {
        std::cout << CLR_ERROR << "WYGASŁ (" << std::abs(r.days_left) << " dni temu)" << CLR_RESET << "\n";
    } else if (r.days_left <= 14) {
        std::cout << CLR_YELLOW << "wygasa za " << r.days_left << " dni" << CLR_RESET << "\n";
    } else {
        std::cout << CLR_GREEN << "OK (zostało " << r.days_left << " dni)" << CLR_RESET << "\n";
    }
}