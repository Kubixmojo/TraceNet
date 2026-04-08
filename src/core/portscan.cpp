#include "portscan.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <cstring>
#include <thread>
#include <algorithm>
#include <mutex>

std::vector<PortResult> scanPorts(const PortScanOptions& opts) {
    std::vector<PortResult> results;
    std::mutex mtx;

    int totalPorts = opts.endPort - opts.startPort + 1;
    int numThreads = std::min(100, totalPorts); // max 100 wątków
    
    std::vector<std::thread> threads;
    
    // każdy wątek dostaje swój kawałek portów
    int chunk = totalPorts / numThreads;

    for (int t = 0; t < numThreads; t++) {
        int from = opts.startPort + t * chunk;
        int to   = (t == numThreads - 1) ? opts.endPort : from + chunk - 1;

        threads.emplace_back([&, from, to]() {
            // resolwuj host (każdy wątek osobno)
            struct hostent* he = gethostbyname(opts.host.c_str());
            if (!he) return;

            struct in_addr addr;
            memcpy(&addr, he->h_addr_list[0], sizeof(struct in_addr));

            for (int port = from; port <= to; port++) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;

                struct timeval tv;
                tv.tv_sec  = opts.timeoutMs / 1000;
                tv.tv_usec = (opts.timeoutMs % 1000) * 1000;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                struct sockaddr_in target{};
                target.sin_family = AF_INET;
                target.sin_port   = htons(port);
                target.sin_addr   = addr;

                bool open = (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0);
                close(sock);

                std::lock_guard<std::mutex> lock(mtx);
                results.push_back({port, open});
            }
        });
    }

    for (auto& t : threads) t.join();

    // sortuj po numerze portu bo wątki mieszają kolejność
    std::sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b) {
        return a.port < b.port;
    });

    return results;
}