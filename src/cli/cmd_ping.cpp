#include "cmd_ping.h"
#include "../core/ping.h"
#include "../core/validate.h"
#include <iostream>
#include <cmath>
#include <iomanip>
#include <csignal>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cli/cmd_ping.h"

extern pid_t active_pid;

static void run_ping(const char* host, const PingOptions& opts) {
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

void cmd_ping(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "użycie: ping <host> [-c <n>]\n";
        return;
    }

    auto v = validate_host(args[1]);
    if (v.type == HostType::INVALID) {
        std::cout << "błąd: " << v.error << "\n";
        return;
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
        signal(SIGINT, SIG_DFL);
        run_ping(args[1].c_str(), opts);
        exit(0);
    } else if (pid > 0) {
        active_pid = pid;
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) != SIGINT && WTERMSIG(status) != SIGTERM)
            std::cout << "błąd: niepoprawny host\n";
        active_pid = -1;
        std::cout << "\n";
    } else {
        std::cout << "fork error\n";
    }
}