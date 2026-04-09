#include <iostream>
#include <sstream>
#include <algorithm>
#include <csignal>
#include <sys/types.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <cstring>

#include "repl.h"
#include "colors.h" //colors
#include "cli/cmd_ping.h"
#include "cli/cmd_dns.h"
#include "cli/cmd_traceroute.h"

extern pid_t active_pid;

static void sigint_handler(int) {
    if (active_pid > 0) {
        kill(active_pid, SIGINT);
        active_pid = -1;
    }
}

std::vector<std::string> Repl::split(const std::string& input) {
    std::istringstream iss(input);
    std::vector<std::string> tokens;
    std::string word;
    while (iss >> word)
        tokens.push_back(word);
    return tokens;
}

//Tab
static const char* commands[] = {
    "ping", "scan", "traceroute", "dns", "ssl", "sniff", "help", "exit", nullptr   // for later make it work with big leathers too
};

static char* command_completer(const char* text, int state) {
    static int idx;
    if (state == 0) idx = 0;
    while (commands[idx]) {
        const char* cmd = commands[idx++];
        if (strncmp(cmd, text, strlen(text)) == 0)
            return strdup(cmd);
    }
    return nullptr;
}

void Repl::run() {
    signal(SIGINT,  sigint_handler);
    signal(SIGTSTP, sigint_handler);

    rl_attempted_completion_function = nullptr;
    rl_completion_entry_function = command_completer;

    std::cout << CLR_CYAN << CLR_BOLD << "TraceNet v0.1" << CLR_RESET << "\n";
    std::cout << CLR_GRAY << "Write 'help' or 'exit'\n" << CLR_RESET;

    while (true) {
        char* raw = readline(prompt.c_str());
        if (!raw) break;

        std::string line(raw);
        free(raw);
        if (line.empty()) continue;
        add_history(line.c_str());

        auto args = split(line);
        if (args.empty()) continue;    // fix for space crash 
        std::transform(args[0].begin(), args[0].end(), args[0].begin(), ::tolower);

        // Comands
        if (args[0] == "ping") {
            cmd_ping(args);
        } else if (args[0] == "scan") {

        } else if (args[0] == "traceroute") {
            cmd_traceroute(args);
        } else if (args[0] == "dns") {
            cmd_dns(args);
        } else if (args[0] == "ssl") {           // do not use big leathers here
            // ssl
        } else if (args[0] == "sniff") {
            // sniff
        } else if (args[0] == "help") {
            // help meeeee...
        }
        // CLI
        else if (args[0] == "exit") {
            break;
        } else {
            std::cout << CLR_ERROR << "Unknown command: " << args[0] << CLR_RESET << "\n";
        }
    }
}