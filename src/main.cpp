#include "repl.h"
#include <csignal>

#include "cli/cmd_ping.h"

pid_t active_pid = -1;

static void sigint_handler(int) {
    if (active_pid > 0) {
        kill(active_pid, SIGINT);
        active_pid = -1;
    }
}

static void setup_signals() {
    signal(SIGINT,  sigint_handler);
    signal(SIGTSTP, sigint_handler);
}

int main() {
    setup_signals();
    Repl repl;
    repl.run();
}