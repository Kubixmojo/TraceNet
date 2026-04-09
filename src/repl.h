#pragma once
#include <string>
#include <vector>

class Repl {
public:
    void run();
private:
    std::string prompt = "TraceNet> ";
    std::vector<std::string> split(const std::string& input);
};