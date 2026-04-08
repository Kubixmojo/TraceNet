#pragma once
#include <string>
#include <map>
#include <vector>

struct IfaceInfo {
    std::string display_name;  // "user name"
    std::string real_name;     // "real name"
    std::string ip;
    bool up;
};

// tworzy kartę dummy, zwraca real_name lub "" jeśli błąd
std::string iface_create(const std::string& display_name,
                          const std::string& ip = "",
                          const std::string& gw = "");

// usuwa kartę (tylko jeśli zaczyna się od "nt_")
bool iface_delete(const std::string& real_name);

// lista wszystkich kart w systemie
std::vector<IfaceInfo> iface_list_all();

// lista tylko kart stworzonych przez nettools (prefix nt_)
std::vector<IfaceInfo> iface_list_own();

struct IfaceDetails {
    std::string name;
    std::string ip;
    std::string mac;
    int mtu;
    bool up;
};

IfaceDetails iface_info(const std::string& real_name);