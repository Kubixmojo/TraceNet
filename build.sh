#!/bin/bash
cd "$(dirname "$0")"
mkdir -p build && cd build
cmake .. && make -j$(nproc)
sudo setcap cap_net_raw+ep ./TraceNet
./TraceNet