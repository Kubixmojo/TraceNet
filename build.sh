#!/bin/bash
PREV=$(pwd)
cd ~/Dokumenty/Net_Tools/Tracert/build
cmake .. && make -j$(nproc) && sudo setcap cap_net_raw+ep ./TraceNet && ./TraceNet
cd "$PREV"