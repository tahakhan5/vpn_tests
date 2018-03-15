
# IPv6 Leakage Test

This is a simple test to check for IPv6 leakage.

It connects to several pre-resolved domains while capturing traffic from the
primary interface. If it captures its own traffic, we're leaking IPv6.

The resolutions are stored in `v6_resolutions.csv`. These will probably work for
a while, but sooner or later they'll start causing errors. You can update them
with `refresh_resolutions.sh`, so I guess run that occasionally.

*READ THE HEADER OF ipv6_leak.py FOR IMPORTANT INFORMATION.*

