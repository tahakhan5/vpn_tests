## Tunnel failure

This tests whether we can pass traffic without the VPN when the VPN fails.

`run_test.py` runs the test. It:
 - Does an IP lookup for each host in hosts.txt
 - Verifies that it can connect to those IPs
 - Blocks all traffic except connctions on port 80 to those IPs
 - Tries periodically to connect to those IPs
 - Considers the test successful if it doesn't manage to connect to any hosts
   after 5 minutes of trying.

We are blocking outbound traffic using `pf`, the BSD firewall/packet filter that
modern Mac OS ships with.

If it can't connect to the majority of hosts on the initial check, or if it
connects to *any* hosts on the second/third checks, it fails. It logs relevant
messages to stderr, and its exit value indicates what happened:
 - 0 means everything worked as expected
 - 1 means you didn't run it as root
 - 2 means you didn't give it valid arguments
 - 3 means that it failed its initial connectivity checks
 - 4+ means that the VPN failed to block

The hosts in `hosts.txt` are the hosts the test attempts to connect to. They
were chosen because they were common webservices, but for our purposes,
literally all we need is for them to respond to standard HTTP requests in
some way (even with an error).

This mostly seems to work, but it's worth noting that while this kills an
openvpn connection successfully, Tunnelblick isn't smart enough to notice that
anything is wrong, and then fails to properly disconnect openvpn. So this test
may be a pain in the butt ot run in practice.
