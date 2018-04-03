
This test mostly collects data to try to infer things about the VPN endpoints.
Among them is geolocation information, but it collects other stuff too.

See Google Doc for description of most of this test's objectives.

INSTALLING
==========

If you've already installed the prerequisites from the parent dir, you
shouldn't need anything else. If you're running this separately,
requirements.txt should be all the python packages. You also need libdnet,
available through homebrew.

BEFORE YOU RUN
==============

These tests make connections to RIPE ATLAS anchors, but these change
periodically. I have no included a list of them in the repository, but have
provided a script that will pull down the current list.

Run `$ ./fetch_ripe_anchors` to get the latest batch. By default is places the
file into `resources`, where `run_tests` expects it.

*You should fetch a new anchors list roughly daily*. Any more frequently than
that is excessive, but they do go stale.

RUNNING
=======

This script requires root privileges when running with scapy.  Otherwise, it can
run as a normal user (see below).

```
    $ sudo -H ./run_tests
```

(You don't NEED the `-H`, but it'll make matplotlib happier.)

This will run the tests and output the results to the `results` folder.

This script has command-line options. Explore them with `./run_tests -h`.


A NOTE ON libdnet / scapy
=========================

libdnet and scapy can be finicky, require root access, and scapy weirdly feels
the need to slowly import matplotlib every time it loads. If you want to skip
the whole headache, you can pass the argument `--skip-scapy` and it skip the TCP
RTT test, and never import scapy at all.
