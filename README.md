
INSTALLING
==========

You will need to install a few things prior to running. Most of these are
available with `homebrew`.

 - Install Chrome
 - Install Homebrew
 - Install the Java JDK
 - Install libdnet (via homebrew)
 - Install openvpn (via homebrew?)
 - Install python3.6 (via web)
 - Install wireshark (via web)
 - `sudo -H pip3 install virtualenv; mkdir -p vpn_tests; cd vpn_tests; virtualenv venv`
 - The script will install missing python dependencies on first run.

You also need to disable any firewalling on your VM.


RUNNING
=======

 ```
 $ cd vpn_tests
 $ sudo ./run_tests.sh
 ```

