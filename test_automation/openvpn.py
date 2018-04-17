#!/usr/bin/python
# openvpn.py: library to handle starting and stopping openvpn instances

import logging
import subprocess
import sys
import threading
import time


logger = logging.getLogger("openvpn")


class OpenVPN(object):
    def __init__(self,
                 config_file=None, auth_file=None, crt_file=None, timeout=60,
                 path='openvpn', cwd=None):
        self.started = False
        self.stopped = False
        self.error = False
        self.path = path
        self.notifications = ""
        self.auth_file = auth_file
        self.crt_file = crt_file
        self.config_file = config_file
        self.thread = threading.Thread(target=self._invoke_openvpn)
        self.thread.setDaemon(1)
        self.timeout = timeout
        self.cwd = cwd

    def _invoke_openvpn(self):
        if self.auth_file is None:
            cmd = ['sudo', self.path, '--script-security', '2',
                   '--config', self.config_file]
        elif self.crt_file is None:
            cmd = ['sudo', self.path, '--script-security', '2',
                   '--config', self.config_file,
                   '--auth-user-pass', self.auth_file]
        else:
            cmd = ['sudo', self.path, '--script-security', '2',
                   '--config', self.config_file,
                   '--auth-user-pass', self.auth_file,
                   '--ca', self.crt_file]
        self.process = subprocess.Popen(cmd,
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        cwd=self.cwd)
        self.kill_switch = self.process.terminate
        self.starting = True
        while True:
            line = self.process.stdout.readline().strip()
            if not line:
                break
            self.output_callback(line, self.process.terminate)

    def output_callback(self, line, kill_switch):
        """Set status of openvpn according to what we process"""
        line = line.decode('utf-8')

        self.notifications += line + "\n"

        if "Initialization Sequence Completed" in line:
            self.started = True
        if "ERROR:" in line or "Cannot resolve host address:" in line:
            self.error = True
        if "process exiting" in line:
            self.stopped = True

    def start(self, timeout=None):
        """Start openvpn and block until the connection is opened or there is
        an error

        """
        if not timeout:
            timeout = self.timeout
        self.thread.start()
        start_time = time.time()
        while start_time + timeout > time.time():
            self.thread.join(1)
            if self.error or self.started:
                break
        if self.started:
            logging.debug("openvpn started")
        else:
            logging.error("openvpn not started")
            sys.stderr.write(self.notifications)
            sys.stderr.write("\n")

    def stop(self, timeout=None):
        """Stop openvpn"""
        if not timeout:
            timeout = self.timeout
        self.kill_switch()
        self.thread.join(timeout)
        if self.stopped:
            logger.debug("stopped")
        else:
            logger.error("not stopped")
            sys.stderr.write(self.notifications)
            sys.stderr.write("\n")
