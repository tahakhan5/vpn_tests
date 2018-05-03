"""Kill runaway Chrome processes."""

import logging
import sys
import threading
import time

import psutil

from enum import Enum


CHROME_KILL_AFTER_S = 180


logger = logging.getLogger("killa")


class KillState(Enum):
    ALIVE = 0
    TERMED = 1
    KILLED = 2


class WatchedProc(object):
    proc = None
    first_seen = None
    state = None

    def __init__(self, proc, first_seen, state):
        self.proc = proc
        self.first_seen = first_seen
        self.state = state

    def try_stop(self):
        if self.state == KillState.ALIVE:
            logger.info("TERMing runaway Chrome", self.proc.pid)
            self.proc.terminate()
            self.state = KillState.TERMED
        elif self.state == KillState.TERMED:
            logger.warning("KILLing runaway Chrome", self.proc.pid)
            self.proc.kill()
            self.state = KillState.KILLED
        elif (self.state == KillState.KILLED and self.proc.is_running() and
              self.proc.status() == 'running'):
            logger.error("Couldn't kill Chrome", self.proc.pid)


def _find_chromes():
    chromes = []
    #for proc in psutil.process_iter():  # This finds all instances of Chrome
    for proc in psutil.Process().children(True):  # Only our children
        try:
            if proc.name() == 'Google Chrome':
                chromes.append(proc)
        except psutil.ZombieProcess:
            pass
        except psutil.AccessDenied:
            pass

    return chromes


def _watch_chromes():
    by_pid = {}
    while True:
        cur_chromes = _find_chromes()
        now = time.time()
        for chrome in cur_chromes:
            if chrome.pid in by_pid:
                continue
            by_pid[chrome.pid] = WatchedProc(chrome, now, KillState.ALIVE)
            logger.info("Monitoring new Chrome instance %d", chrome.pid)

        to_rm = []
        for pid, wproc in by_pid.items():
            try:
                if (not wproc.proc.is_running() or
                        wproc.proc.status() == 'zombie'):
                    to_rm.append(wproc.proc.pid)

                elif now - wproc.first_seen > CHROME_KILL_AFTER_S:
                    wproc.try_stop()
            except psutil.NoSuchProcess:
                to_rm.append(wproc.proc.pid)
            except ProcessLookupError:
                to_rm.append(wproc.proc.pid)
            except Exception:
                logger.error("Unexpected exception")

        for pid in to_rm:
            del by_pid[pid]

        time.sleep(2)


def start_chrome_killa():
    thread = threading.Thread(target=_watch_chromes)
    thread.daemon = True
    thread.start()


def main():
    start_chrome_killa()

    from selenium import webdriver
    webdriver.Chrome(
        "/Users/vpn_test/vpn_tests/manipulation_tests/"
        "redirection_dom/chromedriver")

    time.sleep(200)


if __name__ == "__main__":
    sys.exit(main())
