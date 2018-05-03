#!/usr/bin/env python3
"""Call the script's arguments every hour."""

import subprocess
import sys
import time

from datetime import datetime, timedelta


def main():

    print("== Starting at", datetime.now())
    while True:
        diff = (
            timedelta(hours=1) -
            (datetime.now() -
             datetime.now().replace(minute=0, second=0, microsecond=0)))
        remaining = diff.total_seconds()

        print("== Sleeping for", diff)
        time.sleep(remaining)

        start = datetime.now()
        print("== Calling at", start)
        subprocess.call(sys.argv[1:])
        end = datetime.now()
        diff = end - start
        print("== Done at", end)
        print("== Took", diff)


if __name__ == "__main__":
    sys.exit(main())
