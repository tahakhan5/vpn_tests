#!/usr/bin/env python3
"""Call the script's arguments periodically (see TRIGGER_TIMES)."""

import subprocess
import sys
import time

from datetime import datetime, timedelta
from datetime import time as dttime

# Run the arguments every time we hit one of these times.
# Keep this in sorted order...
TRIGGER_TIMES = [dttime(hour=0, minute=13), dttime(hour=6, minute=10),
                 dttime(hour=11, minute=51), dttime(hour=17, minute=49)]

ONEDAY = timedelta(days=1)


def find_sleep_info():
    now = datetime.now()

    dts = [datetime.combine(now.date(), t) for t in TRIGGER_TIMES]
    dts.append(datetime.combine((now + ONEDAY).date(), TRIGGER_TIMES[0]))

    sleep_until = None
    sleep_for = None
    for dt in dts:
        diff = (dt - now).total_seconds()
        if diff > 0:
            sleep_until = dt
            sleep_for = diff
            break
    return (sleep_until, sleep_for)


def main():

    print("== Starting at", datetime.now())
    while True:
        sleep_until, sleep_for = find_sleep_info()

        print("== Sleeping until", sleep_until,
              "(aka for", sleep_for, "seconds)")
        time.sleep(sleep_for)

        start = datetime.now()
        print("== Calling at", start)
        subprocess.call(sys.argv[1:])
        end = datetime.now()
        diff = end - start
        print("== Done at", end)
        print("== Took", diff)


if __name__ == "__main__":
    sys.exit(main())
