
import argparse
import logging
import glob
import os.path
import subprocess

import openvpn


logger = logging.getLogger("vpn_loop")

LOG_FORMAT = (
    "%(asctime)s %(levelname)-7s %(name)-12s %(funcName)-14s %(message)s")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--logfile',
                        help="Logfile to log to")
    parser.add_argument('-p', '--openvpn_path', default='openvpn',
                        help="Path to OpenVPN")
    parser.add_argument('-c', '--crt_file',
                        help="Certificate file.")
    parser.add_argument('-a', '--auth_file',
                        help="File containing \"username\\npassword\"")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Less verbose logging.")
    parser.add_argument(
        'vpn_name', help="Name of VPN.")
    parser.add_argument(
        'indir', help="Directory containing configuration files (.ovpn).")
    parser.add_argument(
        'script',
        help="Path to script to run on each. Passed {vpn} and {endpoint}.")
    parser.add_argument(
        'post_script', nargs='?',
        help="Path to script to run AFTER each endpoint. Same args as script.")
    return parser.parse_args()


def setup_logging(verbose, logfile=None):
    root_logger = logging.getLogger()
    formatter = logging.Formatter(LOG_FORMAT)
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    root_logger.addHandler(streamhandler)

    if logfile:
        filehandler = logging.FileHandler(logfile)
        filehandler.setFormatter(formatter)
        root_logger.addHandler(filehandler)

    root_logger.setLevel(logging.INFO if verbose else logging.WARNING)


def main():
    args = get_args()

    setup_logging(not args.quiet, args.logfile)

    vpn_name = args.vpn_name.replace(" ", "_")

    crt_file = os.path.abspath(args.crt_file)
    auth_file = os.path.abspath(args.auth_file)

    config_path = os.path.dirname(args.crt_file)

    script_path = os.path.abspath(args.script)
    postscript_path = os.path.abspath(
        args.post_script) if args.post_script else None

    for config_file in glob.glob(os.path.join(args.indir, "*.ovpn")):
        config_name = os.path.basename(config_file)[:-5].replace(" ", "_")
        config_file = os.path.abspath(config_file)

        vpn = openvpn.OpenVPN(timeout=60, auth_file=auth_file,
                              config_file=config_file, crt_file=crt_file,
                              path=args.openvpn_path, cwd=config_path)
        logger.info("Processing config: %s", config_file)
        vpn.start()

        if not vpn.started:
            vpn.stop()
            logger.error("Failed to start VPN %s", config_file)
            continue

        # Do other stuff
        logger.info("Calling script.")
        result = subprocess.call([script_path, vpn_name, config_name])
        logger.info("Returned from script.")

        if result:
            logger.error("Result failed on endpoint %s with status %d",
                         config_name, result)

        vpn.stop()
        logger.debug("VPN stopped!")

        if postscript_path:
            logger.info("Calling post-script.")
            result = subprocess.call([postscript_path, vpn_name, config_name])
            logger.info("Returned from post-script.")

            if result:
                logger.error("Result failed on postscript call %s w/%d",
                             config_name, result)


if __name__ == "__main__":
    main()
