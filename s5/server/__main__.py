"""
    The module called by `python -m s5.server`
    parses arguments and controls an S5Server
"""


import signal
import os
import sys
import logging
import time
from pathlib import Path
SERVER_VERSION_STRING = 'S5 Server 1.0.0'


from . import server

from ..shared import utilcrypto
from ..shared import crypto


def main(argv):
    if argv is None:
        o = parseArgs()
    else:
        o = parseArgs(argv)

    data_dir = o.data
    pid_file = data_dir / 'pid'

    s=server.S5Server(data_dir)


    if o.action == 'init':
        # Initialize the server in a new Data Directory
        s.initializeNew()

    elif o.action == 'serve':
        # serve clients
        s.setup(o.address, o.port, o.ipv6)
        a=s.getAddress()
        print("Starting Server at %r, dir %s" % (a, s.dataPath))

        # Store process ID for 'kill' cmd
        with pid_file.open("wt") as f:
            f.write(str(os.getpid()))

        # Start a Server Thread
        s.serveInThread()

        # Wait for the Interrupt
        try:
            while True:
                time.sleep(100)
        except KeyboardInterrupt:
            pass

        print("\n\nReceived Interupt, shuting down")
        s.close()
        pid_file.unlink()

    elif o.action == 'kill':
        # stop another process that serves clients
        try:
            with pid_file.open("rt") as f:
                pid=int(f.read().strip())
        except FileNotFoundError:
            print("No running process found")
        else:
            os.kill(pid, signal.SIGINT)

    elif o.action == 'token':
        # Create an account for a user and print the token that the client can
        # claim it with
        t=s.createToken(o.user)
        print("Created Token %s for user %s" % (t, o.user))

    elif o.action == 'fingerprint':
        # print fingerprints of the server key with various hash methods
        k=s.publicKey
        if o.hash is not None:
            f=utilcrypto.getFingerprintFromAsymmetricKey(k, o.hash)
            print(o.hash, f)
        else:
            for h in sorted(crypto.Algorithms.hashAlgos):
                f=utilcrypto.getFingerprintFromAsymmetricKey(k, h)
                print(h, f)
    else:
        raise ValueError(o.action)


def parseArgs(*args):
    import argparse
    p=argparse.ArgumentParser(
        description="Start the S5 Server",
        epilog="Find help at <http:// (S5 has no website yet)>",  # TODO: Website
        add_help=True
    )
    p.add_argument(
        '-v',
        '--version',
        help='print version and exit',
        action='version',
        version=SERVER_VERSION_STRING)

    p.add_argument(
        '--data',
        help='Where Server Data is stored',
        required=True,
        type=Path)

    sp = p.add_subparsers(dest='action')
    sp.required = True
    spi = sp.add_parser('init')
    sps = sp.add_parser('serve')
    sps.add_argument('--address', help='Listen only on this Interface')
    sps.add_argument('--port', help='Listen on this Port', type=int)
    sps.add_argument('--ipv6', help='Use IPv6', action='store_true')

    sps = sp.add_parser('token', help="Create a token for a user, so "
            "he can become a registered user" )
    sps.add_argument('user', help='The email of the user')

    sps = sp.add_parser('fingerprint', help="Print the fingerprint of the "
            "server key using a specified, or all known hash methods" )
    sps.add_argument('hash', help='The hash method to use (default: all)',
            nargs='?')

    sps = sp.add_parser('kill', help="Stop the Server" )

    if len(args) == 0:
        args = None

    return p.parse_args(args)

if __name__ == '__main__':
    main(None)
