#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

import argparse
import sys

from commands import getstatusoutput


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dry-run', action='store_true', default=False, help="Don't do anything, just pretend.")
    main_group = parser.add_mutually_exclusive_group()
    main_group.add_argument("-m", "--major", dest='major', action='store_true', default=False, help='Do a major release')
    main_group.add_argument("-i", "--minor", dest='minor', action='store_true', default=False, help='Do a minor release')
    main_group.add_argument("-p", "--patch", dest='patch', action='store_true', default=True, help='Do a patch release')
    args = parser.parse_args()

    # Semantic Versioning: MAJOR.MINOR.PATCH

    # Get the current version from git
    cmd = 'git describe --abbrev=0 --tags'
    status, current_version = getstatusoutput(cmd)

    # Compute the new version
    current_version = map(int, current_version.split('.'))
    if args.major:
        delta = (1, 0, 0)
    elif args.minor:
        delta = (0, 1, 0)
    elif args.patch:
        delta = (0, 0, 1)
    new_version = [x + y for x, y in zip(current_version, delta)]

    # list to string conversion
    new_version = ".".join(map(str, new_version))
    current_version = ".".join(map(str, current_version))

    answer = query_yes_no("Do you want to release %(new_version)s (current_version: %(current_version)s)?" % locals(), default="no")
    if answer:
        cmd = "git tag -a %(new_version)s -m 'Version %(new_version)s'" % locals()
        print cmd
        # status, output = getstatusoutput(cmd)
        cmd = "git push origin %(new_version)s" % locals()
        print cmd
        # status, output = getstatusoutput(cmd)
