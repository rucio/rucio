"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vitjan Zavrtanik, <vitjan.zavrtanik@gmai.com>, 2017
 - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018

 PY3K COMPATIBLE
Generates files filled with random data.
"""

from __future__ import print_function

import os
import sys


def main():
    """
    Generates the dataset specified in the arguments.
    """
    if len(sys.argv) < 3:
        message = """
        Usage: python generate_dataset.py <dataset_name> <number of files> <size of each file in bytes>
        """
        print(message)
        sys.exit(0)
    dataset_name = sys.argv[1]
    file_number = int(sys.argv[2])
    file_size = int(sys.argv[3])

    if not os.path.exists(dataset_name):
        os.makedirs(dataset_name)

    for i in range(file_number):
        tmp_file = open('./' + dataset_name + '/' + dataset_name + '.file' + str(i), 'w+')
        tmp_file.write(os.urandom(file_size))
        tmp_file.close()


if __name__ == '__main__':
    main()
