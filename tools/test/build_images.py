#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 CERN
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import argparse
import collections
import itertools
import json
import os
import pathlib
import subprocess
import sys
from functools import partial

DIST_KEY = "DIST"
BUILD_ARG_KEYS = ["PYTHON"]
BuildArgs = collections.namedtuple('BuildArgs', BUILD_ARG_KEYS)


def main():
    matrix = json.load(sys.stdin)
    matrix = (matrix,) if isinstance(matrix, dict) else matrix

    parser = argparse.ArgumentParser(description='Build images according to the test matrix read from stdin.')
    parser.add_argument('buildfiles_dir', metavar='build directory', type=str, default='.',
                        help='the directory of Dockerfiles')
    parser.add_argument('-o', '--output', dest='output', type=str, choices=['list', 'dict'], default='dict',
                        help='the output of this command')
    parser.add_argument('-n', '--build-no-cache', dest='build_no_cache', action='store_true',
                        help='build images without cache')
    parser.add_argument('-r', '--cache-repo', dest='cache_repo', type=str, default='docker.pkg.github.com/rucio/rucio',
                        help='use the following cache repository, like docker.pkg.github.com/USER/REPO')
    parser.add_argument('-p', '--push-cache', dest='push_cache', action='store_true',
                        help='push the images to the cache repo')
    script_args = parser.parse_args()

    filter_build_args = partial(map,
                                lambda argdict: {arg: val for arg, val in argdict.items() if arg in BUILD_ARG_KEYS})
    make_buildargs = partial(map, lambda argdict: BuildArgs(**argdict))
    distribution_buildargs = {dist: set(make_buildargs(filter_build_args(args))) for dist, args in
                              itertools.groupby(matrix, lambda d: d[DIST_KEY])}
    use_podman = 'USE_PODMAN' in os.environ and os.environ['USE_PODMAN'] == '1'

    images = dict()
    for dist, buildargs_list in distribution_buildargs.items():
        for buildargs in buildargs_list:
            buildargs_tags = '-'.join(map(lambda it: str(it[0]).lower() + str(it[1]).lower(),
                                          buildargs._asdict().items()))
            if buildargs_tags:
                buildargs_tags = '-' + buildargs_tags
            imagetag = f'rucio-autotest:{dist.lower()}{buildargs_tags}'
            if script_args.cache_repo:
                imagetag = script_args.cache_repo.lower() + '/' + imagetag

            cache_args = ()
            if script_args.build_no_cache:
                cache_args = ('--no-cache', '--pull-always' if use_podman else '--pull')
            elif script_args.cache_repo:
                args = ('docker', 'pull', imagetag)
                print("Running", " ".join(args), file=sys.stderr)
                subprocess.run(args, stdout=sys.stderr, check=False)
                cache_args = ('--cache-from', imagetag)

            buildfile = pathlib.Path(script_args.buildfiles_dir) / f'{dist}.Dockerfile'
            args = ('docker', 'build', *cache_args, '--file', str(buildfile), '--tag', imagetag,
                    *itertools.chain(*map(lambda x: ('--build-arg', f'{x[0]}={x[1]}'), buildargs._asdict().items())),
                    '.')
            print("Running", " ".join(args), file=sys.stderr)
            subprocess.run(args, stdout=sys.stderr, check=True)
            print("Finished building image", imagetag, file=sys.stderr)

            if script_args.push_cache:
                args = ('docker', 'push', imagetag)
                print("Running", " ".join(args), file=sys.stderr)
                subprocess.run(args, stdout=sys.stderr, check=True)

            images[imagetag] = {DIST_KEY: dist, **buildargs._asdict()}

    if script_args.output == 'dict':
        json.dump(images, sys.stdout)
    elif script_args.output == 'list':
        json.dump(list(images.keys()), sys.stdout)


if __name__ == "__main__":
    main()
