#!/usr/bin/env python3
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import argparse
import collections
import itertools
import json
import os
import pathlib
import subprocess
import sys
from functools import partial

# mostly for checking the version in automated scripts, similar to sys.version_info
VERSION: tuple[int] = (2, )

DIST_KEY = "DIST"
BUILD_ARG_KEYS = ["PYTHON", "IMAGE_IDENTIFIER"]
BuildArgs = collections.namedtuple('BuildArgs', BUILD_ARG_KEYS)


def add_image_identifier(grouped_args):
    for dist, args in grouped_args:
        for arg in args:
            if "IMAGE_IDENTIFIER" not in arg:
                arg['IMAGE_IDENTIFIER'] = 'autotest'
    return grouped_args


def build_images(matrix, script_args):
    grouped_args = itertools.groupby(matrix, lambda d: d[DIST_KEY])
    add_image_identifier(grouped_args)
    filter_build_args = partial(map,
                                lambda argdict: {arg: val for arg, val in argdict.items() if arg in BUILD_ARG_KEYS})
    make_buildargs = partial(map, lambda argdict: BuildArgs(**argdict))
    distribution_buildargs = {dist: (set(make_buildargs(filter_build_args(args)))) for dist, args in
                              itertools.groupby(sorted(matrix, key=lambda d: d[DIST_KEY]), lambda d: d[DIST_KEY])}
    use_podman = 'USE_PODMAN' in os.environ and os.environ['USE_PODMAN'] == '1'
    images = dict()
    for dist, buildargs_list in distribution_buildargs.items():
        for buildargs in buildargs_list:
            filtered_buildargs = buildargs._asdict()
            del filtered_buildargs['IMAGE_IDENTIFIER']
            buildargs_tags = '-'.join(map(lambda it: str(it[0]).lower() + str(it[1]).lower(),
                                          filtered_buildargs.items()))
            if buildargs_tags:
                buildargs_tags = '-' + buildargs_tags
            image_identifier = buildargs.IMAGE_IDENTIFIER
            if script_args.branch:
                branch = str(script_args.branch).lstrip('refs/heads/')
                if branch.startswith('release-'):
                    image_identifier += '-' + branch.lstrip('release-').lower()
            imagetag = f'rucio-{image_identifier}:{dist.lower()}{buildargs_tags}'
            if script_args.cache_repo:
                imagetag = script_args.cache_repo.lower() + '/' + imagetag
            cache_args = ()
            if script_args.build_no_cache:
                cache_args = ('--no-cache', '--pull-always' if use_podman else '--pull')
            elif script_args.cache_repo:
                args = ('docker', 'pull', imagetag)
                print("Running", " ".join(args), file=sys.stderr, flush=True)
                subprocess.run(args, stdout=sys.stderr, check=False)

            # BuildKit cache arguments
            buildkit_cache_args = ()
            if os.environ.get('BUILDX_CACHE_FROM'):
                buildkit_cache_args += ('--cache-from', os.environ['BUILDX_CACHE_FROM'])
            if os.environ.get('BUILDX_CACHE_TO'):
                buildkit_cache_args += ('--cache-to', os.environ['BUILDX_CACHE_TO'])
            if script_args.cache_repo and not script_args.build_no_cache:
                # Add registry cache as secondary cache source (Optional)
                cache_from_registry = f'type=registry,ref={imagetag}'
                buildkit_cache_args += ('--cache-from', cache_from_registry)

            # add image to output
            images[imagetag] = {DIST_KEY: dist, **buildargs._asdict()}

            if script_args.download_only:
                # skip building
                continue

            args = ()
            env = {"DOCKER_BUILDKIT": "1"}

            # Use docker buildx build (or podman build if USE_PODMAN is set)
            if use_podman:
                docker_cmd = ['podman', 'build']
            else:
                docker_cmd = ['docker', 'buildx', 'build']

            if buildargs.IMAGE_IDENTIFIER == 'integration-test':
                buildfile = pathlib.Path(script_args.buildfiles_dir) / 'alma9.Dockerfile'
                args = (
                    *docker_cmd,
                    *cache_args,
                    *buildkit_cache_args,
                    '--file',
                    str(buildfile),
                    '--tag',
                    imagetag,
                    *itertools.chain(*map(lambda x: ('--build-arg', f'{x[0]}={x[1]}'), filtered_buildargs.items())),
                    f'{script_args.buildfiles_dir}',
                )
            else:
                # build images for autotest or votest
                buildfile = pathlib.Path(script_args.buildfiles_dir) / f'{dist}.Dockerfile'
                args = (
                    *docker_cmd,
                    *cache_args,
                    *buildkit_cache_args,
                    '--file',
                    str(buildfile),
                    '--tag',
                    imagetag,
                    *itertools.chain(*map(lambda x: ('--build-arg', f'{x[0]}={x[1]}'), filtered_buildargs.items())),
                    '.'
                )
            if not args:
                print("Error defining build arguments from", buildargs, file=sys.stderr, flush=True)
                sys.exit(1)
            print("Running", " ".join(args), file=sys.stderr, flush=True)
            subprocess.run(args, stdout=sys.stderr, check=True, env=env)
            print("Finished building image", imagetag, file=sys.stderr, flush=True)

            if script_args.push_cache:
                args = ('docker', 'push', imagetag)
                print("Running", " ".join(args), file=sys.stderr, flush=True)
                subprocess.run(args, stdout=sys.stderr, check=True)

    return images


def build_arguments(parser):
    parser.add_argument('buildfiles_dir', metavar='build directory', type=str, nargs='?', default='.',
                        help='the directory of Dockerfiles')
    parser.add_argument('-n', '--build-no-cache', dest='build_no_cache', action='store_true',
                        help='build images without cache')
    parser.add_argument('-r', '--cache-repo', dest='cache_repo', type=str, default='ghcr.io/rucio/rucio',
                        help='use the following cache repository, like ghcr.io/USER/REPO')
    parser.add_argument('-d', '--download-only', dest='download_only', action='store_true',
                        help='only downloads images from the cache repo and skips building')
    parser.add_argument('-p', '--push-cache', dest='push_cache', action='store_true',
                        help='push the images to the cache repo')
    parser.add_argument('-b', '--branch', dest='branch', type=str, default='master',
                        help='the branch used to build the images from (used for the image name)')


def build_main(matrix, args):
    parser = argparse.ArgumentParser(description='Build images special entry point.')
    build_arguments(parser)
    build_args = parser.parse_args(args)
    return build_images(matrix, build_args)


def output_version():
    print("Rucio tool: build_images.py, copyright 2020 CERN, version", '.'.join(map(str, VERSION)))
    sys.exit(0)


def test_version(given_version: str):
    try:
        parsed_version = tuple(map(int, given_version.split('.')))
    except ValueError:
        print("Cannot parse version:", given_version)
        sys.exit(1)

    if parsed_version <= VERSION:
        sys.exit(0)
    else:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Build images according to the test matrix read from stdin.')
    parser.add_argument('-o', '--output', dest='output', type=str, choices=['list', 'dict'], default='dict',
                        help='the output of this command')
    parser.add_argument('-v', '--version', dest='version', action='store_true',
                        help='returns the version and exits')
    parser.add_argument('--version-test', dest='version_test', type=str, required=False,
                        help='tests if the scripts version is equal or higher than the given version and exits with code 0 if true, 1 otherwise')
    build_group = parser.add_argument_group('build', 'Arguments regarding the building of images')
    build_arguments(build_group)
    script_args = parser.parse_args()

    if script_args.version:
        output_version()
    elif script_args.version_test:
        test_version(str(script_args.version_test))

    matrix = json.load(sys.stdin)
    matrix = (matrix,) if isinstance(matrix, dict) else matrix

    images = build_images(matrix, script_args)

    if script_args.output == 'dict':
        json.dump(images, sys.stdout)
    elif script_args.output == 'list':
        json.dump(list(images.keys()), sys.stdout)


if __name__ == "__main__":
    main()
