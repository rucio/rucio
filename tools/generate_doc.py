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

import itertools
import os
import pathlib
import re
import sys
from collections import namedtuple
from typing import TextIO

import sh

ANCHOR_PATTERN = re.compile(r"<a[^>]*>[^<]*</a>")


class CommandErrorWrapper:
    def __init__(self, procs: list[sh.RunningCommand]):
        self.procs = procs

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(exc_val, sh.ErrorReturnCode):
            print(
                "Error running:",
                exc_val.full_cmd,
                "\nExit Code:",
                exc_val.exit_code,
                file=sys.stderr
            )
            print(
                "  STDOUT:\n",
                exc_val.stdout.decode(errors='replace'),
                "\n",
                file=sys.stderr
            )
            print(
                "  STDERR:\n",
                exc_val.stderr.decode(errors='replace'),
                "\n",
                file=sys.stderr
            )
            for proc in self.procs:
                try:
                    proc.process.terminate()
                except ProcessLookupError:
                    pass
            sys.exit(1)


def escape_doc_line(line: str):
    # there are anchor lines produced by the table of contents option, ignore these
    if ANCHOR_PATTERN.match(line):
        return line
    else:
        return line.replace('<', r'\<').replace('>', r'\>')


def render_pydoc_markdown(rucio_src: str):
    RenderParams = namedtuple("RenderParams", ["title", "fh", "args", "out_file"])

    def render_done(par: RenderParams):
        def inner(cmd, success, exit_code):
            if success:
                print(f"{par.title} doc was generated to {par.out_file}")
            else:
                print(f"Error running {cmd}\n  exit code: {exit_code}")

        return inner

    def print_line(par: RenderParams):
        def inner(line: str):
            print(escape_doc_line(line), end="", file=par.fh)

        return inner

    def render(params: list[RenderParams]):
        python = sys.executable
        if not python:
            python = "python3"

        python = sh.Command(python)
        procs = []
        for par in params:
            print("Adding header for", par.title)
            print("---", file=par.fh)
            print("title:", par.title, file=par.fh)
            print("---", file=par.fh)
            print(file=par.fh)
            print("Rendering", par.title)
            procs.append(
                python(
                    "-m",
                    "pydoc_markdown.main",
                    *par.args,
                    "--render-toc",
                    _out=print_line(par),
                    _bg=True,
                    _done=render_done(par),
                )
            )

        for handle in procs:
            with CommandErrorWrapper(procs):
                handle.wait(timeout=60)

    def create_parent_directory(file: str):
        directory = os.path.dirname(file)
        if directory:
            try:
                os.mkdir(directory, mode=0o755)
            except FileExistsError:
                pass  # ignore existing

    client_module_path = pathlib.Path(os.path.join(rucio_src, "rucio-cli-client"))
    client_module_excludes = {"__pycache__", "__init__", "dq2client"}
    client_modules = [
        module_path.with_suffix("").name
        for module_path in client_module_path.iterdir()
        if module_path.with_suffix("").name not in client_module_excludes
    ]
    client_modules_args = list(itertools.chain(*(("--module", "rucio.client." + mod) for mod in client_modules)))
    client_api_output_file = os.environ.get("RUCIO_CLIENT_API_OUTPUT", default="docs/rucio_client_api.md")
    create_parent_directory(client_api_output_file)

    client_module_path = pathlib.Path(os.path.join(rucio_src, "rucio-api/src/rucio/api/flaskapi/v1/"))
    rest_api_output_file = os.environ.get("RUCIO_REST_API_OUTPUT", default="docs/rucio_rest_api.md")
    create_parent_directory(rest_api_output_file)

    with open(client_api_output_file, "w") as client_api_fh, open(rest_api_output_file, "w") as rest_api_fh:
        render(
            [
                RenderParams(
                    title="Rucio client API",
                    fh=client_api_fh,
                    args=("--search-path", rucio_src, *client_modules_args),
                    out_file=client_api_output_file,
                ),
                RenderParams(
                    title="Rucio REST API",
                    fh=rest_api_fh,
                    args=("--search-path", rucio_src),
                    out_file=rest_api_output_file,
                ),
            ]
        )


def render_bin_help_pages(rucio_src: str):
    out_files: dict[pathlib.Path, str] = {}
    file_handles: dict[pathlib.Path, TextIO] = {}

    def render_done(par: pathlib.Path):
        def inner(cmd, success, exit_code):
            if success:
                print("```", file=file_handles[par])
                print(f"{par} doc was generated to {out_files[par]}")
            else:
                print(f"Error running{cmd}\n  exit code: {exit_code}")

        return inner

    def print_line(par: pathlib.Path):
        def inner(line):
            print(line, end="", file=file_handles[par])

        return inner

    bin_path = pathlib.Path(rucio_src) / "rucio-cli-client"
    bin_help_output_path = os.environ.get("RUCIO_BIN_HELP_OUTPUT", default="docs/bin")
    bin_help_output_path = pathlib.Path(bin_help_output_path)
    bin_help_output_path.mkdir(parents=True, exist_ok=True)
    excludes = {}
    os.environ["PYTHONPATH"] = rucio_src

    def generate_procs():
        for runnable_path in bin_path.iterdir():
            if runnable_path.name not in excludes:
                out_file = str((bin_help_output_path / runnable_path.name).with_suffix(".md"))
                file_handles[runnable_path] = open(out_file, 'w')
                print("Adding header for", runnable_path.name)
                print("---", file=file_handles[runnable_path])
                print("title: Running", runnable_path.name, file=file_handles[runnable_path])
                print("---", file=file_handles[runnable_path])
                print(file=file_handles[runnable_path])
                print("```", file=file_handles[runnable_path])
                out_files[runnable_path] = out_file
                runnable = sh.Command(str(runnable_path))
                yield runnable("--help", _out=print_line(runnable_path), _bg=True, _done=render_done(runnable_path))

    procgen = generate_procs()
    procs = []
    parallel_jobs = 2
    for idx in range(parallel_jobs):
        proc = next(procgen, None)
        if proc is not None:
            procs.append(proc)

    try:
        while len(procs) > 0:
            with CommandErrorWrapper(procs):
                procs.pop(0).wait(timeout=10)
            proc = next(procgen, None)
            if proc is not None:
                procs.append(proc)
    finally:
        for fhandle in file_handles.values():
            fhandle.close()


def main():
    rucio_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    render_pydoc_markdown(rucio_src)
    render_bin_help_pages(rucio_src)


if __name__ == "__main__":
    main()
