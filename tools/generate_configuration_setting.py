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
import os
import re
from glob import glob

from rucio.common.config_settings import Config
from rucio.common.types import ConfigOption


def get_source_files() -> list[str]:
    """Find all the files used in the source code."""
    dir = "./lib/rucio/"
    return [y for x in os.walk(dir) for y in glob(os.path.join(x[0], '*.py'))]


def load_file(file_path: str) -> str:
    """Find all config get calls in code"""
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def write_to_markdown(save_loc: str) -> None:
    """Write the json config into markdown """
    # Format:
    # #### section
    # - **key**: _type_ doc. Default: `default`.`

    file = ""
    for name, attr in Config.__dict__.items():
        if name.startswith("__"):
            continue
        file += f"\n#### {name}\n"
        for name, section in attr.__dict__.items():
            if not isinstance(section, ConfigOption):
                continue

            key = section.name
            _type = section.type_.__name__
            doc = section.docstring
            default = section.default
            if default is None:
                default = "No Default"

            file += f"- **{key}**: _{_type}_ {doc}. Default: `{default}`.\n"

    if not save_loc.endswith(".mdx"):
        save_loc += ".mdx"

    with open(save_loc, "w") as f:
        f.write(file)
        f.close()


def count_doc_lines() -> float:
    """
    Counts the number of parameters with docstrings - returns a ratio of the number of parameters with docstrings to the total number of parameters
    Note: This is a rough estimate that does not include things like import statements or duplicates of the came config parameter call.
    """

    total = 0
    files = get_source_files()
    for file in files:
        pattern = r'\bconfig_get(?:_\w+)?\s*\('
        total += len(re.findall(pattern, load_file(file)))

    count = 0
    for name, attr in Config.__dict__.items():
        if name.startswith("__"):
            continue
        for name, section in attr.__dict__.items():
            if isinstance(section, ConfigOption):
                count += 1

    return count / total


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o", "--output",
        help="Output file name",
        type=str,
        default="rucio_config_defaults.md"
    )

    parser.add_argument(
        "--markdown",
        help="Output markdown",
        action="store_true",
    )

    parser.add_argument(
        "--count",
        help="Count the number of parameters with docstrings",
        action="store_true",
    )

    return parser


if __name__ == "__main__":
    args = arguments().parse_args()

    if args.count:
        print(count_doc_lines())

    if args.markdown:
        write_to_markdown(args.output)
