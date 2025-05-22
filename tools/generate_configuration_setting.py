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
import json
import os
import re
from glob import glob
from typing import Literal, Optional


def get_source_files() -> list[str]:
    """Find all the files used in the source code."""
    dir = "./lib/rucio/"
    return [y for x in os.walk(dir) for y in glob(os.path.join(x[0], '*.py'))]


def load_file(file_path: str) -> str:
    """Find all config get calls in code"""
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def get_config_lines_with_defaults(file_content) -> list[dict[Literal['section', 'key', 'type', 'default', "doc"], str]]:
    """Reads a file and returns all config_get calls with their section, key, type, and default, (if any)"""

    defaults = []
    config_pattern = r'(?:[\w\.]*config_get(?:_\w+)?)\s*\((.*?)\)(?:\s*#\s*doc:\s*(.*))?$'
    config_pattern = re.compile(config_pattern, re.MULTILINE)
    matches = re.finditer(config_pattern, file_content)

    for match in matches:
        line = match.group(0)
        args = match.group(1).replace(")", "").replace("(", "").split(",")
        doc = match.group(2)

        # Skip if this is in an import statement
        if 'import' in line and 'from' in line:
            continue

        if 'config_get_' in line:
            dtype = line.split('config_get_')[1].split('(')[0]
        else:
            dtype = None

        def clean_string(string: str) -> str:
            """Cleans up the string by removing quotes and whitespace"""
            return string.strip().strip("'").strip('"')

        section = None
        key = None
        default = None

        # Check if the args are specified with "="
        for arg in args:
            if "=" in arg:
                # kwargs we care about - section: str, option: str, default: _T
                kwargs = arg.split("=")
                if len(kwargs) == 2:
                    name = kwargs[0].strip()
                    value = clean_string(kwargs[1])
                    if name == "section":
                        section = value
                    elif name == "option":
                        key = value
                    elif name == "default":
                        default = value

        # If not specified with "=", then the first two args are section and key

        section = clean_string(args[0]) if section is None else section
        key = clean_string(args[1]) if key is None else key

        if (len(args) > 3) and (default is None):
            # args order is section, key, raise error, default
            default = clean_string(args[3])

        if doc is not None:
            doc = doc.rstrip('.')  # Remove trailing period, so we can add it again in MD.

        defaults.append(
            {
                "section": section,
                "key": key,
                "type": dtype,
                "default": default,
                "doc": doc
            }
        )

    return defaults


def write_to_markdown(json_config: dict, save_loc: str) -> None:
    """Write the json config into markdown """
    # Format:
    # #### section
    # - **key**: _type_ doc. Default: `default`.`
    if not save_loc.endswith(".mdx"):
        save_loc += ".mdx"

    with open(save_loc, "w") as file:
        for section, items in json_config.items():
            file.write(f"#### {section}\n")

            for key, descriptor in items.items():
                line = f"- **{key}**: "
                if descriptor['type']:
                    line += f"_{descriptor['type']}_ "
                if descriptor["doc"]:
                    line += f"{descriptor['doc']}. "

                if descriptor["default"]:
                    line += f"Default: `{descriptor['default']}`."
                else:
                    line += "No Default."
                file.write(line + "\n")

            file.write("\n")


def make_json_config(config_defaults: list[dict[Literal['section', 'key', 'type', 'default', "doc"], str]], save_loc: Optional[str] = None) -> dict:
    """
    Takes the list of parameters and transforms them into a config matching rucio.cfg

    Takes the most complete version of the args
    """
    json_config = {}
    sections = set(s['section'] for s in config_defaults)

    for section in sections:
        json_config[section] = {}
        items = [item for item in config_defaults if item['section'] == section]
        for item in items:
            key = item['key']
            if key in json_config[section]:
                # If the key already exists, take the most complete version
                existing_item = json_config[section][key]
                if item['type'] and not existing_item['type']:
                    json_config[section][key]['type'] = item['type']
                if item['default'] and not existing_item['default']:
                    json_config[section][key]['default'] = item['default']
                if item['doc'] and not existing_item['doc']:
                    json_config[section][key]['doc'] = item['doc']

            else:
                json_config[section][key] = {
                    "type": item['type'],
                    "default": item['default'],
                    "doc": item['doc']
                }
    if save_loc:
        if not save_loc.endswith(".json"):
            save_loc += ".json"
        with open(save_loc, 'w') as file:
            json.dump(json_config, file)

    return json_config


def count_doc_lines(json_config: dict) -> float:
    """Counts the number of parameters with docstrings - returns a ratio of the number of parameters with docstrings to the total number of parameters"""
    count = 0
    total = 0
    for _, items in json_config.items():
        for _, descriptor in items.items():
            total += 1
            if descriptor['doc']:
                count += 1

    if total == 0:
        return 0.0
    else:
        return count / total


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o", "--output",
        help="Output file name",
        type=str,
        default="rucio_config_defaults.json"
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

    parser.add_argument(
        "--json",
        help="Output json",
        action="store_true",
    )
    return parser


if __name__ == "__main__":
    args = arguments().parse_args()

    source_files = get_source_files()
    defaults = []
    for file in source_files:
        file_content = load_file(file)
        defaults += get_config_lines_with_defaults(file_content)

    json_file = make_json_config(defaults, args.output if args.json else None)
    if args.count:
        print(count_doc_lines(json_file))

    if args.markdown:
        write_to_markdown(json_file, args.output)
