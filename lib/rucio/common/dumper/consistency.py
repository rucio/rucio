# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Fernando Lopez, <felopez@cern.ch>, 2015
#
# PY3K COMPATIBLE

from rucio.common import dumper
from rucio.common.dumper import error, DUMPS_CACHE_DIR
import data_models
import datetime
import logging
import os
import path_parsing
import re
import subprocess
import tempfile


subcommands = ['consistency', 'consistency-manual']


class Consistency(data_models.DataModel):
    SCHEMA = (
        ('apparent_status', str),
        ('path', str),
    )

    @classmethod
    def dump(cls, subcommand, ddm_endpoint, storage_dump, prev_date_fname=None, next_date_fname=None,
             prev_date=None, next_date=None, sort_rucio_replica_dumps=False, date=None,
             cache_dir=DUMPS_CACHE_DIR):
        logger = logging.getLogger('auditor.consistency')
        if subcommand == 'consistency':
            prev_date_fname = data_models.Replica.download(
                ddm_endpoint, prev_date)
            next_date_fname = data_models.Replica.download(
                ddm_endpoint, next_date)
            assert prev_date_fname is not None
            assert next_date_fname is not None
        else:
            assert subcommand == 'consistency-manual'

        prefix = path_parsing.prefix(
            dumper.agis_endpoints_data(),
            ddm_endpoint,
        )
        prefix_components = path_parsing.components(prefix)

        def parser(line):
            '''
            Simple parser for Rucio replica dumps.

            :param line: String with one line of a dump.
            :returns: A tuple with the path and status of the replica.
            '''
            fields = line.split('\t')
            path = fields[6].strip().lstrip('/')
            status = fields[8].strip()

            return ','.join((path, status))

        def strip_storage_dump(line):
            '''
            Parser to have consistent paths in storage dumps.

            :param line: String with one line of a dump.
            :returns: Path formated as in the Rucio Replica Dumps.
            '''
            relative = path_parsing.remove_prefix(
                prefix_components,
                path_parsing.components(line),
            )
            if relative[0] == 'rucio':
                relative = relative[1:]
            return '/'.join(relative)

        if sort_rucio_replica_dumps:
            prev_date_fname_sorted = gnu_sort(
                parse_and_filter_file(prev_date_fname, parser=parser, cache_dir=cache_dir),
                delimiter=',',
                fieldspec='1',
                cache_dir=cache_dir,
            )

            next_date_fname_sorted = gnu_sort(
                parse_and_filter_file(next_date_fname, parser=parser, cache_dir=cache_dir),
                delimiter=',',
                fieldspec='1',
                cache_dir=cache_dir,
            )
        else:
            prev_date_fname_sorted = parse_and_filter_file(
                prev_date_fname,
                parser=parser,
                cache_dir=cache_dir,
            )
            next_date_fname_sorted = parse_and_filter_file(
                next_date_fname,
                parser=parser,
                cache_dir=cache_dir,
            )

        standard_name_re = r'(ddmendpoint_{0}_\d{{2}}-\d{{2}}-\d{{4}}_[0-9a-f]{{40}})$'.format(ddm_endpoint)
        standard_name_match = re.search(standard_name_re, storage_dump)
        if standard_name_match is not None:
            # If the original filename was generated using the expected format,
            # just use the name as prefix for the parsed file.
            sd_prefix = standard_name_match.group(0)
        elif date is not None:
            # Otherwise try to use the date information and DDMEndpoint name to
            # have a meaningful filename.
            sd_prefix = 'ddmendpoint_{0}_{1}'.format(
                ddm_endpoint,
                date.strftime('%d-%m-%Y'),
            )
        else:
            # As last resort use only the DDMEndpoint name, but this is error
            # prone as old dumps may interfere with the checks.
            sd_prefix = 'ddmendpoint_{0}_unknown_date'.format(
                ddm_endpoint,
            )
            logger.warn(
                'Using basic and error prune naming for RSE dump as no date '
                'information was provided, %s dump will be named %s',
                ddm_endpoint,
                sd_prefix,
            )

        storage_dump_fname_sorted = gnu_sort(
            parse_and_filter_file(
                storage_dump,
                parser=strip_storage_dump,
                prefix=sd_prefix,
                cache_dir=cache_dir,
            ),
            prefix=sd_prefix,
            cache_dir=cache_dir,
        )

        with open(prev_date_fname_sorted) as prevf:
            with open(next_date_fname_sorted) as nextf:
                with open(storage_dump_fname_sorted) as sdump:
                    for path, where, status in compare3(prevf, sdump, nextf):
                        prevstatus, nextstatus = status

                        if where[0] and not where[1] and where[2]:
                            if prevstatus == 'A' and nextstatus == 'A':
                                yield cls('LOST', path)

                        if not where[0] and where[1] and not where[2]:
                            yield cls('DARK', path)


def _try_to_advance(it, default=None):
    try:
        el = next(it)
    except StopIteration:
        return default
    return el.strip()


def min3(*values):
    '''
    Minimum between the 3 values ignoring None
    '''
    values = [value for value in values if value is not None]
    assert len(values) > 0
    return min(values)


def split_if_not_none(value, sep=',', fields=2):
    return value.split(sep) if value is not None else ([None] * fields)


def compare3(it0, it1, it2):
    '''
    Generator to compare 3 sorted iterables, in each
    iteration it yields a tuple of the form (current, (bool, bool, bool))
    where current is the current element checked and the
    second element of the tuple is a triplet whose elements take
    a true value if current is contained in the it0, it1 or it2
    respectively.

    This function can't compare the iterators properly if None is
    a valid value.
    '''

    it0 = iter(it0)
    it1 = iter(it1)
    it2 = iter(it2)
    v0 = _try_to_advance(it0)
    v1 = _try_to_advance(it1)
    v2 = _try_to_advance(it2)

    while v0 is not None or v1 is not None or v2 is not None:
        path0, status0 = split_if_not_none(v0)
        path2, status2 = split_if_not_none(v2)

        vmin = min3(path0, v1, path2)
        in0 = in1 = in2 = False
        in0_status = in2_status = None

        # Detect in which iterables the value is present
        #   inN is True if the value is present on the N iterable.
        #   sN  is the status of the path in the rucio replica
        #       dumps (N is either 0 or 2).
        if path0 is not None and path0 == vmin:
            in0 = True
            in0_status = status0

        if v1 is not None and v1 == vmin:
            in1 = True

        if path2 is not None and path2 == vmin:
            in2 = True
            in2_status = status2

        # yield the value, in which iterables is present, and the status
        # in each rucio replica dumps (if it is present there, else None).
        yield (vmin, (in0, in1, in2), (in0_status, in2_status))

        # Discard duplicate entries (it shouldn't be duplicate entries
        # anyways) and
        # advance the iterators, if the iterator N is depleted vN is set
        # to None.
        while v0 is not None and path0 == vmin:
            v0 = _try_to_advance(it0)
            path0, status0 = split_if_not_none(v0)

        while v1 is not None and v1 == vmin:
            v1 = _try_to_advance(it1)

        while v2 is not None and path2 == vmin:
            v2 = _try_to_advance(it2)
            path2, status2 = split_if_not_none(v2)


def parse_and_filter_file(filepath, parser=lambda s: s, filter_=lambda s: s, prefix=None, postfix='parsed', cache_dir=DUMPS_CACHE_DIR):
    '''
    Opens `filepath` as a read-only file, and for each line of the file
    for which the `filter_` function returns True, it writes a version
    parsed with the `parser` function.

    The name of the output file is generated appending '_' + `postfix` to
    the filename in `filepath`. If `prefix` is given it is used instead
    of `filepath`.

    The output file (and temporary files while processing are stored in
    `cache_dir`.

    Default values for the arguments:
        - `parser`: returns the same string.
        - `filter_`: returns True for any argument.
        - `prefix`: None (the name of the input file is used as prefix).
        - `postfix`: 'parsed'.
        - `cache_dir`: DUMPS_CACHE_DIR.

    The output file is created with a random name and renamed atomically
    when it is complete.

    '\n' is appended to each line, therefore if the input is 'a\nb\n' and `parser`
    is not especified the output will be 'a\n\nb\n\n'
    '''

    prefix = os.path.basename(filepath) if prefix is None else prefix
    output_name = '_'.join((prefix, postfix))
    output_path = os.path.join(cache_dir, output_name)

    if os.path.exists(output_path):
        return output_path

    with dumper.temp_file(cache_dir, final_name=output_name) as (output, _):
        input_ = dumper.smart_open(filepath)
        for line in input_:
            if filter_(line):
                output.write(parser(line) + '\n')

        input_.close()

    return output_path


def gnu_sort(file_path, prefix=None, delimiter=None, fieldspec=None, cache_dir=DUMPS_CACHE_DIR):
    '''
    Sort the file with path `file_path` using the GNU sort command, the
    original file is unchanged, the output file is saved with path
    <cache_dir>/<prefix>_sorted.

    :param prefix: If given the output file will be named <prefix>_sorted.
    Otherwise the prefix is the name of the input file.
    :param delimiter: Delimiter character if the data is formated in
    columns (argument of -t in the sort command).
    :param fieldspec: String with the specification of column or columns
    to be used to sort (argument -k in the sort command).
    :param cachedir: Working dir where the output file will be placed.

    Note: Using GNU sort to sort large files is convenient as it has low
    memory and it is relatively fast if used with the environment variable
    LC_ALL set to C as in this function.
    '''
    assert (delimiter is None and fieldspec is None) or (delimiter is not None and fieldspec is not None)
    if delimiter is None:
        cmd_line = 'LC_ALL=C sort {0} > {1}'
    else:
        cmd_line = 'LC_ALL=C sort -t {0} -k {1} {{0}} > {{1}}'.format(delimiter, fieldspec)

    prefix = os.path.basename(file_path) if prefix is None else prefix

    sorted_name = '_'.join((prefix, 'sorted'))
    sorted_path = os.path.join(cache_dir, sorted_name)

    if os.path.exists(sorted_path):
        return sorted_path

    # FIXME: mktemp() is an insecure function and this may be a security
    # threat in some scenarios. Find another way to do it.
    tfile = tempfile.mktemp(dir=cache_dir)

    subprocess.check_call(
        cmd_line.format(file_path, tfile),
        shell=True,
    )

    os.link(tfile, sorted_path)
    os.unlink(tfile)

    return sorted_path


def populate_args(argparser):
    # Option to download the rucio replica dumps automaticaly
    parser = argparser.add_parser(
        'consistency',
        help='Consistency check to verify possible lost files and dark data '
             '(replica dumps are downloaded automatically)'
    )
    parser.add_argument('ddm_endpoint')
    parser.add_argument('storage_dump')
    parser.add_argument(
        '--delta',
        help='Difference in days between the SE dump and the desired rucio '
             'replica dumps (use either this argument or --prev-date and '
             '--next-date)',
        required=False
    )
    parser.add_argument(
        '--prev-date',
        help='Date of the older rucio replica dump to use',
        required=False
    )
    parser.add_argument(
        '--next-date',
        help='Date of the newer rucio replica dump to use',
        required=False
    )

    # Option to use already downloaded rucio replica dumps
    parser_manual = argparser.add_parser(
        'consistency-manual',
        help='Consistency check to verify possible lost files and dark data '
             '(replica dumps should be provided by the user)'
    )
    parser_manual.add_argument('ddm_endpoint')
    parser_manual.add_argument('replicas_before')
    parser_manual.add_argument('storage_dump')
    parser_manual.add_argument('replicas_after')

    for p in (parser, parser_manual):
        p.add_argument(
            '--sort-rucio-dumps',
            help='Starting 18-08-2015 the Rucio Replica Dumps are sorted by '
                 'path. If you need to work with older dumps use this '
                 'argument.',
            action='store_true'
        )


_date_re = re.compile(r'dump_(\d{8})')


def _parse_args_consistency(args):
    args_dict = {}

    # Filename should contain the date
    date_str = _date_re.match(os.path.basename(args.storage_dump))
    if date_str is None:
        error('The storage dump filename must be of the form '
              '"dump_YYYYMMDD" where the date correspond to the date '
              'of the newest files included')
    date_str = date_str.group(1)
    assert date_str is not None
    try:
        args_dict['date'] = date = datetime.datetime.strptime(date_str, '%Y%m%d')
    except ValueError:
        error('Invalid date {0}'.format(date_str))

    if not os.path.exists(args.storage_dump):
        error('File "{0}" does not exist'.format(args.storage_dump))

    if (args.prev_date is not None or args.next_date is not None) and args.delta is not None:
        error('Missing or conflicting arguments, specify either '
              '"--delta" or "--prev-date" and "--next-date"')

    if args.prev_date is not None and args.next_date is not None:
        args_dict['prev_date'] = datetime.datetime.strptime(
            args.prev_date, '%d-%m-%Y',
        )
        args_dict['next_date'] = datetime.datetime.strptime(
            args.next_date, '%d-%m-%Y',
        )
    elif args.delta is not None:
        delta = int(args.delta)
        args_dict['prev_date'] = date - datetime.timedelta(days=delta)
        args_dict['next_date'] = date + datetime.timedelta(days=delta)
    else:
        error('Missing arguments, specify either "--delta" or '
              '"--prev-date" and "--next-date"')

    return args_dict


def _parse_args_consistency_manual(args):
    args_dict = {}
    args_dict['prev_date_fname'] = args.replicas_before
    args_dict['next_date_fname'] = args.replicas_after

    for path in (args.storage_dump, args_dict['prev_date_fname'], args_dict['next_date_fname']):
        if not os.path.exists(path):
            error('File "{0}" does not exist'.format(path))

    return args_dict


def parse_args(args):
    args_dict = {}
    args_dict['subcommand'] = args.subcommand
    args_dict['ddm_endpoint'] = args.ddm_endpoint
    args_dict['storage_dump'] = args.storage_dump
    args_dict['sort_rucio_replica_dumps'] = args.sort_rucio_dumps
    if args.subcommand == 'consistency':
        args_dict.update(_parse_args_consistency(args))
    else:
        args_dict.update(_parse_args_consistency_manual(args))

    return args_dict
