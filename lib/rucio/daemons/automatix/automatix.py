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

import functools
import logging
import random
import secrets
import tempfile
import threading
from configparser import NoOptionError, NoSectionError
from datetime import datetime
from json import load
from os import remove, rmdir
from typing import TYPE_CHECKING, Any, Optional

import rucio.db.sqla.util
from rucio.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int, config_get_list
from rucio.common.logging import setup_logging
from rucio.common.stopwatch import Stopwatch
from rucio.common.types import FileToUploadDict, InternalScope, LoggerFunction
from rucio.common.utils import execute, generate_uuid
from rucio.core.monitor import MetricManager
from rucio.core.scope import list_scopes
from rucio.core.vo import map_vo
from rucio.daemons.common import HeartbeatHandler, run_daemon

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import FrameType


METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()
DAEMON_NAME = "automatix"


def get_data_distribution(
        inputfile: str
) -> tuple[dict[str, int], dict[str, Any]]:
    with open(inputfile) as data_file:
        data = load(data_file)
    probabilities = {}
    probability = 0
    for key in data:
        probability += data[key]["probability"]
        probabilities[key] = probability
    for key in list(probabilities):
        probabilities[key] = float(probabilities[key]) / probability
    return probabilities, data


def choose_element(
        probabilities: "Mapping[str, int]",
        data: "Mapping[str, Any]"
) -> dict[str, Any]:
    rnd = random.uniform(0, 1)  # noqa: S311
    prob = 0
    for key in probabilities:
        prob = probabilities[key]
        if prob >= rnd:
            return data[key]
    return data[key]


def generate_file(
        fname: str,
        size: int,
        logger: LoggerFunction = logging.log
) -> int:
    cmd = "/bin/dd if=/dev/urandom of=%s bs=%s count=1" % (fname, size)
    exitcode, out, err = execute(cmd)
    logger(logging.DEBUG, out)
    logger(logging.DEBUG, err)
    return exitcode


def generate_didname(
        metadata: "Mapping[str, str]",
        dsn: Optional[str],
        did_type: str
) -> str:
    try:
        did_prefix = config_get("automatix", "did_prefix")
    except (NoOptionError, NoSectionError, RuntimeError):
        did_prefix = ""
    try:
        pattern = config_get("automatix", "%s_pattern" % did_type)
        separator = config_get("automatix", "separator")
    except (NoOptionError, NoSectionError, RuntimeError):
        return generate_uuid()
    fields = pattern.split(separator)
    file_name = ""
    for field in fields:
        if field == 'date':
            field_str = str(datetime.utcnow().date())
        elif field == 'did_prefix':
            field_str = did_prefix
        elif field == "dsn":
            field_str = dsn
        elif field == "uuid":
            field_str = generate_uuid()
        elif field == "randint":
            field_str = str(secrets.choice(range(0, 100001)))
        else:
            field_str = metadata.get(field, None)
            if not field_str:
                field_str = str(secrets.choice(range(0, 100001)))
        file_name = "%s%s%s" % (file_name, separator, field_str)
    len_separator = len(separator)
    return file_name[len_separator:]


def automatix(inputfile: str, sleep_time: int, once: bool = False) -> None:
    """
    Creates an automatix Worker that uploads datasets to a list of rses.

    :param inputfile: The input file where the parameters of the distribution is set
    :param sleep_time: Thread sleep time after each chunk of work.
    :param once: Run only once.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            inputfile=inputfile,
        ),
    )


def run_once(heartbeat_handler: HeartbeatHandler, inputfile: str, **_kwargs) -> bool:

    _, _, logger = heartbeat_handler.live()
    try:
        rses = config_get_list("automatix", "rses")
    except (NoOptionError, NoSectionError, RuntimeError):
        logging.log(
            logging.ERROR,
            "Option rses not found in automatix section. Trying the legacy sites option",
        )
        try:
            rses = config_get_list("automatix", "sites")
            logging.log(
                logging.WARNING,
                "Option sites found in automatix section. This option will be deprecated soon. Please update your config to use rses.",
            )
        except (NoOptionError, NoSectionError, RuntimeError):
            logger(logging.ERROR, "Could not load sites from configuration")
            return True

    set_metadata = config_get_bool(
        "automatix", "set_metadata", raise_exception=False, default=True
    )
    dataset_lifetime = config_get_int(
        "automatix", "dataset_lifetime", raise_exception=False, default=0
    )
    account = config_get("automatix", "account", raise_exception=False, default="root")
    scope = config_get("automatix", "scope", raise_exception=False, default="test")
    client = Client(account=account)
    vo = map_vo(client.vo)  # type: ignore
    filters = {"scope": InternalScope("*", vo=vo)}
    scopes = list_scopes(filter_=filters)
    if InternalScope(scope, vo=vo) not in scopes:
        logger(logging.ERROR, "Scope %s does not exist. Exiting", scope)
        return True

    logger(logging.INFO, "Getting data distribution")
    probabilities, data = get_data_distribution(inputfile)
    logger(logging.DEBUG, "Probabilities %s", probabilities)

    cycle_stopwatch = Stopwatch()
    successes = []
    failures = []
    for rse in rses:
        stopwatch = Stopwatch()
        _, _, logger = heartbeat_handler.live()
        tmpdir = tempfile.mkdtemp()
        logger(logging.INFO, "Running on RSE %s", rse)
        dic = choose_element(probabilities, data)
        metadata = dic["metadata"]
        try:
            nbfiles = dic["nbfiles"]
        except KeyError:
            nbfiles = 2
            logger(
                logging.WARNING, "No nbfiles defined in the configuration, will use 2"
            )
        try:
            filesize = dic["filesize"]
        except KeyError:
            filesize = 1000000
            logger(
                logging.WARNING,
                "No filesize defined in the configuration, will use 1M files",
            )
        dsn = generate_didname(metadata, None, "dataset")
        fnames = []
        lfns = []
        physical_fnames = []
        items: list[FileToUploadDict] = []
        for _ in range(nbfiles):
            fname = generate_didname(metadata=metadata, dsn=dsn, did_type="file")
            lfns.append(fname)
            logger(logging.INFO, "Generating file %s in dataset %s", fname, dsn)
            physical_fname = "%s/%s" % (tmpdir, "".join(fname.split("/")))
            physical_fnames.append(physical_fname)
            generate_file(physical_fname, filesize, logger=logger)
            fnames.append(fname)
            file_: FileToUploadDict = {
                "did_scope": scope,
                "did_name": fname,
                "dataset_scope": scope,
                "dataset_name": dsn,
                "rse": rse,
                "path": physical_fname,
            }
            if set_metadata:
                file_["dataset_meta"] = metadata
                if dataset_lifetime:
                    file_["dataset_meta"]["lifetime"] = dataset_lifetime
            items.append(file_)
        logger(logging.INFO, "Upload %s:%s to %s", scope, dsn, rse)
        try:
            upload_client = UploadClient(client)
            ret = upload_client.upload(items=items)
            if ret == 0:
                logger(logging.INFO, "%s successfully registered on %s", dsn, rse)
                METRICS.counter(name="addnewdataset.done").inc()
                METRICS.counter(name="addnewfile.done").inc(nbfiles)
                METRICS.timer(name='datasetinjection').observe(stopwatch.elapsed)
                successes.append(rse)
            else:
                logger(logging.INFO, "Error uploading files")
                failures.append(rse)
        except Exception as error:
            logger(logging.ERROR, "Error uploading files on %s: %s", rse, str(error))
            failures.append(rse)
        finally:
            for physical_fname in physical_fnames:
                remove(physical_fname)
            rmdir(tmpdir)
    logger(
        logging.INFO,
        "It took %f seconds to upload datasets on %s RSEs: %s",
        cycle_stopwatch.elapsed,
        len(successes),
        str(successes),
    )
    if failures:
        logger(
            logging.WARNING,
            "Datasets could not be uploaded on %s RSEs: %s", len(failures), str(failures),
        )
    return True


def run(
    total_workers: int = 1,
    once: bool = False,
    inputfile: str = "/opt/rucio/etc/automatix.json",
    sleep_time: int = 60,
) -> None:
    """
    Starts up the automatix threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException(
            "Database was not updated, daemon won't start"
        )

    threads = list()
    for _ in range(total_workers):
        kwargs = {"once": once, "sleep_time": sleep_time, "inputfile": inputfile}
        threads.append(threading.Thread(target=automatix, kwargs=kwargs))
    [thread.start() for thread in threads]
    while threads[0].is_alive():
        logging.log(logging.DEBUG, "Still %i active threads", len(threads))
        [thread.join(timeout=3.14) for thread in threads]


def stop(signum: Optional[int] = None, frame: Optional["FrameType"] = None) -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()
