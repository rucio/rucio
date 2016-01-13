from rucio.common.dumper import DUMPS_CACHE_DIR
from rucio.common.dumper import temp_file
from rucio.common.dumper.data_models import Replica
import hashlib
import logging
import os
import re
import shutil
import tempfile

try:
    import hadoopy
except ImportError:
    import sys
    if 'nose' not in sys.modules and 'py.test' not in sys.modules:
        raise


class ReplicaFromHDFS(Replica):
    BASE_URL = '/user/rucio01/reports/{0}/replicas_per_rse/{1}.bz2/*'

    @classmethod
    def download(cls, rse, date, cache_dir=DUMPS_CACHE_DIR, buffer_size=65536):
        logger = logging.getLogger('auditor.hdfs')

        if not os.path.isdir(cache_dir):
            os.mkdir(cache_dir)
        tmp_dir = tempfile.mkdtemp(dir=cache_dir)

        url = cls.BASE_URL.format(date.strftime('%Y-%m-%d'), rse)
        filename = '{0}_{1}_{2}_{3}'.format(
            cls.__name__.lower(),
            rse,
            date.strftime('%d-%m-%Y'),
            hashlib.sha1(url).hexdigest()
        )
        filename = re.sub(r'\W', '-', filename)
        path = os.path.join(cache_dir, filename)

        if os.path.exists(path):
            logger.debug('Taking Rucio Replica Dump %s for %s from cache', path, rse)
            return path

        try:
            logging.debug('Trying to download: %s for %s', url, rse)

            hadoopy.get(cls.BASE_URL.format(date.strftime('%Y-%m-%d'), rse), tmp_dir)
            files = (os.path.join(tmp_dir, file_) for file_ in sorted(os.listdir(tmp_dir)))

            with temp_file(cache_dir, filename) as (full_dump, _):
                for chunk_file in files:
                    with open(chunk_file, 'rb') as partial_dump:
                        while True:
                            data_chunk = partial_dump.read(buffer_size)
                            if not data_chunk:
                                break
                            full_dump.write(data_chunk)
        finally:
            shutil.rmtree(tmp_dir)

        return path
