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
import hashlib
import io
import mmap
import zlib
from functools import partial
from typing import TYPE_CHECKING

from rucio.core.common.bittorrent import merkle_sha256
from rucio.core.common.exception import ChecksumCalculationError

if TYPE_CHECKING:
    from _typeshed import FileDescriptorOrPath

# GLOBALLY_SUPPORTED_CHECKSUMS = ['adler32', 'md5', 'sha256', 'crc32']
GLOBALLY_SUPPORTED_CHECKSUMS = ['adler32', 'md5']
PREFERRED_CHECKSUM = GLOBALLY_SUPPORTED_CHECKSUMS[0]
CHECKSUM_KEY = 'supported_checksums'


def is_checksum_valid(checksum_name: str) -> bool:
    """
    A simple function to check whether a checksum algorithm is supported.
    Relies on GLOBALLY_SUPPORTED_CHECKSUMS to allow for expandability.

    :param checksum_name: The name of the checksum to be verified.
    :returns: True if checksum_name is in GLOBALLY_SUPPORTED_CHECKSUMS list, False otherwise.
    """

    return checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS


def set_preferred_checksum(checksum_name: str) -> None:
    """
    If the input checksum name is valid,
    set it as PREFERRED_CHECKSUM.

    :param checksum_name: The name of the checksum to be verified.
    """
    if is_checksum_valid(checksum_name):
        global PREFERRED_CHECKSUM
        PREFERRED_CHECKSUM = checksum_name


def adler32(file: "FileDescriptorOrPath") -> str:
    """
    An Adler-32 checksum is obtained by calculating two 16-bit checksums A and B
    and concatenating their bits into a 32-bit integer. A is the sum of all bytes in the
    stream plus one, and B is the sum of the individual values of A from each step.

    :param file: file name
    :returns: Hexified string, padded to 8 values.
    """

    # adler starting value is _not_ 0
    adler = 1

    can_mmap = False
    # try:
    #    with open(file, 'r+b') as f:
    #        can_mmap = True
    # except:
    #    pass

    try:
        # use mmap if possible
        if can_mmap:
            with open(file, 'r+b') as f:
                m = mmap.mmap(f.fileno(), 0)
                # partial block reads at slightly increased buffer sizes
                for block in iter(partial(m.read, io.DEFAULT_BUFFER_SIZE * 8), b''):
                    adler = zlib.adler32(block, adler)
        else:
            with open(file, 'rb') as f:
                # partial block reads at slightly increased buffer sizes
                for block in iter(partial(f.read, io.DEFAULT_BUFFER_SIZE * 8), b''):
                    adler = zlib.adler32(block, adler)

    except Exception as e:
        raise ChecksumCalculationError('adler32', str(file), e)

    # backflip on 32bit -- can be removed once everything is fully migrated to 64bit
    if adler < 0:
        adler = adler + 2 ** 32

    return str('%08x' % adler)


def md5(file: "FileDescriptorOrPath") -> str:
    """
    Runs the MD5 algorithm (RFC-1321) on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file, "rb") as f:
            list(map(hash_md5.update, iter(lambda: f.read(4096), b"")))
    except Exception as e:
        raise ChecksumCalculationError('md5', str(file), e)

    return hash_md5.hexdigest()


def sha256(file: "FileDescriptorOrPath") -> str:
    """
    Runs the SHA256 algorithm on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    with open(file, "rb") as f:
        bytes_ = f.read()  # read entire file as bytes
        readable_hash = hashlib.sha256(bytes_).hexdigest()
        print(readable_hash)
        return readable_hash


def crc32(file: "FileDescriptorOrPath") -> str:
    """
    Runs the CRC32 algorithm on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    prev = 0
    for eachLine in open(file, "rb"):
        prev = zlib.crc32(eachLine, prev)
    return "%X" % (prev & 0xFFFFFFFF)


CHECKSUM_ALGO_DICT = {
    'adler32': adler32,
    'md5': md5,
    'sha256': sha256,
    'crc32': crc32,
    'merkle_sha256': merkle_sha256
}
