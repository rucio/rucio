import hashlib
import io
import mmap
import zlib

from functools import partial

from . import RucioHashAlgorithm


class Adler32(RucioHashAlgorithm):
    @staticmethod
    def compute_on_file(file):
        """
        An Adler-32 checksum is obtained by calculating two 16-bit checksums A and B
        and concatenating their bits into a 32-bit integer. A is the sum of all bytes in the
        stream plus one, and B is the sum of the individual values of A from each step.

        :param file: file name
        :returns: Hexified string, padded to 8 values.
        :raises: Exception: if checksum calculation failed
        """

        # adler starting value is _not_ 0
        adler = 1

        can_mmap = False
        try:
            with open(file, "r+b") as f:
                can_mmap = True
        except:
            pass

        try:
            # use mmap if possible
            if can_mmap:
                with open(file, "r+b") as f:
                    m = mmap.mmap(f.fileno(), 0)
                    # partial block reads at slightly increased buffer sizes
                    for block in iter(partial(m.read, io.DEFAULT_BUFFER_SIZE * 8), b""):
                        adler = zlib.adler32(block, adler)
            else:
                with open(file, "rb") as f:
                    # partial block reads at slightly increased buffer sizes
                    for block in iter(partial(f.read, io.DEFAULT_BUFFER_SIZE * 8), b""):
                        adler = zlib.adler32(block, adler)

        except Exception as e:
            raise Exception(
                "FATAL - could not get Adler-32 checksum of file %s: %s" % (file, e)
            )

        # backflip on 32bit -- can be removed once everything is fully migrated to 64bit
        if adler < 0:
            adler = adler + 2 ** 32

        return str("%08x" % adler)


class CRC32(RucioHashAlgorithm):
    @staticmethod
    def compute_on_file(file):
        """
        Runs the CRC32 algorithm on the binary content of the file named file
        and returns the hexadecimal digest

        :param file: file name
        :returns: string of 32 hexadecimal digits
        """
        prev = 0
        for eachLine in open(file, "rb"):
            prev = zlib.crc32(eachLine, prev)
        return "%x" % (prev & 0xFFFFFFFF)


class MD5(RucioHashAlgorithm):
    @staticmethod
    def compute_on_file(file):
        """
        Runs the MD5 algorithm (RFC-1321) on the binary content of the file named file
        and returns the hexadecimal digest

        :param file: file name
        :returns: string of 32 hexadecimal digits
        :raises: Exception: if checksum calculation failed
        """
        hash_md5 = hashlib.md5()
        try:
            with open(file, "rb") as f:
                list(map(hash_md5.update, iter(lambda: f.read(4096), b"")))
        except Exception as e:
            raise Exception(
                "FATAL - could not get MD5 checksum of file %s - %s" % (file, e)
            )

        return hash_md5.hexdigest()


class SHA256(RucioHashAlgorithm):
    @staticmethod
    def compute_on_file(file):
        """
        Runs the SHA256 algorithm on the binary content of the file named file
        and returns the hexadecimal digest

        :param file: file name
        :returns: string of 32 hexadecimal digits
        """
        with open(file, "rb") as f:
            bytes_ = f.read()  # read entire file as bytes
            readable_hash = hashlib.sha256(bytes_).hexdigest()
            return readable_hash
