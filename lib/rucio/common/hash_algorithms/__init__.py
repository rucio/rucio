from abc import ABC, abstractmethod
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules


class RucioHashAlgorithm(ABC):
    @staticmethod
    @abstractmethod
    def compute_on_file(file):
        raise NotImplementedError("Abstract method called")


GLOBALLY_SUPPORTED_CHECKSUMS = ["adler32", "md5"]
PREFERRED_CHECKSUM = GLOBALLY_SUPPORTED_CHECKSUMS[0]
CHECKSUM_ALGO_DICT = {}


def is_checksum_valid(checksum_name):
    """
    A simple function to check wether a checksum algorithm is supported.
    Relies on GLOBALLY_SUPPORTED_CHECKSUMS to allow for expandability.

    :param checksum_name: The name of the checksum to be verified.
    :returns: True if checksum_name is in GLOBALLY_SUPPORTED_CHECKSUMS list, False otherwise.
    """

    return checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS


def set_preferred_checksum(checksum_name):
    """
    A simple function to set the preferred checksum algorithm.
    Unsupported algorithms are quietly ignored.

    :param checksum_name: The name of the checksum algorithm to be made preferred.
    """
    if is_checksum_valid(checksum_name):
        global PREFERRED_CHECKSUM
        PREFERRED_CHECKSUM = checksum_name


package_dir = Path(__file__).resolve().parent
for (_, module_name, _) in iter_modules([package_dir]):
    module = import_module("%s.%s" % (__name__, module_name))
    for attribute_name in dir(module):
        attribute = getattr(module, attribute_name)

        try:
            if issubclass(attribute, RucioHashAlgorithm):
                algorithm_name = attribute_name.lower()

                # TODO: check uniqueness of algorithm names
                globals()[algorithm_name] = attribute
                CHECKSUM_ALGO_DICT[algorithm_name] = attribute.compute_on_file
        except TypeError:
            # We are only interested in classes here
            pass
