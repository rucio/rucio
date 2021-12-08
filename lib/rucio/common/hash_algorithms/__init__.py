from abc import ABC, abstractmethod
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules


class RucioHashAlgorithm(ABC):
    @staticmethod
    @abstractmethod
    def compute_on_file(file):
        raise NotImplementedError("Abstract method called")


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
        except TypeError:
            # We are only interested in classes here
            pass
