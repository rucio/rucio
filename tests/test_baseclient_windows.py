import importlib
import os
import sys
import types
from pathlib import Path


def test_baseclient_imports_without_os_geteuid(monkeypatch):
    monkeypatch.delattr(os, "geteuid", raising=False)
    if "dogpile.cache" not in sys.modules:
        region = types.SimpleNamespace(cache_on_arguments=lambda **kw: (lambda fn: fn))
        region.configure = lambda *a, **kw: region
        m = types.ModuleType("dogpile.cache")
        m.make_region = lambda *a, **kw: region
        monkeypatch.setitem(sys.modules, "dogpile", types.ModuleType("dogpile"))
        monkeypatch.setitem(sys.modules, "dogpile.cache", m)

    lib_dir = str(Path(__file__).resolve().parents[1] / "lib")
    added = lib_dir not in sys.path
    if added:
        sys.path.insert(0, lib_dir)
    try:
        mod = importlib.import_module("rucio.client.baseclient")
        mod = importlib.reload(mod)
        assert hasattr(mod, "BaseClient")
    finally:
        if added and lib_dir in sys.path:
            sys.path.remove(lib_dir)
