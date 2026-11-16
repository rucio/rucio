import inspect
from pathlib import Path
import ast


def test_conveyor_receiver_run_forwards_once_and_breaks():
    src = (
        Path(__file__).resolve().parents[1]
        / "lib"
        / "rucio"
        / "daemons"
        / "conveyor"
        / "receiver.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(src)
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    receiver_args = [a.arg for a in funcs["receiver"].args.args]
    assert "once" in receiver_args
    assert "'once': once" in src
    assert "if once:\n                break" in src
