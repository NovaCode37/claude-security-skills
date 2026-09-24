"""Hook engines must inspect only the explicitly supplied file list."""

import importlib.util
from pathlib import Path
import sys

import pytest


def load_engine(folder, filename):
    path = Path(__file__).resolve().parents[1] / folder / filename
    name = "staged_" + folder.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("folder,filename,bad", [
    ("secret-scanner", "engine.py", 'key = "AKIAIOSFODNN7EXAMPLE"\n'),
    ("sast-lite", "analyzer.py", 'eval(input())\n'),
])
def test_multiple_staged_paths_exclude_unselected_files(tmp_path, capsys, folder, filename, bad):
    engine = load_engine(folder, filename)
    first, second, unselected = [tmp_path / name for name in ("a.py", "b.py", "unselected.py")]
    first.write_text("answer = 42\n")
    second.write_text("answer = 43\n")
    unselected.write_text(bad)
    assert engine.main([str(first), str(second)]) == 0
    second.write_text(bad)
    assert engine.main([str(first), str(second)]) == 1
    output = capsys.readouterr().out
    assert str(second) in output
    assert str(unselected) not in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output
