"""Import helpers from scripts/ (not a package) for tests."""
import importlib.util
from pathlib import Path


def _load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent.parent / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


make_samples = _load("make_samples")
