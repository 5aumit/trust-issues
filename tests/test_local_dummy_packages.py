import json
from pathlib import Path
import subprocess
import sys
import zipfile

from configs.issuetrojan.local_dummy_packages import PACKAGES, build_wheels


def test_local_dummy_wheel_is_installed_offline_with_metadata(tmp_path):
    wheelhouse = tmp_path / "wheelhouse"
    build_wheels(wheelhouse)
    wheel_paths = list(wheelhouse.glob("*.whl"))
    assert len(wheel_paths) == len(PACKAGES)
    wheel_names = set()
    for wheel_path in wheel_paths:
        with zipfile.ZipFile(wheel_path) as wheel:
            metadata = next(
                name for name in wheel.namelist() if name.endswith("/METADATA")
            )
            wheel_names.add(
                next(
                    line.removeprefix("Name: ")
                    for line in wheel.read(metadata).decode().splitlines()
                    if line.startswith("Name: ")
                )
            )
    assert wheel_names == set(PACKAGES)
    env_dir = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(env_dir)], check=True)
    python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    package = PACKAGES[0]
    status = (
        "import json, sys\n"
        "from importlib.metadata import PackageNotFoundError, distribution\n"
        "try:\n"
        " d=distribution(sys.argv[1])\n"
        " print(json.dumps({'installed': True, 'name': d.metadata['Name'], 'version': d.version}))\n"
        "except PackageNotFoundError:\n"
        " print(json.dumps({'installed': False}))\n"
    )
    before = subprocess.check_output([python, "-c", status, package], text=True)
    assert json.loads(before) == {"installed": False}
    subprocess.run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            package,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    after = subprocess.check_output([python, "-c", status, package], text=True)
    assert json.loads(after) == {
        "installed": True,
        "name": package,
        "version": "0.0.0",
    }


def test_dummy_packages_are_opt_in(monkeypatch):
    from scripts.run_issuetrojan import parse_args

    monkeypatch.setattr(sys, "argv", ["run_issuetrojan", "--list"])
    default = parse_args()
    assert default.local_dummy_packages is False
    assert default.image == "issuetrojan-smoke:py312"

    monkeypatch.setattr(
        sys,
        "argv",
        ["run_issuetrojan", "--list", "--local-dummy-packages"],
    )
    opt_in = parse_args()
    assert opt_in.local_dummy_packages is True
    assert opt_in.image == "issuetrojan-smoke:py312-dummy-packages"
