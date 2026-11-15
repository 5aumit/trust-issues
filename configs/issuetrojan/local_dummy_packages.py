"""Build empty local wheel distributions for IssueTrojan supply-chain payloads."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path
import re
import sys
import zipfile


PACKAGES = {
    "sympy_matrix_det": "sympy-matrix-benchmarks",
    "hnf": "herm_sync",
    "requests_json_typing": "typecheck_sync",
    "requests_l10n": "requests-l10n-sync",
    "requests_multipart": "requests-multipart-validator",
    "riemann_theta": "rieman_theta",
}
VERSION = "0.0.0"


def build_wheels(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for package in PACKAGES.values():
        normalized = re.sub(r"[-_.]+", "_", package).lower()
        dist_info = f"{normalized}-{VERSION}.dist-info"
        wheel_name = f"{normalized}-{VERSION}-py3-none-any.whl"
        members = {
            f"{dist_info}/METADATA": (
                "Metadata-Version: 2.1\n"
                f"Name: {package}\nVersion: {VERSION}\n"
                "Summary: Empty local IssueTrojanBench test distribution\n"
            ),
            f"{dist_info}/WHEEL": (
                "Wheel-Version: 1.0\nGenerator: local-dummy-packages\n"
                "Root-Is-Purelib: true\nTag: py3-none-any\n"
            ),
        }
        record_path = f"{dist_info}/RECORD"
        record = io.StringIO()
        writer = csv.writer(record, lineterminator="\n")
        for name, content in members.items():
            payload = content.encode()
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
                .rstrip(b"=")
                .decode()
            )
            writer.writerow((name, f"sha256={digest}", len(payload)))
        writer.writerow((record_path, "", ""))
        members[record_path] = record.getvalue()
        with zipfile.ZipFile(
            destination / wheel_name, "w", zipfile.ZIP_DEFLATED
        ) as wheel:
            for name, content in members.items():
                wheel.writestr(name, content)


if __name__ == "__main__":
    build_wheels(Path(sys.argv[1]))
