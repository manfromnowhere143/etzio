"""Generate the optional qualification closure as a CycloneDX 1.6 SBOM; no network."""

import hashlib
import json
from importlib.metadata import distribution
from itertools import product
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    pending = ["pyhanko", "pyhanko-certvalidator", "asn1crypto", "cryptography"]
    components = {}
    dependencies = {}
    for python_full_version, system in product(("3.11.15", "3.14.2"), ("Darwin", "Linux")):
        env = default_environment()
        env.update(
            python_version=python_full_version.rsplit(".", 1)[0],
            python_full_version=python_full_version,
            platform_system=system,
            sys_platform="darwin" if system == "Darwin" else "linux",
            extra="",
        )
        todo = list(pending)
        seen = set()
        while todo:
            name = canonicalize_name(todo.pop())
            if name in seen:
                continue
            seen.add(name)
            dist = distribution(name)
            ref = f"pkg:pypi/{name}@{dist.version}"
            license_label = (
                dist.metadata.get("License-Expression")
                or dist.metadata.get("License")
                or "See distribution license files"
            )
            if len(license_label) > 300:
                license_label = "See distribution license files"
            components[ref] = {
                "type": "library",
                "bom-ref": ref,
                "name": name,
                "version": dist.version,
                "purl": ref,
                "licenses": [{"license": {"name": license_label}}],
            }
            deps = set()
            for value in dist.requires or ():
                req = Requirement(value)
                if req.marker and not req.marker.evaluate(env):
                    continue
                child = canonicalize_name(req.name)
                c = distribution(child)
                deps.add(f"pkg:pypi/{child}@{c.version}")
                todo.append(child)
            dependencies.setdefault(ref, set()).update(deps)
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "etzio-native-time-offline-v1",
                "name": "Etzio offline native-time qualification",
                "version": "1",
            },
            "properties": [
                {
                    "name": "etzio:boundary",
                    "value": "Optional offline qualification closure; not production or binary provenance admission",
                },
                {
                    "name": "etzio:requirements-ci-lock-sha256",
                    "value": hashlib.sha256((root / "tools/ci/requirements-ci.lock").read_bytes()).hexdigest(),
                },
                {
                    "name": "etzio:dependency-markers",
                    "value": "Union of CPython 3.11/3.14 and macOS/Linux marker environments",
                },
            ],
        },
        "components": [components[k] for k in sorted(components)],
        "dependencies": [
            {
                "ref": "etzio-native-time-offline-v1",
                "dependsOn": [f"pkg:pypi/{n}@{distribution(n).version}" for n in sorted(pending)],
            }
        ]
        + [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(dependencies.items())],
    }
    (root / "tools/native-time/sbom.cdx.json").write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    print(f"{len(components)} dependency components retained in tools/native-time/sbom.cdx.json")


if __name__ == "__main__":
    main()
