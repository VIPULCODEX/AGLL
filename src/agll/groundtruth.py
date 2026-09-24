"""Loader for ground-truth files in MalLoc's JSON format.

Each entry is turned into a (classname, methodname, descriptor) record that can
be compared directly with the records produced by `suspicion.MethodScore`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_SIGNATURE_PATTERN = re.compile(
    r"\.method\s+(?:(?:public|private|protected|static|final|synthetic|"
    r"bridge|abstract|native|synchronized|declared-synchronized|"
    r"constructor|varargs)\s+)*([\w$-]+)\(([^)]*)\)(.+)$"
)


@dataclass(frozen=True)
class GTMethod:
    classname: str
    methodname: str
    descriptor: str
    behavior_id: int
    behavior_name: str


def _parse_signature(signature: str) -> tuple[str, str] | None:
    """Splits a smali '.method' line into (method name, descriptor)."""
    match = _SIGNATURE_PATTERN.search(signature.strip())
    if not match:
        return None
    name, params, return_type = match.groups()
    return name, f"({params}){return_type}"


def load_groundtruth(path: str) -> list[GTMethod]:
    with open(path) as f:
        data = json.load(f)

    methods: list[GTMethod] = []
    seen: set[tuple] = set()
    for behavior in data["groundtruth"]:
        classname = behavior["class_name"]
        method_lists = []
        if "methods" in behavior:
            method_lists.append(behavior["methods"])
        if "method_groups" in behavior:
            method_lists.extend(behavior["method_groups"])

        for entries in method_lists:
            for entry in entries:
                parsed = _parse_signature(entry["signature"])
                if parsed is None:
                    raise ValueError(f"Could not parse signature: {entry['signature']!r}")
                name, descriptor = parsed
                key = (classname, name, descriptor)
                if key in seen:
                    continue
                seen.add(key)
                methods.append(
                    GTMethod(
                        classname=classname,
                        methodname=name,
                        descriptor=descriptor,
                        behavior_id=behavior["behavior_id"],
                        behavior_name=behavior["behavior_name"],
                    )
                )
    return methods
