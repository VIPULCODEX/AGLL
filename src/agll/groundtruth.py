"""Parses MalLoc's ground-truth JSON format (see
MalLoc/0_Data/APKs/MalApp_1_9_11_groundtruth.json) into (classname,
methodname, descriptor) triples comparable against AGLL's own MethodScore
records, for smoke-testing stage one against the one demo app this
environment has labels for. This is NOT the labelled MalRadar dataset
sub-objective 1.1 calls for — see PROGRESS.md."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_SIG_RE = re.compile(
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


def _parse_signature(sig: str) -> tuple[str, str] | None:
    m = _SIG_RE.search(sig.strip())
    if not m:
        return None
    name, params, ret = m.groups()
    return name, f"({params}){ret}"


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

        for methods_list in method_lists:
            for entry in methods_list:
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
