"""Stage 2 and Stage 3: LLM interpretation of the shortlist and grounding check.

For each candidate from Stage 1 the LLM sees one smali method body and decides
whether it implements one of the listed malicious behaviors. It is never asked
to propose methods outside the shortlist. Every verdict must quote the API
calls it relies on; the grounding check then verifies each quoted reference
against the method body.

The prompt style, behavior descriptions and Ollama call follow the MalLoc
baseline so both systems can be compared under the same model. Method bodies
are read from an apktool tree, which avoids loading androguard a second time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import requests

from . import groundtruth

# Behavior descriptions, copied verbatim from MalLoc's config.py so that both
# systems are prompted with the same text.
BEHAVIOR_DESCRIPTIONS: dict[int, str] = {
    1: """Privacy Stealing - Methods that access or exfiltrate sensitive user data including:
(1) - Accessing Contact Lists – Retrieving the user's contact details from the device's storage.
(2) - Reading SMS Messages – Accessing and potentially forwarding SMS messages to external servers.
(3) - Collecting Location Data – Gathering precise GPS or network-based location information.
(4) - Extracting Phone Numbers – Accessing the device's phone number or identifiers such as IMEI and IMSI.
(5) - Harvesting Call Logs – Reading historical data on incoming, outgoing, or missed calls.
(6) - Intercepting Communications – Monitoring or manipulating SMS or call-based communication.
(7) - Exfiltrating User Data – Sending private information to external servers or networks.
Look for: Permission checks, content provider queries, telephony manager access, location services, file operations targeting private directories.""",
    2: """SMS/CALL Abuse - Methods that manipulate SMS and phone call functionality:
(1) - Sending SMS messages without user consent
(2) - Intercepting/blocking incoming SMS (especially 2FA messages)
(3) - Deleting SMS messages (to hide evidence)
(4) - Making calls without user awareness
(5) - Monitoring call logs
Look for: SMS manager operations, broadcast receivers for SMS/calls, telephony API usage, SMS deletion commands.""",
    6: """Accessibility Abuse - Methods exploiting accessibility services:
(1) - Accessibility service registration
(2) - Screen content monitoring
(3) - Automated UI interaction
(4) - Silent installation attempts
Example: TOASTAMIGO patterns
Look for: Accessibility service declarations, window content observers, automated click events.""",
    7: """Privilege Escalation - Methods attempting to gain elevated privileges:
(1) - Root exploit attempts
(2) - System file modifications
(3) - Admin privilege requests
(4) - Persistent privilege elevation
Examples: LIBSKIN (right_core.apk), ZNIU (Dirty COW)
Look for: Root checking, system file operations, privilege escalation exploits, admin rights requests.""",
    9: """Aggressive Advertising - Methods implementing malicious ad behavior:
(1) - Fake click generation (GhostClicker pattern)
(2) - Forced ad displays
(3) - Background ad loading
(4) - Click fraud implementation
Look for: dispatchTouchEvent abuse, ad library manipulation, screen overlay for ads, click simulation.""",
    11: """Tricky Behavior - Methods implementing evasion techniques:
(1) - Icon/label manipulation
(2) - App hiding mechanisms
(3) - Settings modification
(4) - False uninstall messages
Example: Maikspy error message pattern
Look for: Package visibility changes, settings modifications, fake error messages.""",
}

# Marker-line output format (no JSON), following MalLoc's prompts.
_SYSTEM_PRELUDE = (
    "You are an expert in Android malware analysis. A static-analysis "
    "pipeline has narrowed an Android app's methods down to a shortlist ranked "
    "by structural suspicion (distance to a sensitive API call, distance from "
    "an app entry point, cyclomatic complexity). One candidate method at a "
    "time, decide whether it implements one of the malicious behaviors listed "
    "below. Judge ONLY from the provided Smali method body — do not assume "
    "anything that is not present in the code, and do not propose methods "
    "outside the candidate under review. Do not call any behavior malicious "
    "without concrete Smali evidence in the method body itself."
)

# Smali extraction from an apktool tree

_METHOD_HEADER_RE = re.compile(
    r"\.method\s+(?:(?:public|private|protected|static|final|synthetic|"
    r"bridge|abstract|native|synchronized|declared-synchronized|"
    r"constructor|varargs)\s+)*([\w$-]+)\(([^)]*)\)(.+)$"
)


def locate_class_file(smali_root: Path, dex_classname: str) -> Path | None:
    """Finds the .smali file of a class such as 'Lorg/example/Foo;'.

    `smali_root` is an apktool output directory, which holds one `smali*`
    folder per dex file (`smali`, `smali_classes2`, ...).
    """
    rel = dex_classname[1:-1].replace(";", "") + ".smali"
    if smali_root.is_dir():
        for sub in smali_root.iterdir():
            if sub.is_dir() and sub.name.startswith("smali"):
                p = sub / rel
                if p.is_file():
                    return p
    return None


def extract_method_body(smali_text: str, methodname: str, descriptor: str) -> str | None:
    """Returns the '.method ... .end method' block for one method, or None.

    Overloads are told apart by descriptor, and access flags on the header line
    are ignored.
    """
    target = methodname + descriptor  # e.g. 'onCreateView(Landroid/view/View;)V'
    lines = smali_text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if not stripped.startswith(".method"):
            i += 1
            continue
        m = _METHOD_HEADER_RE.match(stripped)
        if not m:
            i += 1
            continue
        name, params, ret = m.group(1), m.group(2), m.group(3).strip()
        signature = name + "(" + params + ")" + ret
        start = i
        while i < n and not lines[i].strip().startswith(".end method"):
            i += 1
        block = "\n".join(lines[start : i + 1]) if i < n else "\n".join(lines[start:])
        if signature == target:
            return block
        i += 1
    return None


# Prompt construction

@dataclass
class Candidate:
    rank: int
    classname: str
    methodname: str
    descriptor: str
    suspicion_score: float
    dist_to_sensitive: float | None
    sensitive_category: str | None
    dist_from_entry: float | None
    entry_exported: bool
    cyclomatic_complexity: int | None
    # Filled in once the smali file has been located.
    smali_file: str | None = None
    method_body: str | None = None

    @property
    def signature(self) -> str:
        return f"{self.classname}->{self.methodname}{self.descriptor}"

    @classmethod
    def from_scores_row(cls, row: dict) -> "Candidate":
        return cls(
            rank=row["rank"],
            classname=row["classname"],
            methodname=row["methodname"],
            descriptor=row["descriptor"],
            suspicion_score=row["suspicion_score"],
            dist_to_sensitive=row["dist_to_sensitive"],
            sensitive_category=row["sensitive_category"],
            dist_from_entry=row["dist_from_entry"],
            entry_exported=row["entry_exported"],
            cyclomatic_complexity=row["cyclomatic_complexity"],
        )


def build_prompt(candidate: Candidate, behavior_ids: list[int]) -> str:
    """Builds the prompt for one candidate.

    It contains the behavior descriptions, the Stage 1 signals as context, and
    the method body, whose own `.method` header line is reused verbatim.
    """
    behavior_block = "\n\n".join(
        f"Behavior {b}:\n{BEHAVIOR_DESCRIPTIONS[b]}" for b in behavior_ids
    )

    structural = []
    if candidate.suspicion_score is not None:
        structural.append(f"suspicion score: {candidate.suspicion_score} (rank {candidate.rank})")
    if candidate.dist_to_sensitive is not None:
        structural.append(
            f"shortest distance to a sensitive API call: {candidate.dist_to_sensitive} hop(s)"
            + (f" (category: {candidate.sensitive_category})" if candidate.sensitive_category else "")
        )
    else:
        structural.append("shortest distance to a sensitive API call: unreachable")
    if candidate.dist_from_entry is not None:
        exported = ", exported" if candidate.entry_exported else ""
        structural.append(f"distance from an app entry point: {candidate.dist_from_entry} hop(s){exported}")
    else:
        structural.append("distance from an app entry point: unknown")
    if candidate.cyclomatic_complexity is not None:
        structural.append(f"cyclomatic complexity: {candidate.cyclomatic_complexity}")

    method_line = _first_header_line(candidate)

    prompt = f"""{_SYSTEM_PRELUDE}

Malicious behaviors (refer only to these; any method not clearly matching one of these three is BENIGN):

{behavior_block}

Candidate method (under review — decide only on THIS method, not the whole class):
CLASS: {candidate.classname}
METHOD: {method_line}

Structural signals from the static-analysis stage (context only, not proof of malice):
{chr(10).join('- ' + s for s in structural)}

Smali body of the candidate method:
{candidate.method_body}

IMPORTANT: For your answer, use the following format, nothing else — no markdown, no extra text:
IS_MALICIOUS: yes or no
BEHAVIOR_ID: 1, 9, 11, or none
CONFIDENCE: 0-100
EVIDENCE: quote, verbatim from the Smali body above, the exact API calls or instructions that justify your verdict (invoke-lines with the exact class->method names, e.g. "invoke-static {{v0}}, Ljava/lang/System;->currentTimeMillis()J"). If the evidence is not present verbatim in the body, write EVIDENCE: NONE
"""
    return prompt


def _first_header_line(candidate: Candidate) -> str:
    """Returns the method's own header line, or a flagless reconstruction."""
    if candidate.method_body:
        first = candidate.method_body.splitlines()[0].strip()
        if first.startswith(".method"):
            return first
    return f".method {candidate.methodname}{candidate.descriptor}"


# Ollama client

class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434",
                 model: str = "qwen2.5-coder:7b-instruct-q4_K_M", timeout: int = 300):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, temperature: float = 0.0) -> str:
        """Calls /api/generate without streaming.

        Temperature defaults to 0 so runs are repeatable. Only the
        self-consistency signal in calibration.py passes a higher value.
        """
        resp = requests.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False,
                  "options": {"temperature": temperature}},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


# Verdict parsing

_MAL_RE = re.compile(r"IS_MALICIOUS\s*:\s*(yes|no)", re.IGNORECASE)
_BEH_RE = re.compile(r"BEHAVIOR_ID\s*:\s*(\d+|none)\b", re.IGNORECASE)
_CONF_RE = re.compile(r"CONFIDENCE\s*:\s*(\d+)", re.IGNORECASE)
# The evidence field runs to the end of the response.
_EVID_RE = re.compile(r"EVIDENCE\s*:\s*(.*)", re.IGNORECASE | re.DOTALL)
_REF_RE = re.compile(r"L[\w/$]+;->[\w$]+")


def parse_verdict(raw: str) -> dict:
    """Parses a marker-format response.

    A response without the IS_MALICIOUS marker is returned with
    is_parseable=False instead of being given a default verdict.
    """
    malicious_match = _MAL_RE.search(raw)
    if not malicious_match:
        return {"is_parseable": False, "is_malicious": None, "behavior_id": None,
                "confidence": None, "evidence": None, "raw": raw}
    is_malicious = malicious_match.group(1).strip().lower() == "yes"
    behavior_match = _BEH_RE.search(raw)
    confidence_match = _CONF_RE.search(raw)
    evidence_match = _EVID_RE.search(raw)
    evidence = evidence_match.group(1).strip() if evidence_match else None
    return {
        "is_parseable": True,
        "is_malicious": is_malicious,
        "behavior_id": behavior_match.group(1).lower() if behavior_match else (None if not is_malicious else "unknown"),
        "confidence": int(confidence_match.group(1)) if confidence_match else None,
        "evidence": evidence,
        "raw": raw,
    }


def cited_api_refs(text: str | None) -> list[str]:
    """Returns the distinct 'Lclass;->method' references in an evidence string, in order."""
    if not text:
        return []
    seen: list[str] = []
    seen_set: set[str] = set()
    for m in _REF_RE.findall(text):
        if m not in seen_set:
            seen_set.add(m)
            seen.append(m)
    return seen


def grounding_check(candidate: Candidate, verdict: dict) -> dict:
    """Checks that every API reference cited as evidence appears in the method body.

    A reference that does not appear is reported as ungrounded.
    """
    refs = cited_api_refs(verdict.get("evidence"))
    body = candidate.method_body or ""
    grounded = [r for r in refs if r in body]
    ungrounded = [r for r in refs if r not in grounded]
    return {
        "cited_refs": refs,
        "grounded_refs": grounded,
        "ungrounded_refs": ungrounded,
        "grounded": len(ungrounded) == 0,
        "has_evidence": bool(refs),
    }


def load_candidates(scores_path: str | Path, top_pct: float = 0.05) -> list[Candidate]:
    with open(scores_path) as f:
        rows = json.load(f)
    count = max(1, round(len(rows) * top_pct))
    return [Candidate.from_scores_row(row) for row in rows[:count]]


def load_groundtruth(gt_path: str | Path) -> set[tuple[str, str, str]]:
    """Returns the ground-truth methods as (classname, methodname, descriptor) triples."""
    return {(m.classname, m.methodname, m.descriptor) for m in groundtruth.load_groundtruth(gt_path)}