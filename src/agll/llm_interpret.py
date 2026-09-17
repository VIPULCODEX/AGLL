"""
Stage-three: LLM interpretation of the structural candidate set (sub-objective
1.2). Input is the top-`pct`-of-rank candidates produced by stage one
(`suspicion.py` / `run_smoke_test.py`); for each candidate alone, the LLM
decides whether the method implements one of the three malicious behaviors
this app is ground-truthed against. "LLM only interprets what analysis
surfaces" — the LLM is never asked to propose methods outside the candidate
list, and is told so explicitly.

Everything here deliberately mirrors the conditions of the MalLoc baseline runs
(nnMalLoc/1_Code/ProgressiveAnalysisUtils.py`) so the end-to-end AGLL number
is comparable to MalLoc's full-app run (public/MalLoc/PROGRESS.md) on the same
model (`qwen2.5-coder:7b-instruct-q4_K_M` via Ollama):

  - same 3 behavior descriptions MalLoc feeds its prompts (copied verbatim
    from MalLoc/1_Code/config.py, behaviors 1/9/11);
  - same renderer (Ollama /api/generate) and marker-parseable output format;
  - raw smali method bodies as the code evidence, extracted from apktool
    output (MalLoc/0_Data/Validation) rather than androguard's decompiler,
    so the text handed to the LLM is byte-identical to what the ground-truth
    signatures were checked against.

The difference from MalLoc is the *gating*: MalLoc handed the LLM whole
classes (and, in the full-app run, screened all 99 classes); AGLL hands the
LLM only the structurally-narrowed shortlist, one method at a time. That is the
point of the comparison.

Anti-hallucination (this is where MalLoc's own reproduction caught a fabricated
signature — MalLoc/PROGRESS.md section 4.2): every verdict must carry an
EVIDENCE field quoting verbatim the smali invoke/API lines that justify it, and
the judge pass re-checks each cited reference against the actual smali text.

Smali method-body extraction is deliberately independent of androguard: the
structural JSON already pins each candidate to (classname, methodname,
descriptor), and the apktool tree already has every app class as text. Loading
androguard a second time (a ~2 minute wall-clock cost) buys nothing for the
interpretation stage.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import requests

# --- Behavior descriptions: copied verbatim from MalLoc/1_Code/config.py.
# --- Source is the MalLoc replication package being reproduced as a baseline
# --- (Objective 1.3); keeping the text identical makes the two prompt
# --- conditions comparable. Originally only 1/9/11 (the MalApp_1_9_11 demo
# --- app's 3 behaviors) were included here; 2 and 6 were added after a judge
# --- pass caught that SyntheticMalApp's ground truth uses categories
# --- {1, 2, 6, 11} but the synthetic run's prompt only offered {1, 9, 11} —
# --- see AGLL/PROGRESS.md JUDGE LOG, "prompt/fixture category mismatch".
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

# MalLoc's own prompt template style (marker lines, no free-form JSON) —
# see MalLoc/1_Code/ProgressiveAnalysisUtils.py. Kept for comparability and
# because it is what survived adversarial scrutiny in the baseline runs.
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

# ---------------------------------------------------------------------------
# Smali extraction (from the apktool tree used by the MalLoc reproduction).
# ---------------------------------------------------------------------------

_METHOD_HEADER_RE = re.compile(
    r"\.method\s+(?:(?:public|private|protected|static|final|synthetic|"
    r"bridge|abstract|native|synchronized|declared-synchronized|"
    r"constructor|varargs)\s+)*([\w$-]+)\(([^)]*)\)(.+)$"
)


def _find_smali_root(smali_roots: list[Path]) -> None:
    pass  # (helper contract only; actual search is in locate_class_file)


def locate_class_file(smali_root: Path, dex_classname: str) -> Path | None:
    """Map a dex class name ('Llu/snt/trux/koopaapp/ui/home/Foo;') to its
    .smali file under an apktool tree whose roots are `smali`,
    `smali_classes2`, ... (multi-dex)."""
    rel = dex_classname[1:-1].replace(";", "") + ".smali"
    if smali_root.is_dir():
        for sub in smali_root.iterdir():
            if sub.is_dir() and sub.name.startswith("smali"):
                p = sub / rel
                if p.is_file():
                    return p
    return None


def extract_method_body(smali_text: str, methodname: str, descriptor: str) -> str | None:
    """Return the full '.method ... .end method' block whose header parses to
    `methodname` + `descriptor` (descriptor normalized with no whitespace),
    or None. Handles overloads (later definitions scanned past) and access
    flags on the header line."""
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


# ---------------------------------------------------------------------------
# Prompt construction + LLM call (Ollama, same renderer MalLoc used).
# ---------------------------------------------------------------------------

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
    # populated during the run
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


def build_prompt(
    cand: Candidate,
    behavior_ids: list[int],
    activate_body_flag: bool = True,
) -> str:
    """One candidate method, its smali body, its structural signals, and the
    same three behavior descriptions MalLoc prompts with. The candidate's own
    `.method` header line is used verbatim (matches MalLoc Phase-2's
    "the first line of the method exactly as it appears in the Smali code"
    requirement)."""
    behavior_block = "\n\n".join(
        f"Behavior {b}:\n{BEHAVIOR_DESCRIPTIONS[b]}" for b in behavior_ids
    )

    sig_parts = []
    structural = []
    if cand.suspicion_score is not None:
        structural.append(f"suspicion score: {cand.suspicion_score} (rank {cand.rank})")
    if cand.dist_to_sensitive is not None:
        structural.append(
            f"shortest distance to a sensitive API call: {cand.dist_to_sensitive} hop(s)"
            + (f" (category: {cand.sensitive_category})" if cand.sensitive_category else "")
        )
    else:
        structural.append("shortest distance to a sensitive API call: unreachable")
    if cand.dist_from_entry is not None:
        exported = ", exported" if cand.entry_exported else ""
        structural.append(f"distance from an app entry point: {cand.dist_from_entry} hop(s){exported}")
    else:
        structural.append("distance from an app entry point: unknown")
    if cand.cyclomatic_complexity is not None:
        structural.append(f"cyclomatic complexity: {cand.cyclomatic_complexity}")

    method_line = _first_header_line(cand)

    prompt = f"""{_SYSTEM_PRELUDE}

Malicious behaviors (refer only to these; any method not clearly matching one of these three is BENIGN):

{behavior_block}

Candidate method (under review — decide only on THIS method, not the whole class):
CLASS: {cand.classname}
METHOD: {method_line}

Structural signals from the static-analysis stage (context only, not proof of malice):
{chr(10).join('- ' + s for s in structural)}

Smali body of the candidate method:
{cand.method_body}

IMPORTANT: For your answer, use the following format, nothing else — no markdown, no extra text:
IS_MALICIOUS: yes or no
BEHAVIOR_ID: 1, 9, 11, or none
CONFIDENCE: 0-100
EVIDENCE: quote, verbatim from the Smali body above, the exact API calls or instructions that justify your verdict (invoke-lines with the exact class->method names, e.g. "invoke-static {{v0}}, Ljava/lang/System;->currentTimeMillis()J"). If the evidence is not present verbatim in the body, write EVIDENCE: NONE
"""
    return prompt


def _first_header_line(cand: Candidate) -> str:
    """Best-effort reconstruction of the .method header line for the prompt,
    from the extracted body (the real smali header is always preferred; the
    fallback is a flagless reconstruction)."""
    if cand.method_body:
        first = cand.method_body.splitlines()[0].strip()
        if first.startswith(".method"):
            return first
    return f".method {cand.methodname}{cand.descriptor}"


# ---------------------------------------------------------------------------
# Ollama client (same pattern as MalLoc/1_Code/LLMUtils.py OllamaInterface).
# ---------------------------------------------------------------------------

class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:7b-instruct-q4_K_M", timeout: int = 300):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, temperature: float = 0.0) -> str:
        """/api/generate, stream disabled, temperature pinned to 0 by default
        for reproducibility (documented in PROGRESS.md — the MalLoc baseline
        calls were defaults; this difference is called out, not hidden).
        Objective 2's self-consistency signal (calibration.py) is the one
        caller that deliberately passes a nonzero temperature."""
        resp = requests.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False,
                  "options": {"temperature": temperature}},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


# ---------------------------------------------------------------------------
# Verdict parsing (marker format, like MalLoc's parse_marker_class_output).
# ---------------------------------------------------------------------------

_MAL_RE = re.compile(r"IS_MALICIOUS\s*:\s*(yes|no)", re.IGNORECASE)
_BEH_RE = re.compile(r"BEHAVIOR_ID\s*:\s*(\d+|none)\b", re.IGNORECASE)
_CONF_RE = re.compile(r"CONFIDENCE\s*:\s*(\d+)", re.IGNORECASE)
# Evidence conventionally spans the rest of the response (code fences,
# bulleted invoke lines, rationale), so DOTALL and capture-to-end.
_EVID_RE = re.compile(r"EVIDENCE\s*:\s*(.*)", re.IGNORECASE | re.DOTALL)
_REF_RE = re.compile(r"L[\w/$]+;->[\w$]+")


def parse_verdict(raw: str) -> dict:
    """Parse the marker-format response into {is_malicious, behavior_id,
    confidence, evidence}. Return is_parseable=False for outputs that lack the
    IS_MALICIOUS marker (these are surfaced to the judge, never silently
    defaulted)."""
    malicious_match = _MAL_RE.search(raw)
    if not malicious_match:
        return {"is_parseable": False, "is_malicious": None, "behavior_id": None,
                "confidence": None, "evidence": None, "raw": raw}
    is_malicious = malicious_match.group(1).strip().lower() == "yes"
    beh = _BEH_RE.search(raw)
    conf = _CONF_RE.search(raw)
    evid = _EVID_RE.search(raw)
    if evid:
        # Evidence conventionally spans the rest of the response (code
        # fences, bulleted invoke lines, rationale) — take the full capture.
        evidence = evid.group(1).strip()
    return {
        "is_parseable": True,
        "is_malicious": is_malicious,
        "behavior_id": beh.group(1).lower() if beh else (None if not is_malicious else "unknown"),
        "confidence": int(conf.group(1)) if conf and is_malicious else (int(conf.group(1)) if conf else None),
        "evidence": evidence,
        "raw": raw,
    }


def cited_api_refs(text: str | None) -> list[str]:
    """All class->method references mentioned in a free-text evidence field,
    for the judge's grounding check."""
    if not text:
        return []
    seen: list[str] = []
    seen_set: set[str] = set()
    for m in _REF_RE.findall(text):
        if m not in seen_set:
            seen_set.add(m)
            seen.append(m)
    return seen


def grounding_check(cand: Candidate, verdict: dict) -> dict:
    """Adversarial check on a malicious verdict: every class->method reference
    cited in EVIDENCE must literally appear in the smali body (or, for
    helper-method references, in the same class file). Any citation that does
    not appear is flagged as ungrounded — this is exactly where MalLoc's
    reproduction caught a hallucinated signature (PROGRESS.md sec 4.2)."""
    refs = cited_api_refs(verdict.get("evidence"))
    ground = [r for r in refs if r in (cand.method_body or "")]
    ungrounded = [r for r in refs if r not in ground]
    # Cross-check: BEHAVIOR_ID must be one of the behaviors if was_grounded
    return {
        "cited_refs": refs,
        "grounded_refs": ground,
        "ungrounded_refs": ungrounded,
        "grounded": len(ungrounded) == 0,
        "has_evidence": bool(refs),
    }


def load_candidates(scores_path: str | Path, top_pct: float = 0.05) -> list[Candidate]:
    with open(scores_path) as f:
        rows = json.load(f)
    n = max(1, round(len(rows) * top_pct))
    cands = [Candidate.from_scores_row(r) for r in rows[:n]]
    return cands


def load_groundtruth(gt_path: str | Path) -> set[tuple[str, str, str]]:
    """(classname, methodname, descriptor) triples, mirrored from
    groundtruth.load_groundtruth but keyed for the judge's FP/TP matching."""
    import sys
    from pathlib import Path as _P
    sys.path.insert(0, str(_P(__file__).resolve().parents[2] / "src"))
    from . import groundtruth as _gt
    return {(_g.classname, _g.methodname, _g.descriptor) for _g in _gt.load_groundtruth(gt_path)}