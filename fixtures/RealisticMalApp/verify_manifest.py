#!/usr/bin/env python3
"""Validate the frozen-before-inference source-level fixture manifest."""
import json
from pathlib import Path

root = Path(__file__).parent
manifest = json.loads((root / "ground_truth_manifest.json").read_text())
errors = []
payload = [m for m in manifest["methods"] if m["role"] == "payload-model"]
if len(payload) != 8:
    errors.append(f"expected 8 payload methods, found {len(payload)}")
if {m["category_id"] for m in payload} != {1, 2, 7, 11}:
    errors.append("payload categories must be exactly 1, 2, 7, 11")
for item in manifest["methods"]:
    cls = item["class"].rsplit(".", 1)[-1]
    method = item["method"].split("(", 1)[0]
    source = root / "app/src/main/java/org/research/realisticmalapp" / f"{cls}.java"
    if not source.exists() or method not in source.read_text():
        errors.append(f"unresolved source method: {item['class']}.{item['method']}")
    if not item.get("dex_descriptor", "").startswith("Lorg/research/realisticmalapp/"):
        errors.append(f"missing or invalid descriptor: {item['class']}.{item['method']}")
text = (root / "app/src/main/AndroidManifest.xml").read_text()
for forbidden in ("READ_SMS", "RECEIVE_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE", "INTERNET"):
    if forbidden in text:
        errors.append(f"forbidden capability declared: {forbidden}")
if errors:
    raise SystemExit("FAILED\n- " + "\n- ".join(errors))
print(f"OK: {len(payload)} payload models across 4 categories; no forbidden manifest capabilities.")
