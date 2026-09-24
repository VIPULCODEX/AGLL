#!/usr/bin/env python3
"""Compute the four confidence signals for every Stage 2 verdict and fit the fusion model.

Run from the repository root; paths in APPS are relative to it. The script is
resumable: signals already stored in results/calibration_detail.json are reused,
so an interrupted run continues where it stopped. With all signals present it
only refits the model, which needs no LLM.

Phases:
  1. self-consistency (k extra samples from the primary model) and c_pa,
  2. ensemble agreement from a second, smaller model,
  3. fusion: logistic fit, ECE, and the Elkan threshold sweep.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from agll import calibration, llm_interpret  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"
DETAIL_PATH = RESULTS_DIR / "calibration_detail.json"

# The ground-truth and smali paths point into a MalLoc checkout placed next to
# this repository (see README).
APPS = [
    dict(name="MalApp_1_9_11",
         scores="results/malapp_stage1_scores.json",
         gt="../MalLoc/0_Data/APKs/MalApp_1_9_11_groundtruth.json",
         smali="../MalLoc/0_Data/Validation/MalApp_1_9_11",
         top_pct=0.05, behavior_ids=[1, 9, 11],
         interactions="results/malapp_stage2_interactions.json"),
    dict(name="SyntheticMalApp",
         scores="results/synthetic_stage1_scores.json",
         gt="../MalLoc/0_Data/APKs/SyntheticMalApp_groundtruth.json",
         smali="../MalLoc/0_Data/APKs/SyntheticMalApp_decompiled",
         top_pct=1.0, behavior_ids=[1, 2, 6, 11],
         interactions="results/synthetic_stage2_interactions.json"),
    dict(name="RealisticMalApp",
         scores="results/realistic_stage1_scores.json",
         gt="../MalLoc/0_Data/APKs/RealisticMalApp_groundtruth.json",
         smali="../MalLoc/0_Data/APKs/RealisticMalApp_decompiled",
         top_pct=0.50, behavior_ids=[1, 2, 7, 11],
         interactions="results/realistic_stage2_interactions.json"),
]

PRIMARY_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
SECONDARY_MODEL = "qwen2.5:1.5b"
SELF_CONSISTENCY_K = 2
SELF_CONSISTENCY_TEMPERATURE = 0.7
COST_RATIOS = [(1, 1), (2, 1), (5, 1), (10, 1), (20, 1)]  # (C_FA, C_FR)


def load_candidates_with_bodies(scores_path, smali_root, top_pct):
    candidates = llm_interpret.load_candidates(Path(scores_path), top_pct=top_pct)
    for candidate in candidates:
        smali_path = llm_interpret.locate_class_file(Path(smali_root), candidate.classname)
        candidate.smali_file = str(smali_path) if smali_path else None
        if smali_path:
            smali_text = smali_path.read_text(encoding="utf-8", errors="replace")
            candidate.method_body = llm_interpret.extract_method_body(
                smali_text, candidate.methodname, candidate.descriptor)
    return candidates


def collect_eligible_candidates():
    """Returns (app, candidate, primary verdict, in_gt, predicted_malicious, correct) tuples.

    A candidate is eligible if it has a method body and a parseable Stage 2 verdict.
    """
    eligible = []
    for app in APPS:
        candidates = load_candidates_with_bodies(app["scores"], app["smali"], app["top_pct"])
        ground_truth = llm_interpret.load_groundtruth(Path(app["gt"]))
        with open(app["interactions"]) as f:
            interactions = {i["rank"]: i for i in json.load(f)}

        for candidate in candidates:
            if not candidate.method_body:
                continue
            interaction = interactions.get(candidate.rank)
            if not interaction or interaction.get("error") or not interaction.get("raw_response"):
                continue
            primary = llm_interpret.parse_verdict(interaction["raw_response"])
            if not primary["is_parseable"]:
                continue
            in_gt = (candidate.classname, candidate.methodname, candidate.descriptor) in ground_truth
            predicted_malicious = primary["is_malicious"]
            correct = 1 if predicted_malicious == in_gt else 0
            eligible.append((app, candidate, primary, in_gt, predicted_malicious, correct))
    return eligible


def save_detail(detail) -> None:
    with open(DETAIL_PATH, "w") as f:
        json.dump(detail, f, indent=2)


def find_detail(detail, app_name, rank):
    return next(d for d in detail if d["app"] == app_name and d["rank"] == rank)


def run_self_consistency(eligible, previous):
    """Phase 1: returns one detail record per eligible candidate."""
    client = llm_interpret.OllamaClient(model=PRIMARY_MODEL, timeout=120)
    done = {(d["app"], d["rank"]): d for d in previous if "c_sc" in d and "sub_verdicts" in d}
    detail = []
    for app, candidate, primary, in_gt, predicted_malicious, correct in eligible:
        key = (app["name"], candidate.rank)
        if key in done:
            detail.append(done[key])
            continue

        started = time.time()
        try:
            c_sc, sub_verdicts = calibration.self_consistency(
                client, candidate, app["behavior_ids"], predicted_malicious,
                k=SELF_CONSISTENCY_K, temperature=SELF_CONSISTENCY_TEMPERATURE)
        except Exception as error:
            print(f"    self-consistency call failed: {error}")
            c_sc, sub_verdicts = 0.0, [{"is_parseable": False, "is_malicious": False}]
        print(f"{app['name']} rank {candidate.rank:3d} c_sc={c_sc:.2f} "
              f"({time.time() - started:.1f}s)", flush=True)

        detail.append({
            "app": app["name"], "rank": candidate.rank, "signature": candidate.signature,
            "predicted_malicious": predicted_malicious, "in_gt": in_gt, "correct": correct,
            "c_sc": round(c_sc, 4), "sub_verdicts": sub_verdicts,
            "c_pa": round(calibration.program_analysis_consistency(candidate, primary), 4),
        })
        save_detail(detail)
    return detail


def run_ensemble(eligible, detail):
    """Phase 2: adds c_ens to each record; a failed call is marked unavailable."""
    client = llm_interpret.OllamaClient(model=SECONDARY_MODEL, timeout=90)
    done = {(d["app"], d["rank"]) for d in detail if "c_ens" in d or d.get("c_ens_unavailable")}
    for app, candidate, _, _, predicted_malicious, _ in eligible:
        if (app["name"], candidate.rank) in done:
            continue

        started = time.time()
        record = find_detail(detail, app["name"], candidate.rank)
        try:
            c_ens, verdict = calibration.ensemble_disagreement(
                client, candidate, app["behavior_ids"], predicted_malicious)
            print(f"{app['name']} rank {candidate.rank:3d} c_ens={c_ens:.2f} "
                  f"({time.time() - started:.1f}s)", flush=True)
            record["c_ens"] = round(c_ens, 4)
            record["ensemble_verdict"] = verdict.get("is_malicious")
        except Exception as error:
            print(f"{app['name']} rank {candidate.rank:3d} c_ens failed "
                  f"({type(error).__name__}) after {time.time() - started:.1f}s; "
                  f"marked unavailable", flush=True)
            record["c_ens_unavailable"] = True
            record["c_ens_error"] = f"{type(error).__name__}: {error}"
        save_detail(detail)


def build_features(eligible, detail):
    """Phase 3a: entropy signals and feature records for candidates with all four signals."""
    features = []
    excluded = []
    for app, candidate, primary, _, _, _ in eligible:
        record = find_detail(detail, app["name"], candidate.rank)
        if "c_ens" not in record:
            # No ensemble result: leave the candidate out rather than impute it.
            excluded.append(record["signature"])
            continue
        h_sem, h_max = calibration.semantic_entropy([primary] + record["sub_verdicts"])
        record["h_sem"] = round(h_sem, 4)
        record["h_max"] = round(h_max, 4)
        features.append(calibration.CalibrationFeatures(
            signature=record["signature"], app=record["app"], c_sc=record["c_sc"],
            h_sem=record["h_sem"], h_max=record["h_max"], c_ens=record["c_ens"],
            c_pa=record["c_pa"], predicted_malicious=record["predicted_malicious"],
            in_gt=record["in_gt"], correct=record["correct"]))
    return features, excluded


def fit_and_report(features, detail) -> None:
    n_correct = sum(f.correct for f in features)
    print(f"Label balance: {n_correct}/{len(features)} correct")

    if len({f.correct for f in features}) < 2:
        with open(RESULTS_DIR / "calibration_results.json", "w") as f:
            json.dump({"fit": None, "detail": detail}, f, indent=2)
        return

    weights, _ = calibration.fit_logistic(features)
    print("\nFitted logistic weights: " + " ".join(f"w{i}={w:.4f}" for i, w in enumerate(weights)))

    pairs = [(calibration.calibrated_confidence(f, weights), f.correct) for f in features]
    ece = calibration.expected_calibration_error(pairs, n_bins=5)
    print(f"Expected calibration error (5 bins): {ece:.4f}")

    sweep = []
    for cost_fa, cost_fr in COST_RATIOS:
        tau = calibration.elkan_threshold(cost_fa, cost_fr)
        accepted = [(p, y) for p, y in pairs if p >= tau]
        coverage = len(accepted) / len(pairs)
        accuracy = sum(y for _, y in accepted) / len(accepted) if accepted else float("nan")
        sweep.append({"c_fa": cost_fa, "c_fr": cost_fr, "tau": tau,
                      "coverage": coverage, "accuracy_among_accepted": accuracy})
        print(f"C_FA:{cost_fa} C_FR:{cost_fr} tau*={tau:.3f} cov={coverage:.3f} acc={accuracy:.3f}")

    summary = {
        "n_candidates": len(features), "n_correct": n_correct,
        "weights": {"w0": weights[0], "w1_c_sc": weights[1], "w2_c_sem": weights[2],
                    "w3_c_ens": weights[3], "w4_c_pa": weights[4]},
        "ece_5bin": ece, "elkan_sweep": sweep,
    }
    with open(RESULTS_DIR / "calibration_results.json", "w") as f:
        json.dump({"summary": summary, "detail": detail}, f, indent=2)


def main():
    started = time.time()
    previous = []
    if DETAIL_PATH.is_file():
        with open(DETAIL_PATH) as f:
            previous = json.load(f)

    eligible = collect_eligible_candidates()
    print(f"{len(eligible)} eligible candidates across all apps.")

    print("--- Phase 1: self-consistency (primary model) ---")
    detail = run_self_consistency(eligible, previous)
    print("--- Phase 2: ensemble agreement (secondary model) ---")
    run_ensemble(eligible, detail)

    print("--- Phase 3: signal fusion ---")
    features, excluded = build_features(eligible, detail)
    if excluded:
        print(f"\nExcluded {len(excluded)} candidate(s) without an ensemble result:")
        for signature in excluded:
            print(f"  - {signature}")
    print(f"\nAll signals computed in {(time.time() - started) / 60:.1f} min.")
    fit_and_report(features, detail)
    print("Done")


if __name__ == "__main__":
    main()
