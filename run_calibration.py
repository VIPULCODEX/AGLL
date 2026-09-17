
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from agll import calibration, llm_interpret  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"

APPS = [
    dict(name="MalApp_1_9_11",
         scores="results/sample_gpu7b_stage1_scores.json",
         gt="../MalLoc/0_Data/APKs/MalApp_1_9_11_groundtruth.json",
         smali="../MalLoc/0_Data/Validation/MalApp_1_9_11",
         top_pct=0.05, behavior_ids=[1, 9, 11],
         interactions="results/sample_gpu7b_stage2_llm_interactions.json"),
    dict(name="SyntheticMalApp",
         scores="results/synthetic_stage1_scores.json",
         gt="../MalLoc/0_Data/APKs/SyntheticMalApp_groundtruth.json",
         smali="../MalLoc/0_Data/APKs/SyntheticMalApp_decompiled",
         top_pct=1.0, behavior_ids=[1, 2, 6, 11],
         interactions="results/synthetic_gpu7b_stage2_llm_interactions_fixedbehaviors.json"),
    dict(name="RealisticMalApp",
         scores="results/realistic_stage1_scores.json",
         gt="../MalLoc/0_Data/APKs/RealisticMalApp_groundtruth.json",
         smali="../MalLoc/0_Data/APKs/RealisticMalApp_decompiled",
         top_pct=0.50, behavior_ids=[1, 2, 7, 11],
         interactions="results/realistic_gpu7b_stage2_llm_interactions.json"),
]

SELF_CONSISTENCY_K = 2
SELF_CONSISTENCY_TEMP = 0.7
SECONDARY_MODEL = "qwen2.5:1.5b"

def load_candidates_with_bodies(scores_path, smali_root, top_pct):
    cands = llm_interpret.load_candidates(Path(scores_path), top_pct=top_pct)
    for c in cands:
        f = llm_interpret.locate_class_file(Path(smali_root), c.classname)
        c.smali_file = str(f) if f else None
        if f:
            c.method_body = llm_interpret.extract_method_body(
                f.read_text(encoding="utf-8", errors="replace"), c.methodname, c.descriptor)
    return cands

def main():
    client_primary = llm_interpret.OllamaClient(model="qwen2.5-coder:7b-instruct-q4_K_M", timeout=120)
    client_secondary = llm_interpret.OllamaClient(model=SECONDARY_MODEL, timeout=90)

    # First pass: self-consistency (primary model)
    detail = []
    if (RESULTS_DIR / "calibration_detail.json").is_file():
        with open(RESULTS_DIR / "calibration_detail.json") as f:
            detail = json.load(f)

    done_sc = {(d["app"], d["rank"]): d for d in detail if "c_sc" in d}
    
    t_start = time.time()
    
    all_eligible = []
    
    for app in APPS:
        cands = load_candidates_with_bodies(app["scores"], app["smali"], app["top_pct"])
        gt = llm_interpret.load_groundtruth(Path(app["gt"]))
        with open(app["interactions"]) as f:
            interactions = {i["rank"]: i for i in json.load(f)}

        for c in cands:
            if not c.method_body: continue
            inter = interactions.get(c.rank)
            if not inter or inter.get("error") or not inter.get("raw_response"): continue
            primary = llm_interpret.parse_verdict(inter["raw_response"])
            if not primary["is_parseable"]: continue
            
            is_gt = (c.classname, c.methodname, c.descriptor) in gt
            predicted_malicious = primary["is_malicious"]
            correct = 1 if predicted_malicious == is_gt else 0
            all_eligible.append((app, c, primary, is_gt, predicted_malicious, correct))

    print(f"Total {len(all_eligible)} eligible candidates across apps.")
    
    print("--- Phase 1: Self Consistency (Primary Model) ---")
    new_detail = []
    for app, c, primary, is_gt, predicted_malicious, correct in all_eligible:
        key = (app["name"], c.rank)
        if key in done_sc and "c_sc" in done_sc[key] and "sub_verdicts" in done_sc[key]:
            d = done_sc[key]
            new_detail.append(d)
            continue
            
        t0 = time.time()
        try:
            c_sc, sub_verdicts = calibration.self_consistency(
                client_primary, c, app["behavior_ids"], predicted_malicious,
                k=SELF_CONSISTENCY_K, temperature=SELF_CONSISTENCY_TEMP)
        except Exception as e:
            print(f"    [SC Timeout/Error] {e}")
            c_sc, sub_verdicts = 0.0, [{"is_parseable": False, "is_malicious": False}]

        elapsed = time.time() - t0
        print(f"{app['name']} rank {c.rank:3d} c_sc={c_sc:.2f} ({elapsed:.1f}s)", flush=True)
        
        d = {
            "app": app["name"], "rank": c.rank, "signature": c.signature,
            "predicted_malicious": predicted_malicious, "in_gt": is_gt, "correct": correct,
            "c_sc": round(c_sc, 4), "sub_verdicts": sub_verdicts,
            "c_pa": round(calibration.program_analysis_consistency(c, primary), 4)
        }
        new_detail.append(d)
        with open(RESULTS_DIR / "calibration_detail.json", "w") as f:
            json.dump(new_detail, f, indent=2)
            
    print("--- Phase 2: Ensemble (Secondary Model) ---")
    done_ens = {(d["app"], d["rank"]): d for d in new_detail
                if "c_ens" in d or d.get("c_ens_unavailable")}
    for app, c, primary, is_gt, predicted_malicious, correct in all_eligible:
        key = (app["name"], c.rank)
        if key in done_ens:
            continue

        t0 = time.time()
        try:
            c_ens, ens_verdict = calibration.ensemble_disagreement(
                client_secondary, c, app["behavior_ids"], predicted_malicious)
            elapsed = time.time() - t0
            print(f"{app['name']} rank {c.rank:3d} c_ens={c_ens:.2f} ({elapsed:.1f}s)", flush=True)
            for d in new_detail:
                if d["app"] == app["name"] and d["rank"] == c.rank:
                    d["c_ens"] = round(c_ens, 4)
                    d["ensemble_verdict"] = ens_verdict.get("is_malicious")
                    break
        except Exception as e:
            elapsed = time.time() - t0
            print(f"{app['name']} rank {c.rank:3d} c_ens FAILED ({type(e).__name__}) "
                  f"after {elapsed:.1f}s - marking unavailable, continuing", flush=True)
            for d in new_detail:
                if d["app"] == app["name"] and d["rank"] == c.rank:
                    d["c_ens_unavailable"] = True
                    d["c_ens_error"] = f"{type(e).__name__}: {e}"
                    break
        with open(RESULTS_DIR / "calibration_detail.json", "w") as f:
            json.dump(new_detail, f, indent=2)
            
    print("--- Phase 3: Final signal fusion ---")
    all_features = []
    excluded_unavailable = []
    for app, c, primary, is_gt, predicted_malicious, correct in all_eligible:
        d = [d for d in new_detail if d["app"] == app["name"] and d["rank"] == c.rank][0]
        if "c_ens" not in d:
            # Ensemble call never succeeded (marked c_ens_unavailable in Phase 2) -
            # excluded from the fitted/reported set rather than imputed, so the
            # calibration numbers reflect only candidates where all 4 real signals
            # were actually computed. Recorded, not silently dropped.
            excluded_unavailable.append(d["signature"])
            continue
        h_sem, h_max = calibration.semantic_entropy([primary] + d["sub_verdicts"])
        d["h_sem"] = round(h_sem, 4)
        d["h_max"] = round(h_max, 4)

        feat = calibration.CalibrationFeatures(
            signature=d["signature"], app=d["app"], c_sc=d["c_sc"], h_sem=d["h_sem"], h_max=d["h_max"],
            c_ens=d["c_ens"], c_pa=d["c_pa"], predicted_malicious=d["predicted_malicious"],
            in_gt=d["in_gt"], correct=d["correct"]
        )
        all_features.append(feat)

    if excluded_unavailable:
        print(f"\nExcluded {len(excluded_unavailable)} candidate(s) with a failed "
              f"ensemble call (c_ens unavailable) from the fitted set:")
        for sig in excluded_unavailable:
            print(f"  - {sig}")

    total_elapsed = time.time() - t_start
    print(f"\nAll signals computed in {total_elapsed/60:.1f} min.")

    n_correct = sum(f.correct for f in all_features)
    print(f"Label balance: {n_correct}/{len(all_features)} correct")

    if len(set(f.correct for f in all_features)) < 2:
        with open(RESULTS_DIR / "calibration_results.json", "w") as f:
            json.dump({"fit": None, "detail": new_detail}, f, indent=2)
        return

    weights, clf = calibration.fit_logistic(all_features)
    print(f"\nFitted logistic weights (w0..w4): w0={weights[0]:.4f} w1={weights[1]:.4f} w2={weights[2]:.4f} w3={weights[3]:.4f} w4={weights[4]:.4f}")

    pairs = [(calibration.calibrated_confidence(f, weights), f.correct) for f in all_features]
    ece = calibration.expected_calibration_error(pairs, n_bins=5)
    print(f"Expected Calibration Error: {ece:.4f}")

    sweep = []
    for c_fa, c_fr in [(1, 1), (2, 1), (5, 1), (10, 1), (20, 1)]:
        tau = calibration.elkan_threshold(c_fa, c_fr)
        accepted = [(p, y) for p, y in pairs if p >= tau]
        coverage = len(accepted) / len(pairs)
        acc = (sum(y for _, y in accepted) / len(accepted)) if accepted else float("nan")
        sweep.append({"c_fa": c_fa, "c_fr": c_fr, "tau": tau, "coverage": coverage, "accuracy_among_accepted": acc})
        print(f"C_FA:{c_fa} C_FR:{c_fr} tau*={tau:.3f} cov={coverage:.3f} acc={acc:.3f}")

    out = {
        "n_candidates": len(all_features), "n_correct": n_correct,
        "weights": {"w0": weights[0], "w1_c_sc": weights[1], "w2_c_sem": weights[2], "w3_c_ens": weights[3], "w4_c_pa": weights[4]},
        "ece_5bin": ece, "elkan_sweep": sweep,
    }
    with open(RESULTS_DIR / "calibration_results.json", "w") as f:
        json.dump({"summary": out, "detail": new_detail}, f, indent=2)
    print("Done")

if __name__ == '__main__':
    main()
