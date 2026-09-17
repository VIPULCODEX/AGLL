#!/usr/bin/env python3
"""
Stage-1 weight ablation, deferred since the pipeline was first built and
flagged as overdue in PROGRESS.md's KNOWN ISSUES / IN PROGRESS sections for
every entry since. Now that all 3 apps have cached stage-1 scores (with the
raw per-method signals, not just the final score), this recomputes the
suspicion score under a grid of alternative weight combinations WITHOUT
re-running androguard, and reports recall/precision at fixed cuts for each
combination across all 3 apps.

Usage: python3 weight_ablation.py
"""

import itertools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from agll import groundtruth  # noqa: E402

APPS = [
    ("MalApp_1_9_11", "results/sample_gpu7b_stage1_scores.json",
     "../MalLoc/0_Data/APKs/MalApp_1_9_11_groundtruth.json"),
    ("SyntheticMalApp", "results/synthetic_stage1_scores.json",
     "../MalLoc/0_Data/APKs/SyntheticMalApp_groundtruth.json"),
    ("RealisticMalApp", "results/realistic_stage1_scores.json",
     "../MalLoc/0_Data/APKs/RealisticMalApp_groundtruth.json"),
]

# The default, currently-in-production weights (suspicion.py MethodScore).
DEFAULT = {"w_sink": 0.5, "w_entry": 0.3, "w_cfg": 0.2, "decay_scale": 3.0}

CUTS = (0.05, 0.10, 0.20, 0.50)


def decay(d, scale):
    if d is None:
        return 0.0
    return 1.0 / (1.0 + d / scale)


def score_method(m, w_sink, w_entry, w_cfg, decay_scale):
    s_sink = decay(m["dist_to_sensitive"], decay_scale)
    s_entry = decay(m["dist_from_entry"], decay_scale) * (1.0 if m["entry_exported"] else 0.6)
    cc = m["cyclomatic_complexity"] or 0
    s_cfg = min(cc / 15.0, 1.0)
    return w_sink * s_sink + w_entry * s_entry + w_cfg * s_cfg


def load_app(scores_path, gt_path):
    with open(scores_path) as f:
        methods = json.load(f)
    gt = groundtruth.load_groundtruth(gt_path)
    gt_keys = {(g.classname, g.methodname, g.descriptor) for g in gt}
    return methods, gt_keys


def evaluate(methods, gt_keys, w_sink, w_entry, w_cfg, decay_scale):
    scored = [(score_method(m, w_sink, w_entry, w_cfg, decay_scale), m) for m in methods]
    scored.sort(key=lambda x: x[0], reverse=True)
    keys_in_order = [(m["classname"], m["methodname"], m["descriptor"]) for _, m in scored]
    total = len(keys_in_order)
    out = {}
    for cut in CUTS:
        n = max(1, round(total * cut))
        top = set(keys_in_order[:n])
        tp = len(gt_keys & top)
        recall = tp / len(gt_keys) if gt_keys else 0.0
        precision = tp / n if n else 0.0
        out[cut] = (recall, precision, n)
    return out


def mean_recall_at(results_by_app, cut):
    vals = [results_by_app[app][cut][0] for app in results_by_app]
    return sum(vals) / len(vals)


def main():
    apps_data = {}
    for name, scores_path, gt_path in APPS:
        methods, gt_keys = load_app(scores_path, gt_path)
        apps_data[name] = (methods, gt_keys)
        print(f"Loaded {name}: {len(methods)} methods, {len(gt_keys)} GT methods")

    # --- 1. Confirm the default reproduces the numbers already on record. ---
    print("\n=== Sanity check: does recomputing from cached raw signals match the "
          "already-published numbers for the DEFAULT weights? ===")
    default_by_app = {}
    for name, (methods, gt_keys) in apps_data.items():
        default_by_app[name] = evaluate(methods, gt_keys, **DEFAULT)
        row = default_by_app[name]
        print(f"  {name}: " + ", ".join(
            f"top{int(c*100)}%=R{row[c][0]:.2f}/P{row[c][1]:.2f}" for c in CUTS))

    # --- 2. Grid search. ---
    weight_combos = []
    for w_sink in (0.3, 0.4, 0.5, 0.6, 0.7):
        for w_entry in (0.1, 0.2, 0.3, 0.4, 0.5):
            w_cfg = round(1.0 - w_sink - w_entry, 4)
            if w_cfg < 0 or w_cfg > 1:
                continue
            weight_combos.append((w_sink, w_entry, w_cfg))
    decay_scales = (2.0, 3.0, 5.0)

    print(f"\n=== Grid search: {len(weight_combos)} weight combos x "
          f"{len(decay_scales)} decay scales = "
          f"{len(weight_combos) * len(decay_scales)} configurations ===")

    results = []
    for (w_sink, w_entry, w_cfg), scale in itertools.product(weight_combos, decay_scales):
        by_app = {}
        for name, (methods, gt_keys) in apps_data.items():
            by_app[name] = evaluate(methods, gt_keys, w_sink, w_entry, w_cfg, scale)
        # Primary criterion: mean recall at top-20% across the 3 apps (the
        # cut where all 3 apps have a non-degenerate, non-trivial candidate
        # count). Tie-break: mean precision at top-20%.
        mean_r20 = mean_recall_at(by_app, 0.20)
        mean_p20 = sum(by_app[a][0.20][1] for a in by_app) / len(by_app)
        results.append({
            "w_sink": w_sink, "w_entry": w_entry, "w_cfg": w_cfg, "decay_scale": scale,
            "mean_recall_20": round(mean_r20, 4), "mean_precision_20": round(mean_p20, 4),
            "by_app": by_app,
        })

    results.sort(key=lambda r: (r["mean_recall_20"], r["mean_precision_20"]), reverse=True)

    default_mean_r20 = mean_recall_at(default_by_app, 0.20)
    default_mean_p20 = sum(default_by_app[a][0.20][1] for a in default_by_app) / len(default_by_app)
    print(f"\nDefault weights (0.5/0.3/0.2, scale=3): "
          f"mean recall@20%={default_mean_r20:.4f}, mean precision@20%={default_mean_p20:.4f}")

    print("\nTop 10 configurations by mean recall@20% (tie-break: mean precision@20%):")
    print(f"{'w_sink':>7} {'w_entry':>8} {'w_cfg':>6} {'scale':>6} {'mean_R@20':>10} {'mean_P@20':>10}")
    for r in results[:10]:
        print(f"{r['w_sink']:7.2f} {r['w_entry']:8.2f} {r['w_cfg']:6.2f} {r['decay_scale']:6.1f} "
              f"{r['mean_recall_20']:10.4f} {r['mean_precision_20']:10.4f}")

    best = results[0]
    print(f"\nBest by mean recall@20%: w_sink={best['w_sink']}, w_entry={best['w_entry']}, "
          f"w_cfg={best['w_cfg']}, decay_scale={best['decay_scale']}")
    print("Per-app detail for the best configuration:")
    for name in apps_data:
        row = best["by_app"][name]
        print(f"  {name}: " + ", ".join(
            f"top{int(c*100)}%=R{row[c][0]:.2f}/P{row[c][1]:.2f}" for c in CUTS))

    out_path = Path("results/weight_ablation_results.json")
    with open(out_path, "w") as f:
        json.dump({
            "default": {"weights": DEFAULT, "by_app": {
                a: {str(c): v for c, v in default_by_app[a].items()} for a in default_by_app
            }, "mean_recall_20": default_mean_r20, "mean_precision_20": default_mean_p20},
            "grid_top10": [
                {**{k: r[k] for k in ("w_sink", "w_entry", "w_cfg", "decay_scale",
                                       "mean_recall_20", "mean_precision_20")},
                 "by_app": {a: {str(c): v for c, v in r["by_app"][a].items()} for a in r["by_app"]}}
                for r in results[:10]
            ],
            "n_configs_tried": len(results),
        }, f, indent=2)
    print(f"\nWrote full grid-search detail to {out_path}")


if __name__ == "__main__":
    main()
