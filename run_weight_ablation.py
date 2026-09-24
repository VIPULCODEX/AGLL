#!/usr/bin/env python3
"""Grid search over the Stage 1 weights, without rerunning androguard.

The cached Stage 1 scores keep the raw per-method signals, so the suspicion
score can be recomputed under any weight combination. For each combination the
script reports recall and precision at fixed cut-offs on all three apps and
ranks the combinations by mean recall at the top 20%.

Usage:
    python3 run_weight_ablation.py

Ranking by the mean over three apps of very different sizes lets the two small
fixtures outvote the one real app, so the script also ranks the same grid with
the real app first: its mean recall over all cuts is the primary key, and the
mean fixture recall at the top 20% only breaks ties. The pipeline's weights
(0.7 / 0.1 / 0.2, see suspicion.py) come from that second ranking.
"""

import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "src"))
from agll import groundtruth  # noqa: E402

# The ground-truth files come from a MalLoc checkout next to this repository.
APPS = [
    ("MalApp_1_9_11", "results/malapp_stage1_scores.json",
     "../MalLoc/0_Data/APKs/MalApp_1_9_11_groundtruth.json"),
    ("SyntheticMalApp", "results/synthetic_stage1_scores.json",
     "../MalLoc/0_Data/APKs/SyntheticMalApp_groundtruth.json"),
    ("RealisticMalApp", "results/realistic_stage1_scores.json",
     "../MalLoc/0_Data/APKs/RealisticMalApp_groundtruth.json"),
]

# Weights used before the ablation; the grid is compared against them.
PREVIOUS_DEFAULT = {"w_sink": 0.5, "w_entry": 0.3, "w_cfg": 0.2, "decay_scale": 3.0}

CUTS = (0.05, 0.10, 0.20, 0.50)
REAL_APP = "MalApp_1_9_11"
OUTPUT_PATH = ROOT / "results" / "weight_ablation_results.json"


def decay(distance, scale):
    if distance is None:
        return 0.0
    return 1.0 / (1.0 + distance / scale)


def score_method(method, w_sink, w_entry, w_cfg, decay_scale):
    sink_score = decay(method["dist_to_sensitive"], decay_scale)
    entry_factor = 1.0 if method["entry_exported"] else 0.6
    entry_score = decay(method["dist_from_entry"], decay_scale) * entry_factor
    complexity = method["cyclomatic_complexity"] or 0
    cfg_score = min(complexity / 15.0, 1.0)
    return w_sink * sink_score + w_entry * entry_score + w_cfg * cfg_score


def load_app(scores_path, gt_path):
    with open(ROOT / scores_path) as f:
        methods = json.load(f)
    ground_truth = groundtruth.load_groundtruth(ROOT / gt_path)
    return methods, {(g.classname, g.methodname, g.descriptor) for g in ground_truth}


def evaluate(methods, gt_keys, w_sink, w_entry, w_cfg, decay_scale):
    """Returns {cut: (recall, precision, n)} for one weight combination."""
    scored = [(score_method(m, w_sink, w_entry, w_cfg, decay_scale), m) for m in methods]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    ranked_keys = [(m["classname"], m["methodname"], m["descriptor"]) for _, m in scored]
    total = len(ranked_keys)
    result = {}
    for cut in CUTS:
        n = max(1, round(total * cut))
        true_positives = len(gt_keys & set(ranked_keys[:n]))
        recall = true_positives / len(gt_keys) if gt_keys else 0.0
        precision = true_positives / n if n else 0.0
        result[cut] = (recall, precision, n)
    return result


def mean_at(results_by_app, cut, index):
    """Mean of recall (index 0) or precision (index 1) over the apps at one cut."""
    values = [results_by_app[app][cut][index] for app in results_by_app]
    return sum(values) / len(values)


def format_row(row):
    return ", ".join(f"top{int(cut * 100)}%=R{row[cut][0]:.2f}/P{row[cut][1]:.2f}" for cut in CUTS)


def stringify_cuts(by_app):
    return {app: {str(cut): value for cut, value in row.items()} for app, row in by_app.items()}


def main():
    apps_data = {}
    for name, scores_path, gt_path in APPS:
        methods, gt_keys = load_app(scores_path, gt_path)
        apps_data[name] = (methods, gt_keys)
        print(f"Loaded {name}: {len(methods)} methods, {len(gt_keys)} ground-truth methods")

    print("\n=== Previous default weights, recomputed from the cached signals ===")
    default_by_app = {}
    for name, (methods, gt_keys) in apps_data.items():
        default_by_app[name] = evaluate(methods, gt_keys, **PREVIOUS_DEFAULT)
        print(f"  {name}: {format_row(default_by_app[name])}")

    weight_combos = []
    for w_sink in (0.3, 0.4, 0.5, 0.6, 0.7):
        for w_entry in (0.1, 0.2, 0.3, 0.4, 0.5):
            w_cfg = round(1.0 - w_sink - w_entry, 4)
            if 0 <= w_cfg <= 1:
                weight_combos.append((w_sink, w_entry, w_cfg))
    decay_scales = (2.0, 3.0, 5.0)

    print(f"\n=== Grid search: {len(weight_combos)} weight combinations x "
          f"{len(decay_scales)} decay scales = {len(weight_combos) * len(decay_scales)} configurations ===")

    results = []
    for (w_sink, w_entry, w_cfg), scale in itertools.product(weight_combos, decay_scales):
        by_app = {name: evaluate(methods, gt_keys, w_sink, w_entry, w_cfg, scale)
                  for name, (methods, gt_keys) in apps_data.items()}
        real_app_recall = sum(by_app[REAL_APP][cut][0] for cut in CUTS) / len(CUTS)
        fixtures = [name for name in by_app if name != REAL_APP]
        fixture_recall_20 = sum(by_app[name][0.20][0] for name in fixtures) / len(fixtures)
        results.append({
            "w_sink": w_sink, "w_entry": w_entry, "w_cfg": w_cfg, "decay_scale": scale,
            "mean_recall_20": round(mean_at(by_app, 0.20, 0), 4),
            "mean_precision_20": round(mean_at(by_app, 0.20, 1), 4),
            "real_app_mean_recall": round(real_app_recall, 4),
            "fixture_recall_20": round(fixture_recall_20, 4),
            "by_app": by_app,
        })
    # The top 20% is the cut where all three apps have a meaningful candidate count.
    results.sort(key=lambda r: (r["mean_recall_20"], r["mean_precision_20"]), reverse=True)

    real_first = sorted(results, key=lambda r: (r["real_app_mean_recall"], r["fixture_recall_20"]),
                        reverse=True)

    default_recall = mean_at(default_by_app, 0.20, 0)
    default_precision = mean_at(default_by_app, 0.20, 1)
    print(f"\nPrevious default (0.5/0.3/0.2, scale=3): "
          f"mean recall@20%={default_recall:.4f}, mean precision@20%={default_precision:.4f}")

    print("\nTop 10 configurations by mean recall@20% (ties broken by mean precision@20%):")
    print(f"{'w_sink':>7} {'w_entry':>8} {'w_cfg':>6} {'scale':>6} {'mean_R@20':>10} {'mean_P@20':>10}")
    for r in results[:10]:
        print(f"{r['w_sink']:7.2f} {r['w_entry']:8.2f} {r['w_cfg']:6.2f} {r['decay_scale']:6.1f} "
              f"{r['mean_recall_20']:10.4f} {r['mean_precision_20']:10.4f}")

    best = results[0]
    print(f"\nBest by mean recall@20%: w_sink={best['w_sink']}, w_entry={best['w_entry']}, "
          f"w_cfg={best['w_cfg']}, decay_scale={best['decay_scale']}")
    for name in apps_data:
        print(f"  {name}: {format_row(best['by_app'][name])}")

    print(f"\nTop 5 with the real app first (real-app mean recall over all cuts, "
          f"then fixture recall@20%):")
    print(f"{'w_sink':>7} {'w_entry':>8} {'w_cfg':>6} {'scale':>6} {'real_R':>8} {'fixt_R@20':>10}")
    for r in real_first[:5]:
        print(f"{r['w_sink']:7.2f} {r['w_entry']:8.2f} {r['w_cfg']:6.2f} {r['decay_scale']:6.1f} "
              f"{r['real_app_mean_recall']:8.4f} {r['fixture_recall_20']:10.4f}")

    top_fields = ("w_sink", "w_entry", "w_cfg", "decay_scale", "mean_recall_20", "mean_precision_20")
    real_first_fields = top_fields + ("real_app_mean_recall", "fixture_recall_20")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({
            "default": {"weights": PREVIOUS_DEFAULT, "by_app": stringify_cuts(default_by_app),
                        "mean_recall_20": default_recall, "mean_precision_20": default_precision},
            "grid_top10": [
                {**{k: r[k] for k in top_fields}, "by_app": stringify_cuts(r["by_app"])}
                for r in results[:10]
            ],
            "real_app_first_top5": [
                {**{k: r[k] for k in real_first_fields}, "by_app": stringify_cuts(r["by_app"])}
                for r in real_first[:5]
            ],
            "n_configs_tried": len(results),
        }, f, indent=2)
    print(f"\nWrote grid-search detail to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
