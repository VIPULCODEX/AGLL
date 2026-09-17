#!/usr/bin/env python3
import json
import sys
import time
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from agll import callgraph, groundtruth, suspicion  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"

def main():
    parser = argparse.ArgumentParser(description="Run AGLL stage-one structural narrowing.")
    parser.add_argument("--apk", required=True, help="Path to APK")
    parser.add_argument("--groundtruth", required=True, help="Path to groundtruth JSON")
    parser.add_argument("--package", required=True, help="Package prefix to filter (e.g., 'Lorg/research/syntheticmalloc/')")
    parser.add_argument("--out", default="sample_gpu7b_stage1_scores.json", help="Output JSON filename")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)

    t0 = time.time()
    print(f"Loading {args.apk} ...", flush=True)
    a, d, dx = callgraph.load_apk(args.apk)
    print(f"  loaded in {time.time() - t0:.1f}s, package={a.get_package()}")

    t1 = time.time()
    cg = callgraph.build_call_graph(dx)
    print(f"Call graph: {cg.number_of_nodes()} nodes, {cg.number_of_edges()} edges "
          f"(built in {time.time() - t1:.1f}s)")

    added = callgraph.add_callback_dispatch_edges(cg)
    print(f"Added {added} synthetic listener-dispatch edges "
          f"({cg.number_of_edges()} edges total now)")

    components = callgraph.get_components(a)
    print(f"Manifest components: {len(components)} "
          f"({sum(c.exported for c in components)} exported)")

    entry_nodes = callgraph.get_entry_point_nodes(dx, cg, components)
    print(f"Entry-point call-graph nodes identified: {len(entry_nodes)}")

    t2 = time.time()
    scores = suspicion.score_app_methods(dx, cg, args.package, entry_nodes)
    print(f"Scored {len(scores)} app-package methods in {time.time() - t2:.1f}s")

    scores.sort(key=lambda s: s.suspicion_score, reverse=True)

    out_path = RESULTS_DIR / args.out
    with open(out_path, "w") as f:
        json.dump(
            [
                {
                    "rank": i + 1,
                    "classname": s.classname,
                    "methodname": s.methodname,
                    "descriptor": s.descriptor,
                    "suspicion_score": s.suspicion_score,
                    "dist_to_sensitive": s.dist_to_sensitive,
                    "sensitive_category": s.sensitive_category,
                    "dist_from_entry": s.dist_from_entry,
                    "entry_exported": s.entry_exported,
                    "cyclomatic_complexity": s.cyclomatic_complexity,
                }
                for i, s in enumerate(scores)
            ],
            f,
            indent=2,
        )
    print(f"Wrote full ranked list ({len(scores)} methods) to {out_path}")

    # Ground-truth comparison.
    gt_methods = groundtruth.load_groundtruth(args.groundtruth)
    gt_keys = {(g.classname, g.methodname, g.descriptor) for g in gt_methods}
    gt_classes = {g.classname for g in gt_methods}
    print(f"\nGround truth: {len(gt_methods)} methods across {len(gt_classes)} classes")

    score_keys = [(s.classname, s.methodname, s.descriptor) for s in scores]
    found_in_graph = gt_keys & set(score_keys)
    print(f"GT methods actually present as nodes in the call graph: "
          f"{len(found_in_graph)}/{len(gt_keys)}")
    missing = gt_keys - set(score_keys)
    if missing:
        print("  MISSING from call graph (likely dead-code-eliminated, or a "
              "constructor/synthetic form the call graph doesn't expose):")
        for c, m, desc in sorted(missing):
            print(f"    {c}->{m}{desc}")

    total = len(scores)
    print(f"\nTotal scored app methods: {total}")
    print(f"{'top %':>7} {'N':>6} {'GT found':>9} {'recall':>7} {'precision':>9}")
    for pct in (0.02, 0.03, 0.05, 0.10, 0.20, 0.50, 1.00):
        n = max(1, round(total * pct))
        top_n = score_keys[:n]
        top_n_set = set(top_n)
        tp = len(gt_keys & top_n_set)
        recall = tp / len(gt_keys) if gt_keys else 0.0
        precision = tp / n if n else 0.0
        print(f"{pct*100:6.0f}% {n:6d} {tp:9d} {recall:7.2f} {precision:9.3f}")

    print("\nPer ground-truth-behavior best rank achieved by any of its methods:")
    for gt in sorted({(g.behavior_id, g.behavior_name, g.classname) for g in gt_methods}):
        behavior_id, behavior_name, classname = gt
        this_class_gt_keys = {
            (g.classname, g.methodname, g.descriptor)
            for g in gt_methods
            if g.classname == classname
        }
        ranks = [i + 1 for i, k in enumerate(score_keys) if k in this_class_gt_keys]
        print(f"  Behavior {behavior_id} ({behavior_name}) — {classname}: "
              f"{len(ranks)}/{len(this_class_gt_keys)} GT methods found, "
              f"ranks={sorted(ranks) if ranks else 'NONE FOUND'}")

if __name__ == "__main__":
    main()
