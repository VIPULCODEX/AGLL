#!/usr/bin/env python3
"""Stage 1: rank the methods of an APK by structural suspicion.

Writes the full ranked list to results/<out> and, when a ground-truth file is
given, prints recall and precision at several cut-offs.

Example:
    python3 run_stage1.py --apk app.apk --groundtruth app_groundtruth.json \
        --package 'Lorg/example/app/' --out app_stage1_scores.json
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from agll import callgraph, groundtruth, suspicion  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"
CUTS = (0.02, 0.03, 0.05, 0.10, 0.20, 0.50, 1.00)


def parse_args():
    parser = argparse.ArgumentParser(description="Run AGLL Stage 1 (structural narrowing).")
    parser.add_argument("--apk", required=True, help="path to the APK")
    parser.add_argument("--groundtruth", required=True, help="path to the ground-truth JSON")
    parser.add_argument("--package", required=True,
                        help="smali package prefix of the app's own code, e.g. 'Lorg/example/app/'")
    parser.add_argument("--out", default="malapp_stage1_scores.json",
                        help="output file name inside results/")
    return parser.parse_args()


def write_scores(scores, out_path: Path) -> None:
    rows = [
        {
            "rank": rank,
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
        for rank, s in enumerate(scores, start=1)
    ]
    with open(out_path, "w") as f:
        json.dump(rows, f, indent=2)


def report_against_groundtruth(scores, gt_methods) -> None:
    gt_keys = {(g.classname, g.methodname, g.descriptor) for g in gt_methods}
    gt_classes = {g.classname for g in gt_methods}
    print(f"\nGround truth: {len(gt_methods)} methods across {len(gt_classes)} classes")

    ranked_keys = [(s.classname, s.methodname, s.descriptor) for s in scores]
    present = gt_keys & set(ranked_keys)
    print(f"Ground-truth methods present in the call graph: {len(present)}/{len(gt_keys)}")
    missing = gt_keys - set(ranked_keys)
    if missing:
        print("  Missing from the call graph (removed as dead code, or a constructor or "
              "synthetic form the graph does not expose):")
        for classname, methodname, descriptor in sorted(missing):
            print(f"    {classname}->{methodname}{descriptor}")

    total = len(scores)
    print(f"\nTotal scored app methods: {total}")
    print(f"{'top %':>7} {'N':>6} {'GT found':>9} {'recall':>7} {'precision':>9}")
    for cut in CUTS:
        n = max(1, round(total * cut))
        true_positives = len(gt_keys & set(ranked_keys[:n]))
        recall = true_positives / len(gt_keys) if gt_keys else 0.0
        precision = true_positives / n if n else 0.0
        print(f"{cut * 100:6.0f}% {n:6d} {true_positives:9d} {recall:7.2f} {precision:9.3f}")

    print("\nBest rank per ground-truth class:")
    for behavior_id, behavior_name, classname in sorted(
            {(g.behavior_id, g.behavior_name, g.classname) for g in gt_methods}):
        class_keys = {
            (g.classname, g.methodname, g.descriptor)
            for g in gt_methods if g.classname == classname
        }
        ranks = [i + 1 for i, key in enumerate(ranked_keys) if key in class_keys]
        print(f"  Behavior {behavior_id} ({behavior_name}) - {classname}: "
              f"{len(ranks)}/{len(class_keys)} methods found, "
              f"ranks={sorted(ranks) if ranks else 'none'}")


def main():
    args = parse_args()
    RESULTS_DIR.mkdir(exist_ok=True)

    start = time.time()
    print(f"Loading {args.apk} ...", flush=True)
    apk, _, analysis = callgraph.load_apk(args.apk)
    print(f"  loaded in {time.time() - start:.1f}s, package={apk.get_package()}")

    start = time.time()
    call_graph = callgraph.build_call_graph(analysis)
    print(f"Call graph: {call_graph.number_of_nodes()} nodes, "
          f"{call_graph.number_of_edges()} edges (built in {time.time() - start:.1f}s)")

    added = callgraph.add_callback_dispatch_edges(call_graph)
    print(f"Added {added} synthetic listener-dispatch edges "
          f"({call_graph.number_of_edges()} edges in total)")

    components = callgraph.get_components(apk)
    print(f"Manifest components: {len(components)} "
          f"({sum(c.exported for c in components)} exported)")

    entry_nodes = callgraph.get_entry_point_nodes(analysis, call_graph, components)
    print(f"Entry-point nodes: {len(entry_nodes)}")

    start = time.time()
    scores = suspicion.score_app_methods(analysis, call_graph, args.package, entry_nodes)
    print(f"Scored {len(scores)} methods in {time.time() - start:.1f}s")
    scores.sort(key=lambda s: s.suspicion_score, reverse=True)

    out_path = RESULTS_DIR / args.out
    write_scores(scores, out_path)
    print(f"Wrote the ranked list ({len(scores)} methods) to {out_path}")

    report_against_groundtruth(scores, groundtruth.load_groundtruth(args.groundtruth))


if __name__ == "__main__":
    main()
