#!/usr/bin/env python3
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from agll import groundtruth, llm_interpret  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"

TOP_PCT = 0.05
MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
BASE_URL = "http://localhost:11434"


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="extract smali + print table; no LLM calls")
    p.add_argument("--resume", action="store_true", help="skip ranks already in the interactions JSON")
    p.add_argument("--judge-only", action="store_true", help="re-run metrics/judge on saved JSON")
    p.add_argument("--top-pct", type=float, default=TOP_PCT, help=f"top fraction of candidates (default {TOP_PCT})")
    p.add_argument("--model", default=MODEL)
    p.add_argument("--base-url", default=BASE_URL)
    p.add_argument("--max-retries", type=int, default=2)
    p.add_argument("--scores", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--smali", required=True)
    p.add_argument("--interactions-out", default="sample_gpu7b_stage2_llm_interactions.json")
    p.add_argument("--results-out", default="sample_gpu7b_stage2_llm_results.json")
    p.add_argument("--behavior-ids", default="1,9,11",
                   help="comma-separated behavior IDs to offer the LLM (default '1,9,11', "
                        "the MalApp_1_9_11 demo app's 3 behaviors). Must match the "
                        "ground-truth fixture's actual category set or the run "
                        "under-informs the model — see AGLL/PROGRESS.md JUDGE LOG.")
    args = p.parse_args()
    args.behavior_ids = [int(x) for x in args.behavior_ids.split(",") if x.strip()]
    return args


def ensure_stage1_scores(scores_path) -> None:
    if not Path(scores_path).is_file():
        raise SystemExit(f"missing {scores_path}")


def prepare_candidates(args) -> list[llm_interpret.Candidate]:
    ensure_stage1_scores(args.scores)
    cands = llm_interpret.load_candidates(Path(args.scores), top_pct=args.top_pct)
    for c in cands:
        f = llm_interpret.locate_class_file(Path(args.smali), c.classname)
        c.smali_file = str(f) if f else None
        if f:
            c.method_body = llm_interpret.extract_method_body(f.read_text(encoding="utf-8", errors="replace"),
                                                              c.methodname, c.descriptor)
    return cands


def print_table(cands: list[llm_interpret.Candidate], args) -> None:
    print(f"{'rank':>4} {'GT?':>4} {'found':>5} {'score':>7}  method")
    gt = llm_interpret.load_groundtruth(Path(args.gt))
    for c in cands:
        key = (c.classname, c.methodname, c.descriptor)
        gt_flag = "GT" if key in gt else "  "
        found = "ok" if c.method_body else ("NOFILE" if not c.smali_file else "MISS")
        print(f"{c.rank:4d} {gt_flag:>4} {found:>5} {c.suspicion_score:7.4f}  {c.classname}->{c.methodname}{c.descriptor}")
    bodies = sum(1 for c in cands if c.method_body)
    print(f"\n{len(cands)} candidates, {bodies} with extracted smali method bodies.")


def load_interactions(path) -> list[dict]:
    if Path(path).is_file():
        with open(path) as f:
            return json.load(f)
    return []


def save_interactions(interactions: list[dict], path) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(path, "w") as f:
        json.dump(interactions, f, indent=2)


def run_llm_stage(cands: list[llm_interpret.Candidate], args) -> None:
    interactions = load_interactions(RESULTS_DIR / args.interactions_out)
    done_ranks = {i["rank"] for i in interactions}
    client = llm_interpret.OllamaClient(base_url=args.base_url, model=args.model)

    todo = []
    for c in cands:
        if args.resume and c.rank in done_ranks:
            continue
        if not c.method_body:
            interactions.append({
                "rank": c.rank,
                "signature": c.signature,
                "error": "no smali method body available (not judged)",
                "prompt": None, "raw_response": None, "elapsed_s": 0.0,
            })
            continue
        todo.append(c)

    if not todo:
        print("Nothing to run (use --judge-only to re-verify).")
    else:
        print(f"Interpreting {len(todo)}/{len(cands)} candidates with {args.model} ...", flush=True)

    for c in todo:
        prompt = llm_interpret.build_prompt(c, args.behavior_ids)
        raw, elapsed, err = "", 0.0, None
        t0 = time.time()
        for attempt in range(1, args.max_retries + 2):
            try:
                raw = client.generate(prompt)
                elapsed = time.time() - t0
                break
            except Exception as e:
                err = str(e)
                print(f"  rank {c.rank}: attempt {attempt} failed ({e!r}); retrying", flush=True)
                time.sleep(2 * attempt)
        if err and not raw:
            raw = f"__ERROR__: {err}"
        interactions.append({
            "rank": c.rank,
            "signature": c.signature,
            "classname": c.classname,
            "methodname": c.methodname,
            "descriptor": c.descriptor,
            "suspicion_score": c.suspicion_score,
            "sensitive_category": c.sensitive_category,
            "prompt": prompt,
            "raw_response": raw,
            "elapsed_s": round(elapsed, 1),
        })
        save_interactions(interactions, RESULTS_DIR / args.interactions_out)
        v = llm_interpret.parse_verdict(raw)
        print(f"  rank {c.rank:2d} -> {'parse-err' if not v['is_parseable'] else ('MALICIOUS' if v['is_malicious'] else 'benign')}, "
              f"conf={v.get('confidence')}, evid_chars={len(v.get('evidence') or '')}", flush=True)


def judge(cands: list[llm_interpret.Candidate], args) -> dict:
    interactions = load_interactions(RESULTS_DIR / args.interactions_out)
    by_rank = {i["rank"]: i for i in interactions}
    gt = llm_interpret.load_groundtruth(Path(args.gt))
    gt_methods = groundtruth.load_groundtruth(Path(args.gt))
    gt_total = len(gt_methods)

    results = []
    tp = fp = fn = parse_errors = 0
    fn_list = []
    for c in cands:
        inter = by_rank.get(c.rank)
        is_gt = (c.classname, c.methodname, c.descriptor) in gt
        if inter is None:
            entry = {"rank": c.rank, "signature": c.signature, "in_gt": is_gt,
                     "verdict": "not_run", "error": "no interaction recorded"}
            results.append(entry)
            continue
        if inter.get("error"):
            entry = {"rank": c.rank, "signature": c.signature, "in_gt": is_gt,
                     "verdict": "unavailable", "error": inter["error"]}
            results.append(entry)
            continue
        verdict = llm_interpret.parse_verdict(inter["raw_response"] or "")
        check = llm_interpret.grounding_check(c, verdict)
        if not verdict["is_parseable"]:
            parse_errors += 1
            state = "parse_error"
        else:
            state = "malicious" if verdict["is_malicious"] else "benign"
        if state == "malicious":
            if is_gt:
                tp += 1
            else:
                fp += 1
        elif state == "benign" and is_gt:
            fn += 1
            fn_list.append(c.signature)
        results.append({
            "rank": c.rank,
            "signature": c.signature,
            "classname": c.classname,
            "methodname": c.methodname,
            "descriptor": c.descriptor,
            "in_gt": is_gt,
            "verdict": state,
            "pred_behavior_id": verdict.get("behavior_id"),
            "confidence": verdict.get("confidence"),
            "evidence": verdict.get("evidence"),
            "grounding": check,
            "raw_response_excerpt": (inter["raw_response"] or "")[:200],
        })

    cand_keys = {(c.classname, c.methodname, c.descriptor) for c in cands}
    structurally_missed = sorted(gt - cand_keys)
    fn += len(structurally_missed)
    for sig in structurally_missed:
        fn_list.append(f"(structural miss) {sig}")

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / gt_total if gt_total else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    summary = {
        "model": args.model,
        "top_pct": args.top_pct,
        "n_candidates": len(cands),
        "gt_total": gt_total,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "parse_errors": parse_errors,
        "fn_list": fn_list,
        "predicted_malicious": [r for r in results if r["verdict"] == "malicious"]
    }
    out = {"summary": summary, "per_candidate": results}
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_DIR / args.results_out, "w") as f:
        json.dump(out, f, indent=2)

    print("\n" + "=" * 70)
    print(f"END-TO-END (structural top-{args.top_pct:.0%} + LLM interpretation), {args.model}")
    print("=" * 70)
    print(f"{'rank':>4} {'verdict':>10} {'GT':>3} {'conf':>4} {'grounded':>8}  signature")
    for r in results:
        g = r["grounding"] if r.get("grounding") else {}
        gr = "" if g is None else ("ok" if g.get("grounded") else f"UNGROUNDED:{g.get('ungrounded_refs')}")
        print(f"{r['rank']:4d} {r['verdict']:>10} {'yes' if r['in_gt'] else '':>3} "
              f"{(r.get('confidence') or 0):4d} {gr:>8}  {r['signature']}")
    print(f"\nMethod-level: TP={tp} FP={fp} FN={fn} (of {gt_total} GT methods)")
    print(f"  precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}   (parse_errors={parse_errors})")
    return out


def main():
    args = parse_args()
    if args.judge_only:
        cands = prepare_candidates(args)
        judge(cands, args)
        return
    cands = prepare_candidates(args)
    print_table(cands, args)
    if args.dry_run:
        print("\n[DRY-RUN] no LLM calls made. Preview prompt (rank 1):\n")
        if cands:
            print(llm_interpret.build_prompt(cands[0], args.behavior_ids))
        return
    run_llm_stage(cands, args)
    judge(cands, args)


if __name__ == "__main__":
    main()
