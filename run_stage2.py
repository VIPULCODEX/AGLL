#!/usr/bin/env python3
"""Stage 2 and 3: interpret the Stage 1 shortlist with an LLM, then score it.

Reads the ranked list written by run_stage1.py, prompts the model once per
candidate in the top --top-pct of that list, and writes two files to results/:
the raw interactions and the scored results (precision, recall, F1 and the
grounding check for every candidate).

Example:
    python3 run_stage2.py --scores results/app_stage1_scores.json \
        --gt app_groundtruth.json --smali app_apktool_output/ \
        --interactions-out app_stage2_interactions.json \
        --results-out app_stage2_results.json

--dry-run only extracts method bodies, --resume skips ranks that already have
an interaction, and --judge-only re-scores saved interactions without calling
the model.
"""

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="extract method bodies and print the shortlist; no LLM calls")
    parser.add_argument("--resume", action="store_true", help="skip ranks that already have a saved interaction")
    parser.add_argument("--judge-only", action="store_true", help="re-score saved interactions without calling the model")
    parser.add_argument("--top-pct", type=float, default=TOP_PCT, help=f"fraction of the ranked list to interpret (default {TOP_PCT})")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--max-retries", type=int, default=2)
    parser.add_argument("--scores", required=True)
    parser.add_argument("--gt", required=True)
    parser.add_argument("--smali", required=True)
    parser.add_argument("--interactions-out", default="malapp_stage2_interactions.json")
    parser.add_argument("--results-out", default="malapp_stage2_results.json")
    parser.add_argument("--behavior-ids", default="1,9,11",
                   help="comma-separated behavior IDs offered to the LLM; should match "
                        "the behavior categories used in the ground truth (default: 1,9,11)")
    args = parser.parse_args()
    args.behavior_ids = [int(x) for x in args.behavior_ids.split(",") if x.strip()]
    return args


def prepare_candidates(args) -> list[llm_interpret.Candidate]:
    if not Path(args.scores).is_file():
        raise SystemExit(f"missing {args.scores}")
    candidates = llm_interpret.load_candidates(Path(args.scores), top_pct=args.top_pct)
    for candidate in candidates:
        smali_path = llm_interpret.locate_class_file(Path(args.smali), candidate.classname)
        candidate.smali_file = str(smali_path) if smali_path else None
        if smali_path:
            smali_text = smali_path.read_text(encoding="utf-8", errors="replace")
            candidate.method_body = llm_interpret.extract_method_body(
                smali_text, candidate.methodname, candidate.descriptor)
    return candidates


def print_table(candidates: list[llm_interpret.Candidate], args) -> None:
    print(f"{'rank':>4} {'GT?':>4} {'found':>5} {'score':>7}  method")
    ground_truth = llm_interpret.load_groundtruth(Path(args.gt))
    for candidate in candidates:
        key = (candidate.classname, candidate.methodname, candidate.descriptor)
        gt_flag = "GT" if key in ground_truth else "  "
        found = "ok" if candidate.method_body else ("NOFILE" if not candidate.smali_file else "MISS")
        print(f"{candidate.rank:4d} {gt_flag:>4} {found:>5} {candidate.suspicion_score:7.4f}  {candidate.classname}->{candidate.methodname}{candidate.descriptor}")
    bodies = sum(1 for candidate in candidates if candidate.method_body)
    print(f"\n{len(candidates)} candidates, {bodies} with extracted smali method bodies.")


def load_interactions(path) -> list[dict]:
    if Path(path).is_file():
        with open(path) as f:
            return json.load(f)
    return []


def save_interactions(interactions: list[dict], path) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(path, "w") as f:
        json.dump(interactions, f, indent=2)


def run_interpretation(candidates: list[llm_interpret.Candidate], args) -> None:
    interactions = load_interactions(RESULTS_DIR / args.interactions_out)
    done_ranks = {i["rank"] for i in interactions}
    client = llm_interpret.OllamaClient(base_url=args.base_url, model=args.model)

    todo = []
    for candidate in candidates:
        if args.resume and candidate.rank in done_ranks:
            continue
        if not candidate.method_body:
            interactions.append({
                "rank": candidate.rank,
                "signature": candidate.signature,
                "error": "no smali method body available (not judged)",
                "prompt": None, "raw_response": None, "elapsed_s": 0.0,
            })
            continue
        todo.append(candidate)

    if not todo:
        print("Nothing to run (use --judge-only to re-verify).")
    else:
        print(f"Interpreting {len(todo)}/{len(candidates)} candidates with {args.model} ...", flush=True)

    for candidate in todo:
        prompt = llm_interpret.build_prompt(candidate, args.behavior_ids)
        raw, elapsed, err = "", 0.0, None
        started = time.time()
        for attempt in range(1, args.max_retries + 2):
            try:
                raw = client.generate(prompt)
                elapsed = time.time() - started
                break
            except Exception as error:
                err = str(error)
                print(f"  rank {candidate.rank}: attempt {attempt} failed ({error!r}); retrying", flush=True)
                time.sleep(2 * attempt)
        if err and not raw:
            raw = f"__ERROR__: {err}"
        interactions.append({
            "rank": candidate.rank,
            "signature": candidate.signature,
            "classname": candidate.classname,
            "methodname": candidate.methodname,
            "descriptor": candidate.descriptor,
            "suspicion_score": candidate.suspicion_score,
            "sensitive_category": candidate.sensitive_category,
            "prompt": prompt,
            "raw_response": raw,
            "elapsed_s": round(elapsed, 1),
        })
        save_interactions(interactions, RESULTS_DIR / args.interactions_out)
        verdict = llm_interpret.parse_verdict(raw)
        label = 'parse-err' if not verdict['is_parseable'] else ('MALICIOUS' if verdict['is_malicious'] else 'benign')
        print(f"  rank {candidate.rank:2d} -> {label}, conf={verdict.get('confidence')}, "
              f"evid_chars={len(verdict.get('evidence') or '')}", flush=True)


def judge(candidates: list[llm_interpret.Candidate], args) -> dict:
    interactions = load_interactions(RESULTS_DIR / args.interactions_out)
    by_rank = {i["rank"]: i for i in interactions}
    ground_truth = llm_interpret.load_groundtruth(Path(args.gt))
    gt_total = len(groundtruth.load_groundtruth(Path(args.gt)))

    results = []
    tp = fp = fn = parse_errors = 0
    fn_list = []
    for candidate in candidates:
        interaction = by_rank.get(candidate.rank)
        is_gt = (candidate.classname, candidate.methodname, candidate.descriptor) in ground_truth
        if interaction is None:
            entry = {"rank": candidate.rank, "signature": candidate.signature, "in_gt": is_gt,
                     "verdict": "not_run", "error": "no interaction recorded"}
            results.append(entry)
            continue
        if interaction.get("error"):
            entry = {"rank": candidate.rank, "signature": candidate.signature, "in_gt": is_gt,
                     "verdict": "unavailable", "error": interaction["error"]}
            results.append(entry)
            continue
        verdict = llm_interpret.parse_verdict(interaction["raw_response"] or "")
        check = llm_interpret.grounding_check(candidate, verdict)
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
            fn_list.append(candidate.signature)
        results.append({
            "rank": candidate.rank,
            "signature": candidate.signature,
            "classname": candidate.classname,
            "methodname": candidate.methodname,
            "descriptor": candidate.descriptor,
            "in_gt": is_gt,
            "verdict": state,
            "pred_behavior_id": verdict.get("behavior_id"),
            "confidence": verdict.get("confidence"),
            "evidence": verdict.get("evidence"),
            "grounding": check,
            "raw_response_excerpt": (interaction["raw_response"] or "")[:200],
        })

    candidate_keys = {(c.classname, c.methodname, c.descriptor) for c in candidates}
    structurally_missed = sorted(ground_truth - candidate_keys)
    fn += len(structurally_missed)
    for key in structurally_missed:
        fn_list.append(f"(structural miss) {key}")

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / gt_total if gt_total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    summary = {
        "model": args.model,
        "top_pct": args.top_pct,
        "n_candidates": len(candidates),
        "gt_total": gt_total,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "parse_errors": parse_errors,
        "fn_list": fn_list,
        "predicted_malicious": [r for r in results if r["verdict"] == "malicious"],
    }
    out = {"summary": summary, "per_candidate": results}
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_DIR / args.results_out, "w") as f:
        json.dump(out, f, indent=2)

    print("\n" + "=" * 70)
    print(f"END-TO-END (structural top-{args.top_pct:.0%} + LLM interpretation), {args.model}")
    print("=" * 70)
    print(f"{'rank':>4} {'verdict':>10} {'GT':>3} {'conf':>4} {'grounded':>8}  signature")
    for result in results:
        grounding = result["grounding"] if result.get("grounding") else {}
        status = "ok" if grounding.get("grounded") else f"UNGROUNDED:{grounding.get('ungrounded_refs')}"
        print(f"{result['rank']:4d} {result['verdict']:>10} {'yes' if result['in_gt'] else '':>3} "
              f"{(result.get('confidence') or 0):4d} {status:>8}  {result['signature']}")
    print(f"\nMethod-level: TP={tp} FP={fp} FN={fn} (of {gt_total} GT methods)")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}   (parse_errors={parse_errors})")
    return out


def main():
    args = parse_args()
    if args.judge_only:
        candidates = prepare_candidates(args)
        judge(candidates, args)
        return
    candidates = prepare_candidates(args)
    print_table(candidates, args)
    if args.dry_run:
        print("\nDry run: no LLM calls were made. Prompt for rank 1:\n")
        if candidates:
            print(llm_interpret.build_prompt(candidates[0], args.behavior_ids))
        return
    run_interpretation(candidates, args)
    judge(candidates, args)


if __name__ == "__main__":
    main()
