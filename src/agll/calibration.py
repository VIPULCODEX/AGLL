"""
Objective 2 — Calibrated Confidence Scoring (Three-Objective-Workflow.md).

Four signals per Stage-2 prediction, fused by a logistic mapping FIT on real
data (not hand-picked weights, unlike the earlier `MalLoc/day3_confidence.py`
prototype), plus Elkan's cost-sensitive decision threshold.

- c_sc: self-consistency (k reruns at nonzero temperature, agreement with the
  primary temp=0 verdict).
- H_sem / c_sem: semantic-entropy-style signal. The plan specifies clustering
  k free-text explanations via NLI-based bidirectional entailment (Kuhn, Gal,
  Farquhar, ICLR 2023) and no NLI model is available in this environment.
  Approximated here by clustering on (verdict, behavior_id, frozenset of
  cited API references) instead of raw text — a coarser, structured proxy for
  "the same underlying explanation," appropriate given this project's forced
  marker-format output (verdict/behavior/evidence are already structured,
  not free text). This approximation is documented, not hidden — see
  PROGRESS.md DECISIONS & WHY.
- c_ens: ensemble disagreement against a second, smaller local model
  (`qwen2.5:1.5b`). Not truly "independently hosted" (plan's own wording) —
  both models run on the same local Ollama instance — but a genuinely
  different model family/size, which is what this environment has.
- c_pa: program-analysis consistency, reusing AGLL's own stage-3 grounding
  check directly (`llm_interpret.grounding_check`) rather than reimplementing
  it — the fraction of cited API references that verify against the real
  method body.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from . import llm_interpret


def self_consistency(client, cand, behavior_ids, primary_is_malicious: bool,
                      k: int = 2, temperature: float = 0.7) -> tuple[float, list[dict]]:
    """Rerun the interpretation prompt k times at nonzero temperature; return
    (fraction agreeing with the primary temp=0 verdict, raw sub-verdicts)."""
    prompt = llm_interpret.build_prompt(cand, behavior_ids)
    agreements = 0
    sub_verdicts = []
    for _ in range(k):
        raw = client.generate(prompt, temperature=temperature)
        v = llm_interpret.parse_verdict(raw)
        sub_verdicts.append(v)
        if v["is_parseable"] and v["is_malicious"] == primary_is_malicious:
            agreements += 1
    return agreements / k if k else 0.0, sub_verdicts


def _cluster_key(v: dict) -> tuple:
    """Structured proxy for 'semantically equivalent explanation' — see
    module docstring for why this substitutes for NLI-based clustering."""
    if not v.get("is_parseable"):
        return ("unparseable",)
    refs = frozenset(llm_interpret.cited_api_refs(v.get("evidence")))
    return (v["is_malicious"], v.get("behavior_id"), refs)


def semantic_entropy(verdicts: list[dict]) -> tuple[float, float]:
    """Returns (H_sem, H_max) over a list of verdict dicts (including the
    primary verdict — pass all k+1 verdicts in). H_sem = -sum(p_i log p_i)
    over clusters; H_max = log(n_distinct_possible) is taken as log(len(verdicts))
    (the entropy-maximizing case: every run in its own cluster)."""
    n = len(verdicts)
    if n <= 1:
        return 0.0, 1.0
    counts = Counter(_cluster_key(v) for v in verdicts)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log(p)
    h_max = math.log(n)
    return h, (h_max if h_max > 0 else 1.0)


def ensemble_disagreement(client_secondary, cand, behavior_ids,
                           primary_is_malicious: bool) -> tuple[float, dict]:
    """One call to a second, smaller local model; returns (1.0 if it agrees
    with the primary verdict else 0.0, its raw parsed verdict)."""
    prompt = llm_interpret.build_prompt(cand, behavior_ids)
    raw = client_secondary.generate(prompt, temperature=0.0)
    v = llm_interpret.parse_verdict(raw)
    agree = 1.0 if (v["is_parseable"] and v["is_malicious"] == primary_is_malicious) else 0.0
    return agree, v


def program_analysis_consistency(cand, primary_verdict: dict) -> float:
    """Reuses the real stage-3 grounding check. c_pa = fraction of cited API
    references that verify against the real method body. A verdict that
    cites nothing is treated as c_pa=1.0 (vacuously consistent — nothing
    claimed, nothing to contradict), matching MalLoc/day3_confidence.py's
    convention for the no-claims case."""
    check = llm_interpret.grounding_check(cand, primary_verdict)
    cited = check.get("cited_refs", [])
    if not cited:
        return 1.0
    grounded = check.get("grounded_refs", [])
    return len(grounded) / len(cited)


@dataclass
class CalibrationFeatures:
    signature: str
    app: str
    c_sc: float
    h_sem: float
    h_max: float
    c_ens: float
    c_pa: float
    predicted_malicious: bool
    in_gt: bool
    correct: int  # label: 1 if predicted verdict matches ground truth, else 0

    @property
    def h_sem_norm_complement(self) -> float:
        """1 - H_sem/H_max, the fusion formula's actual term (low entropy -> high)."""
        return 1.0 - (self.h_sem / self.h_max if self.h_max > 0 else 0.0)

    def feature_vector(self) -> list[float]:
        return [self.c_sc, self.h_sem_norm_complement, self.c_ens, self.c_pa]


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def fit_logistic(features: list[CalibrationFeatures]):
    """Fits sigmoid(w0 + w1*c_sc + w2*(1-H_sem/H_max) + w3*c_ens + w4*c_pa) via
    scikit-learn's LogisticRegression on (X, y). Returns the fitted
    coefficients as (w0, w1, w2, w3, w4). Requires scikit-learn."""
    from sklearn.linear_model import LogisticRegression

    X = [f.feature_vector() for f in features]
    y = [f.correct for f in features]
    if len(set(y)) < 2:
        raise ValueError(
            f"Cannot fit a logistic model: all {len(y)} labels are the same "
            f"class ({y[0]}). Need both correct and incorrect examples."
        )
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, y)
    w0 = clf.intercept_[0]
    w1, w2, w3, w4 = clf.coef_[0]
    return (w0, w1, w2, w3, w4), clf


def calibrated_confidence(feat: CalibrationFeatures, weights) -> float:
    w0, w1, w2, w3, w4 = weights
    return sigmoid(
        w0 + w1 * feat.c_sc + w2 * feat.h_sem_norm_complement
        + w3 * feat.c_ens + w4 * feat.c_pa
    )


def elkan_threshold(c_fa: float, c_fr: float) -> float:
    """Elkan (IJCAI 2001): the Bayes-optimal accept threshold tau* for a
    binary accept/reject decision under asymmetric misclassification costs.
    Accept automatically iff p_hat(correct) >= tau*."""
    return c_fa / (c_fa + c_fr)


def expected_calibration_error(pairs: list[tuple[float, int]], n_bins: int = 10) -> float:
    """Standard ECE: bin predicted probabilities into n_bins equal-width bins,
    compare each bin's mean predicted probability to its actual accuracy,
    weight by bin size. `pairs` is a list of (p_hat, correct_label)."""
    bins = [[] for _ in range(n_bins)]
    for p, y in pairs:
        idx = min(int(p * n_bins), n_bins - 1)
        bins[idx].append((p, y))
    n = len(pairs)
    ece = 0.0
    for b in bins:
        if not b:
            continue
        conf = sum(p for p, _ in b) / len(b)
        acc = sum(y for _, y in b) / len(b)
        ece += (len(b) / n) * abs(conf - acc)
    return ece
