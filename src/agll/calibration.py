"""Calibrated confidence for Stage 2 verdicts.

Four signals are computed for each verdict and fused by a logistic model that
is fit on labeled candidates. An accept-or-review threshold then follows from
Elkan's cost-sensitive rule.

Signals:
  c_sc   self-consistency: agreement of k extra samples (temperature > 0)
         with the primary temperature-0 verdict.
  c_sem  semantic-entropy proxy. Verdicts are clustered by their verdict,
         behavior id and set of cited API references, in place of the
         NLI-based clustering of Kuhn et al. (ICLR 2023), since no NLI model
         was available. The fusion uses 1 - H_sem / H_max.
  c_ens  agreement with a second, smaller model served by the same Ollama
         instance.
  c_pa   fraction of cited API references that pass the Stage 3 grounding check.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from . import llm_interpret


def self_consistency(client, candidate, behavior_ids, primary_is_malicious: bool,
                     k: int = 2, temperature: float = 0.7) -> tuple[float, list[dict]]:
    """Re-runs the prompt k times; returns (agreement rate, parsed sub-verdicts)."""
    prompt = llm_interpret.build_prompt(candidate, behavior_ids)
    agreements = 0
    sub_verdicts = []
    for _ in range(k):
        raw = client.generate(prompt, temperature=temperature)
        verdict = llm_interpret.parse_verdict(raw)
        sub_verdicts.append(verdict)
        if verdict["is_parseable"] and verdict["is_malicious"] == primary_is_malicious:
            agreements += 1
    return agreements / k if k else 0.0, sub_verdicts


def _cluster_key(verdict: dict) -> tuple:
    if not verdict.get("is_parseable"):
        return ("unparseable",)
    cited = frozenset(llm_interpret.cited_api_refs(verdict.get("evidence")))
    return (verdict["is_malicious"], verdict.get("behavior_id"), cited)


def semantic_entropy(verdicts: list[dict]) -> tuple[float, float]:
    """Returns (H_sem, H_max) for a list of verdicts that includes the primary one.

    H_max is log(n), the entropy when every verdict falls in its own cluster.
    """
    n = len(verdicts)
    if n <= 1:
        return 0.0, 1.0
    counts = Counter(_cluster_key(v) for v in verdicts)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log(p)
    max_entropy = math.log(n)
    return entropy, (max_entropy if max_entropy > 0 else 1.0)


def ensemble_disagreement(secondary_client, candidate, behavior_ids,
                          primary_is_malicious: bool) -> tuple[float, dict]:
    """Returns (1.0 if the second model agrees with the primary verdict, else 0.0, its verdict)."""
    prompt = llm_interpret.build_prompt(candidate, behavior_ids)
    raw = secondary_client.generate(prompt, temperature=0.0)
    verdict = llm_interpret.parse_verdict(raw)
    agrees = verdict["is_parseable"] and verdict["is_malicious"] == primary_is_malicious
    return (1.0 if agrees else 0.0), verdict


def program_analysis_consistency(candidate, primary_verdict: dict) -> float:
    """Fraction of cited references that appear in the method body.

    A verdict that cites nothing scores 1.0: it makes no claim to contradict.
    """
    check = llm_interpret.grounding_check(candidate, primary_verdict)
    cited = check.get("cited_refs", [])
    if not cited:
        return 1.0
    return len(check.get("grounded_refs", [])) / len(cited)


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
    correct: int  # 1 if the verdict matches the ground truth, else 0

    @property
    def h_sem_norm_complement(self) -> float:
        """1 - H_sem / H_max: high when the sampled verdicts agree."""
        return 1.0 - (self.h_sem / self.h_max if self.h_max > 0 else 0.0)

    def feature_vector(self) -> list[float]:
        return [self.c_sc, self.h_sem_norm_complement, self.c_ens, self.c_pa]


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def fit_logistic(features: list[CalibrationFeatures]):
    """Fits sigmoid(w0 + w1*c_sc + w2*(1 - H_sem/H_max) + w3*c_ens + w4*c_pa).

    Returns ((w0, w1, w2, w3, w4), fitted scikit-learn model).
    """
    from sklearn.linear_model import LogisticRegression

    X = [f.feature_vector() for f in features]
    y = [f.correct for f in features]
    if len(set(y)) < 2:
        raise ValueError(
            f"Cannot fit a logistic model: all {len(y)} labels are the same "
            f"class ({y[0]}). Both correct and incorrect examples are needed."
        )
    model = LogisticRegression(max_iter=1000)
    model.fit(X, y)
    w0 = model.intercept_[0]
    w1, w2, w3, w4 = model.coef_[0]
    return (w0, w1, w2, w3, w4), model


def calibrated_confidence(features: CalibrationFeatures, weights) -> float:
    w0, w1, w2, w3, w4 = weights
    return sigmoid(
        w0 + w1 * features.c_sc + w2 * features.h_sem_norm_complement
        + w3 * features.c_ens + w4 * features.c_pa
    )


def elkan_threshold(cost_false_accept: float, cost_false_reject: float) -> float:
    """Accept automatically when the calibrated probability is at least this value.

    Elkan, "The Foundations of Cost-Sensitive Learning", IJCAI 2001.
    """
    return cost_false_accept / (cost_false_accept + cost_false_reject)


def expected_calibration_error(pairs: list[tuple[float, int]], n_bins: int = 10) -> float:
    """Equal-width-bin ECE over (probability, correct-label) pairs."""
    bins = [[] for _ in range(n_bins)]
    for probability, label in pairs:
        index = min(int(probability * n_bins), n_bins - 1)
        bins[index].append((probability, label))
    total = len(pairs)
    ece = 0.0
    for bin_pairs in bins:
        if not bin_pairs:
            continue
        confidence = sum(p for p, _ in bin_pairs) / len(bin_pairs)
        accuracy = sum(y for _, y in bin_pairs) / len(bin_pairs)
        ece += (len(bin_pairs) / total) * abs(confidence - accuracy)
    return ece
