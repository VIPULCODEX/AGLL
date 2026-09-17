"""
Stage-one structural suspicion scoring (Three-Objective-Workflow.md,
Objective 1): for every method in the app's own package, combine three
static, LLM-independent signals into one suspicion score:

  1. reachability from a sensitive API (+ shortest distance)
  2. distance from an entry point reachable without user interaction
  3. control-flow irregularity (cyclomatic complexity of the method itself)

No LLM is involved anywhere in this module.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from . import sensitive_apis


def normalize_descriptor(descriptor: str) -> str:
    """androguard's EncodedMethod.get_descriptor() inserts a space after each
    ';' between parameter types (e.g. '(Landroid/view/View; Landroid/os/Bundle;)V'),
    which raw smali/DEX descriptors never contain. Strip it so descriptors are
    comparable against ground-truth signatures parsed from smali text."""
    return descriptor.replace(" ", "")


def _full_name(data: dict) -> str:
    descriptor = normalize_descriptor(data.get("descriptor", ""))
    return f"{data.get('classname')}->{data.get('methodname')}{descriptor}"


def find_sensitive_nodes(cg: nx.DiGraph) -> set:
    sensitive = set()
    for node, data in cg.nodes(data=True):
        if sensitive_apis.is_sensitive(_full_name(data)):
            sensitive.add(node)
    return sensitive


def _multi_source_bfs_distance(graph: nx.DiGraph, sources: set) -> dict:
    """Single-pass multi-source BFS. Returns {node: hop_distance} for every
    node reachable from `sources` following `graph`'s edge direction. Sources
    themselves get distance 0."""
    dist = {s: 0 for s in sources}
    q = deque(sources)
    while q:
        u = q.popleft()
        for v in graph.successors(u):
            if v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def distance_to_sensitive(cg: nx.DiGraph, sensitive_nodes: set) -> dict:
    """dist[node] = min hops from `node` to *some* sensitive node, following
    call edges forward (caller -> callee). Implemented as a multi-source BFS
    on the reversed graph seeded from the sensitive nodes, which is
    equivalent and O(V+E) instead of O(V) separate forward BFS/ancestor
    calls."""
    reversed_cg = cg.reverse(copy=False)
    return _multi_source_bfs_distance(reversed_cg, sensitive_nodes)


def distance_from_entry(cg: nx.DiGraph, entry_nodes: set) -> dict:
    """dist[node] = min hops from *some* entry-point node to `node`, following
    call edges forward."""
    return _multi_source_bfs_distance(cg, entry_nodes)


def cyclomatic_complexity(dx, method_node) -> int | None:
    """E - N + 2 over the method's own basic-block CFG. Returns None for
    external (framework/library stub) methods, which have no body to
    analyze."""
    ma = dx.get_method_analysis(method_node)
    if ma is None or ma.is_external():
        return None
    blocks = list(ma.get_basic_blocks())
    if not blocks:
        return None
    n = len(blocks)
    e = sum(len(b.childs) for b in blocks)
    return max(e - n + 2, 1)


def _decay(distance: int | float | None, scale: float = 3.0) -> float:
    """Map a hop distance to (0, 1], smaller distance -> closer to 1.
    Unreachable (None/inf) -> 0."""
    if distance is None or distance == float("inf"):
        return 0.0
    return 1.0 / (1.0 + distance / scale)


@dataclass
class MethodScore:
    classname: str
    methodname: str
    descriptor: str
    dist_to_sensitive: float | None
    sensitive_category: str | None
    dist_from_entry: float | None
    entry_exported: bool
    cyclomatic_complexity: int | None
    score_sensitive: float = field(init=False)
    score_entry: float = field(init=False)
    score_cfg: float = field(init=False)
    suspicion_score: float = field(init=False)

    def __post_init__(self):
        self.score_sensitive = _decay(self.dist_to_sensitive)
        entry_score = _decay(self.dist_from_entry)
        # An entry point an attacker can reach without user interaction
        # (exported component) is weighted higher than one that requires the
        # user to open the app first, per Objective 1's stage-one definition.
        self.score_entry = entry_score * (1.0 if self.entry_exported else 0.6)
        cc = self.cyclomatic_complexity or 0
        self.score_cfg = min(cc / 15.0, 1.0)  # 15+ branches -> saturate at 1.0
        # Weights 0.7/0.1/0.2 (decay scale unchanged at 3.0), adopted 2026-09-16
        # after a 66-config grid ablation across all 3 apps (see PROGRESS.md
        # DONE + weight_ablation.py): identical recall/precision to the prior
        # 0.5/0.3/0.2 default on the one real app at every cut, strictly
        # better or equal on both fixtures at every cut. Chosen specifically
        # because it does NOT trade real-app performance for fixture
        # performance, unlike the grid's top config by raw mean-recall (see
        # PROGRESS.md JUDGE LOG for why that one was rejected).
        self.suspicion_score = round(
            0.7 * self.score_sensitive + 0.1 * self.score_entry + 0.2 * self.score_cfg,
            4,
        )


def score_app_methods(
    dx,
    cg: nx.DiGraph,
    package_prefix: str,
    entry_nodes: dict,
) -> list[MethodScore]:
    """Scores every non-external method whose classname starts with
    `package_prefix` (the app's own smali package, e.g. 'Llu/snt/trux/koopaapp/'),
    matching the scope MalLoc's own full-app run used (99 app classes,
    excluding ~17.8k bundled third-party library classes — see
    MalLoc/PROGRESS.md sec 4.4)."""
    sensitive_nodes = find_sensitive_nodes(cg)
    dist_sens = distance_to_sensitive(cg, sensitive_nodes)
    dist_entry = distance_from_entry(cg, set(entry_nodes.keys()))

    results = []
    for node, data in cg.nodes(data=True):
        if data.get("external"):
            continue
        classname = data.get("classname", "")
        if not classname.startswith(package_prefix):
            continue

        d_sens = dist_sens.get(node)
        sens_category = None
        if d_sens == 0:
            sens_category = sensitive_apis.category_for(_full_name(data))
        elif d_sens is not None:
            # category of the nearest sensitive node isn't tracked per-hop;
            # re-derive by checking direct successors that are sensitive.
            for succ in cg.successors(node):
                cat = sensitive_apis.category_for(_full_name(cg.nodes[succ]))
                if cat:
                    sens_category = cat
                    break

        results.append(
            MethodScore(
                classname=classname,
                methodname=data.get("methodname"),
                descriptor=normalize_descriptor(data.get("descriptor", "")),
                dist_to_sensitive=d_sens,
                sensitive_category=sens_category,
                dist_from_entry=dist_entry.get(node),
                entry_exported=bool(entry_nodes.get(node, False)),
                cyclomatic_complexity=cyclomatic_complexity(dx, node),
            )
        )
    return results
