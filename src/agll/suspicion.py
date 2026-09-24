"""Stage 1 structural suspicion score. No LLM is involved.

Every method in the application's own package gets a score built from three
signals:

  1. call-graph distance to a sensitive API,
  2. call-graph distance from an entry point,
  3. cyclomatic complexity of the method.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from . import sensitive_apis

WEIGHT_SENSITIVE = 0.7
WEIGHT_ENTRY = 0.1
WEIGHT_CFG = 0.2

# Entry points reachable without user interaction (exported components) count
# fully; the rest are discounted.
NON_EXPORTED_ENTRY_FACTOR = 0.6
COMPLEXITY_SATURATION = 15
DECAY_SCALE = 3.0


def normalize_descriptor(descriptor: str) -> str:
    """Removes the spaces androguard puts between parameter types.

    androguard renders '(Landroid/view/View; Landroid/os/Bundle;)V', while smali
    signatures never contain spaces, so descriptors must be normalized before
    they are compared with ground-truth signatures.
    """
    return descriptor.replace(" ", "")


def _full_name(data: dict) -> str:
    descriptor = normalize_descriptor(data.get("descriptor", ""))
    return f"{data.get('classname')}->{data.get('methodname')}{descriptor}"


def find_sensitive_nodes(call_graph: nx.DiGraph) -> set:
    return {
        node for node, data in call_graph.nodes(data=True)
        if sensitive_apis.is_sensitive(_full_name(data))
    }


def _multi_source_bfs(graph: nx.DiGraph, sources: set) -> dict:
    """Hop distance from the nearest source to every reachable node."""
    distance = {source: 0 for source in sources}
    queue = deque(sources)
    while queue:
        node = queue.popleft()
        for neighbor in graph.successors(node):
            if neighbor not in distance:
                distance[neighbor] = distance[node] + 1
                queue.append(neighbor)
    return distance


def distance_to_sensitive(call_graph: nx.DiGraph, sensitive_nodes: set) -> dict:
    """Minimum number of call hops from each node to any sensitive node.

    A single BFS over the reversed graph, seeded with all sensitive nodes, gives
    every node's distance in O(V + E).
    """
    return _multi_source_bfs(call_graph.reverse(copy=False), sensitive_nodes)


def distance_from_entry(call_graph: nx.DiGraph, entry_nodes: set) -> dict:
    """Minimum number of call hops from any entry point to each node."""
    return _multi_source_bfs(call_graph, entry_nodes)


def cyclomatic_complexity(analysis, method_node) -> int | None:
    """E - N + 2 over the method's basic-block graph, or None for external methods."""
    method_analysis = analysis.get_method_analysis(method_node)
    if method_analysis is None or method_analysis.is_external():
        return None
    blocks = list(method_analysis.get_basic_blocks())
    if not blocks:
        return None
    edge_count = sum(len(block.childs) for block in blocks)
    return max(edge_count - len(blocks) + 2, 1)


def _decay(distance: float | None, scale: float = DECAY_SCALE) -> float:
    """Maps a hop distance to (0, 1]; unreachable maps to 0."""
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
        entry_factor = 1.0 if self.entry_exported else NON_EXPORTED_ENTRY_FACTOR
        self.score_entry = _decay(self.dist_from_entry) * entry_factor
        complexity = self.cyclomatic_complexity or 0
        self.score_cfg = min(complexity / COMPLEXITY_SATURATION, 1.0)
        self.suspicion_score = round(
            WEIGHT_SENSITIVE * self.score_sensitive
            + WEIGHT_ENTRY * self.score_entry
            + WEIGHT_CFG * self.score_cfg,
            4,
        )


def score_app_methods(
    analysis,
    call_graph: nx.DiGraph,
    package_prefix: str,
    entry_nodes: dict,
) -> list[MethodScore]:
    """Scores every non-external method whose class starts with `package_prefix`.

    The prefix is the application's own package in smali form, for example
    'Lorg/example/app/', so bundled third-party libraries are left out.
    """
    sensitive_nodes = find_sensitive_nodes(call_graph)
    sensitive_dist = distance_to_sensitive(call_graph, sensitive_nodes)
    entry_dist = distance_from_entry(call_graph, set(entry_nodes.keys()))

    scores = []
    for node, data in call_graph.nodes(data=True):
        if data.get("external"):
            continue
        classname = data.get("classname", "")
        if not classname.startswith(package_prefix):
            continue

        distance = sensitive_dist.get(node)
        category = None
        if distance == 0:
            category = sensitive_apis.category_for(_full_name(data))
        elif distance is not None:
            # The BFS keeps distances only, so the category is recovered from
            # the first directly called sensitive method, if there is one.
            for successor in call_graph.successors(node):
                found = sensitive_apis.category_for(_full_name(call_graph.nodes[successor]))
                if found:
                    category = found
                    break

        scores.append(
            MethodScore(
                classname=classname,
                methodname=data.get("methodname"),
                descriptor=normalize_descriptor(data.get("descriptor", "")),
                dist_to_sensitive=distance,
                sensitive_category=category,
                dist_from_entry=entry_dist.get(node),
                entry_exported=bool(entry_nodes.get(node, False)),
                cyclomatic_complexity=cyclomatic_complexity(analysis, node),
            )
        )
    return scores
