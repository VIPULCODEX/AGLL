"""
APK loading, call-graph construction, and entry-point identification for
Objective 1 stage one (see Three-Objective-Workflow.md). Thin wrapper around
androguard 4.1.4 — see PROGRESS.md DECISIONS & WHY for why androguard was
chosen and how its call graph is shaped (nodes are raw
`androguard.core.dex.EncodedMethod` / `ExternalMethod` objects, edges are
caller -> callee, one edge per caller/callee pair regardless of call count).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import networkx as nx
from androguard.misc import AnalyzeAPK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Lifecycle / callback method names treated as entry points when they occur
# inside a manifest-declared component class. This is deliberately narrower
# than androguard's own get_call_graph(entry_points=...) flag, which marks
# every method of an entry-point class as "entrypoint" — that overcounts
# (e.g. a private helper method never invoked by the framework). Restricting
# to actual callback names is a design choice, see PROGRESS.md.
ENTRY_POINT_METHOD_NAMES = {
    # Activity / Fragment lifecycle
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onRestart", "onCreateView", "onActivityResult", "onNewIntent",
    "onRequestPermissionsResult",
    # Service lifecycle
    "onStartCommand", "onBind", "onUnbind", "onHandleIntent", "onRebind",
    # BroadcastReceiver
    "onReceive",
    # ContentProvider
    "query", "insert", "update", "delete", "onCreate",
    # Background work / threads, common attacker-triggerable-without-UI paths
    "doInBackground", "run", "onLocationChanged",
}


def load_apk(apk_path: str):
    logging.getLogger("androguard").setLevel(logging.CRITICAL)
    a, d, dx = AnalyzeAPK(apk_path)
    return a, d, dx


def build_call_graph(dx) -> nx.DiGraph:
    return dx.get_call_graph()


def add_callback_dispatch_edges(cg: nx.DiGraph) -> int:
    """Verified gap (see PROGRESS.md KNOWN ISSUES): androguard's plain call
    graph has an edge from a site to a lambda/anonymous-listener class's
    `<init>` (the `new Foo(...)` call), but no edge from there to the
    listener's actual callback method (`onClick`, `run`, `accept`, ...) —
    that dispatch happens inside the Android framework once the listener is
    registered, with no `invoke-*` bytecode connecting the two. Confirmed by
    direct inspection: in the MalApp_1_9_11 sample,
    `RequestData2Fragment$$ExternalSyntheticLambda0-><init>` was reachable
    from `onCreateView` (dist 1) while its sibling `onClick` method — which
    contains the actual `sendEmail` call — was unreachable (dist None).

    This adds a synthetic edge from every caller of a lambda/anon-listener
    class's `<init>` to every other (non-`<init>`) method in that same class,
    modeling "constructing and registering a listener implies the framework
    will eventually invoke it." This is a soundness-over-completeness
    heuristic (may add edges for listeners that are constructed but never
    actually registered) rather than a fix that models real Android listener
    registration APIs (setOnClickListener, etc.) precisely — see PROGRESS.md
    for why that fuller fix was out of scope for this pass.

    Returns the number of synthetic edges added.
    """
    import re

    lambda_marker = re.compile(r"\$\$ExternalSyntheticLambda\d+;$|\$\d+;$")

    nodes_by_class: dict[str, list] = {}
    for node, data in cg.nodes(data=True):
        nodes_by_class.setdefault(data.get("classname", ""), []).append(node)

    added = 0
    for node, data in list(cg.nodes(data=True)):
        if data.get("methodname") != "<init>":
            continue
        classname = data.get("classname", "")
        if not lambda_marker.search(classname):
            continue
        callers = list(cg.predecessors(node))
        siblings = [n for n in nodes_by_class.get(classname, []) if n != node]
        for caller in callers:
            for sibling in siblings:
                if not cg.has_edge(caller, sibling):
                    cg.add_edge(caller, sibling, synthetic=True)
                    added += 1
    return added


@dataclass(frozen=True)
class Component:
    classname: str  # 'Lpkg/Class;' form
    kind: str  # activity | service | receiver | provider
    exported: bool


def _exported_map(a, tag: str) -> dict[str, bool]:
    """Map manifest component name (as declared, possibly relative, e.g.
    '.MainActivity') -> exported bool, for a given manifest tag
    (activity/activity-alias/service/receiver/provider)."""
    manifest = a.get_android_manifest_xml()
    result: dict[str, bool] = {}
    if manifest is None:
        return result
    for el in manifest.findall(f".//{tag}"):
        name = el.get(f"{ANDROID_NS}name")
        if name is None:
            continue
        exported_attr = el.get(f"{ANDROID_NS}exported")
        if exported_attr is not None:
            exported = exported_attr == "true"
        else:
            # No explicit attribute: implicitly exported if it has an
            # intent-filter (pre-Android-12 default behaviour), else private.
            exported = el.find("intent-filter") is not None
        result[name] = exported
    return result


def _to_dex_classname(package: str, manifest_name: str) -> str:
    """Manifest component names are Java-style ('com.foo.Bar' or
    '.Bar' relative to the package); dex/call-graph classnames are smali-style
    ('Lcom/foo/Bar;'). Normalize the former to the latter."""
    if manifest_name.startswith("."):
        full = package + manifest_name
    elif "." not in manifest_name:
        full = package + "." + manifest_name
    else:
        full = manifest_name
    return "L" + full.replace(".", "/") + ";"


# Android framework base classes that carry their own lifecycle callbacks but
# are never declared in AndroidManifest.xml (Fragments are hosted by an
# Activity/FragmentManager, not launched by the OS directly). Verified bug:
# an earlier version of this pipeline scoped entry points to manifest
# components only, which silently zeroed out `dist_from_entry` for every
# Fragment method in the sample app — including the ground-truth malicious
# RequestData2Fragment — because androguard's plain call graph has no edge
# modeling FragmentManager-mediated instantiation. See PROGRESS.md KNOWN
# ISSUES for the root-cause writeup. Matched as a substring against the
# superclass chain, so both android.app.* and androidx.* variants match.
LIFECYCLE_BASE_CLASS_MARKERS = (
    "/Fragment;", "/DialogFragment;", "/ListFragment;", "/PreferenceFragment;",
    "/AsyncTask;", "/IntentService;", "/Worker;", "/ListenableWorker;",
    "/ViewModel;", "$Adapter;", "/RecyclerView$Adapter;",
)


def _superclass_chain(dx, classname: str, max_depth: int = 25) -> list[str]:
    chain = []
    current = classname
    for _ in range(max_depth):
        ca = dx.classes.get(current)
        if ca is None:
            break
        superclass = ca.extends
        if not superclass or superclass in chain:
            break
        chain.append(superclass)
        current = superclass
    return chain


def is_lifecycle_bearing_class(dx, classname: str) -> bool:
    for ancestor in _superclass_chain(dx, classname):
        if any(marker in ancestor for marker in LIFECYCLE_BASE_CLASS_MARKERS):
            return True
    return False


def get_components(a) -> list[Component]:
    package = a.get_package()
    components: list[Component] = []
    tag_kind = [
        ("activity", "activity"),
        ("activity-alias", "activity"),
        ("service", "service"),
        ("receiver", "receiver"),
        ("provider", "provider"),
    ]
    for tag, kind in tag_kind:
        for manifest_name, exported in _exported_map(a, tag).items():
            components.append(
                Component(
                    classname=_to_dex_classname(package, manifest_name),
                    kind=kind,
                    exported=exported,
                )
            )
    return components


def get_entry_point_nodes(dx, cg: nx.DiGraph, components: list[Component]) -> dict:
    """Returns {node: exported_bool} for call-graph nodes that are named like
    a framework lifecycle callback and belong to either (a) a
    manifest-declared component class, or (b) a class that (transitively)
    extends a lifecycle-bearing framework base class not declared in the
    manifest (Fragment, AsyncTask, ViewModel, RecyclerView.Adapter, ... — see
    LIFECYCLE_BASE_CLASS_MARKERS). (b) always gets exported=False since it is
    only reachable once the app is already running, never directly by
    external IPC. Falls back to marking every method of a class as an entry
    point if no lifecycle-named method for that class is found in the graph
    (e.g. inherited, not overridden — still worth treating the class as
    reachable)."""
    component_by_class = {c.classname: c for c in components}
    entry_nodes: dict = {}
    classes_with_named_hit: set[str] = set()
    lifecycle_class_cache: dict[str, bool] = {}

    def is_entry_class(classname: str) -> tuple[bool, bool]:
        """Returns (is_entry_class, exported)."""
        comp = component_by_class.get(classname)
        if comp is not None:
            return True, comp.exported
        cached = lifecycle_class_cache.get(classname)
        if cached is None:
            cached = is_lifecycle_bearing_class(dx, classname)
            lifecycle_class_cache[classname] = cached
        return cached, False

    for node, data in cg.nodes(data=True):
        classname = data.get("classname")
        is_entry, exported = is_entry_class(classname)
        if not is_entry:
            continue
        if data.get("methodname") in ENTRY_POINT_METHOD_NAMES:
            entry_nodes[node] = exported
            classes_with_named_hit.add(classname)

    for node, data in cg.nodes(data=True):
        classname = data.get("classname")
        if classname in classes_with_named_hit:
            continue
        is_entry, exported = is_entry_class(classname)
        if not is_entry:
            continue
        entry_nodes[node] = exported

    return entry_nodes
