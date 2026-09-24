"""APK loading, call-graph construction and entry-point detection (Stage 1).

This is a thin layer over androguard. The call graph it returns has one node
per method (androguard's `EncodedMethod` or `ExternalMethod`) and one
caller -> callee edge per pair, regardless of how many call sites exist.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import networkx as nx
from androguard.misc import AnalyzeAPK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Callback names that count as entry points when they appear in an entry class.
# androguard's own entry-point flag marks every method of such a class, which
# also counts private helpers the framework never calls.
ENTRY_POINT_METHOD_NAMES = {
    # Activity and Fragment lifecycle
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onRestart", "onCreateView", "onActivityResult", "onNewIntent",
    "onRequestPermissionsResult",
    # Service lifecycle
    "onStartCommand", "onBind", "onUnbind", "onHandleIntent", "onRebind",
    # BroadcastReceiver
    "onReceive",
    # ContentProvider
    "query", "insert", "update", "delete",
    # Background work that can run without any UI interaction
    "doInBackground", "run", "onLocationChanged",
}

# Framework base classes that have lifecycle callbacks but are never declared
# in the manifest, because an Activity or a FragmentManager hosts them. A
# manifest-only entry-point search misses every method of these classes.
# Markers are matched as substrings of the superclass chain, so both
# android.app.* and androidx.* variants are covered.
LIFECYCLE_BASE_CLASS_MARKERS = (
    "/Fragment;", "/DialogFragment;", "/ListFragment;", "/PreferenceFragment;",
    "/AsyncTask;", "/IntentService;", "/Worker;", "/ListenableWorker;",
    "/ViewModel;", "$Adapter;", "/RecyclerView$Adapter;",
)

# Lambda and anonymous-class names, e.g. Foo$$ExternalSyntheticLambda0 or Foo$1.
_LISTENER_CLASS_PATTERN = re.compile(r"\$\$ExternalSyntheticLambda\d+;$|\$\d+;$")


@dataclass(frozen=True)
class Component:
    classname: str  # smali form, e.g. 'Lcom/example/Main;'
    kind: str  # activity | service | receiver | provider
    exported: bool


def load_apk(apk_path: str):
    """Returns androguard's (APK, list of DalvikVMFormat, Analysis) triple."""
    logging.getLogger("androguard").setLevel(logging.CRITICAL)
    apk, dex_files, analysis = AnalyzeAPK(apk_path)
    return apk, dex_files, analysis


def build_call_graph(analysis) -> nx.DiGraph:
    return analysis.get_call_graph()


def add_callback_dispatch_edges(call_graph: nx.DiGraph) -> int:
    """Connects listener construction sites to the listener's callback methods.

    The plain call graph has an edge to a lambda's or anonymous listener's
    `<init>`, but none from there to the callback (`onClick`, `run`, ...). The
    framework makes that call after the listener is registered, so no invoke
    instruction links the two. For every caller of such an `<init>`, this adds
    an edge to each other method of the same class.

    The heuristic favors soundness over completeness: a listener that is built
    but never registered still gets connected. Returns the number of edges added.
    """
    methods_by_class: dict[str, list] = {}
    for node, data in call_graph.nodes(data=True):
        methods_by_class.setdefault(data.get("classname", ""), []).append(node)

    added = 0
    for node, data in list(call_graph.nodes(data=True)):
        if data.get("methodname") != "<init>":
            continue
        classname = data.get("classname", "")
        if not _LISTENER_CLASS_PATTERN.search(classname):
            continue
        callers = list(call_graph.predecessors(node))
        callbacks = [m for m in methods_by_class.get(classname, []) if m != node]
        for caller in callers:
            for callback in callbacks:
                if not call_graph.has_edge(caller, callback):
                    call_graph.add_edge(caller, callback, synthetic=True)
                    added += 1
    return added


def _exported_map(apk, tag: str) -> dict[str, bool]:
    """Maps each component name declared under `tag` to its exported flag."""
    manifest = apk.get_android_manifest_xml()
    exported_by_name: dict[str, bool] = {}
    if manifest is None:
        return exported_by_name
    for element in manifest.findall(f".//{tag}"):
        name = element.get(f"{ANDROID_NS}name")
        if name is None:
            continue
        exported_attr = element.get(f"{ANDROID_NS}exported")
        if exported_attr is not None:
            exported = exported_attr == "true"
        else:
            # Without the attribute, a component is exported only if it has an
            # intent filter (the behavior before Android 12).
            exported = element.find("intent-filter") is not None
        exported_by_name[name] = exported
    return exported_by_name


def _to_smali_classname(package: str, manifest_name: str) -> str:
    """Converts a manifest name ('.Main', 'Main' or 'com.foo.Main') to 'Lcom/foo/Main;'."""
    if manifest_name.startswith("."):
        qualified = package + manifest_name
    elif "." not in manifest_name:
        qualified = package + "." + manifest_name
    else:
        qualified = manifest_name
    return "L" + qualified.replace(".", "/") + ";"


def _superclass_chain(analysis, classname: str, max_depth: int = 25) -> list[str]:
    chain: list[str] = []
    current = classname
    for _ in range(max_depth):
        class_analysis = analysis.classes.get(current)
        if class_analysis is None:
            break
        superclass = class_analysis.extends
        if not superclass or superclass in chain:
            break
        chain.append(superclass)
        current = superclass
    return chain


def is_lifecycle_bearing_class(analysis, classname: str) -> bool:
    return any(
        marker in ancestor
        for ancestor in _superclass_chain(analysis, classname)
        for marker in LIFECYCLE_BASE_CLASS_MARKERS
    )


def get_components(apk) -> list[Component]:
    package = apk.get_package()
    tags_and_kinds = [
        ("activity", "activity"),
        ("activity-alias", "activity"),
        ("service", "service"),
        ("receiver", "receiver"),
        ("provider", "provider"),
    ]
    components: list[Component] = []
    for tag, kind in tags_and_kinds:
        for manifest_name, exported in _exported_map(apk, tag).items():
            components.append(
                Component(
                    classname=_to_smali_classname(package, manifest_name),
                    kind=kind,
                    exported=exported,
                )
            )
    return components


def get_entry_point_nodes(analysis, call_graph: nx.DiGraph,
                          components: list[Component]) -> dict:
    """Returns {node: exported} for the call-graph nodes that act as entry points.

    A node qualifies if its method has a lifecycle-callback name and its class is
    either declared in the manifest or extends a lifecycle base class (see
    LIFECYCLE_BASE_CLASS_MARKERS). Classes of the second kind are never
    exported, since they only run once the app is already running. A qualifying
    class with no callback-named method in the graph (for example, one that
    inherits its callbacks) has all of its methods treated as entry points.
    """
    component_by_class = {c.classname: c for c in components}
    entry_nodes: dict = {}
    classes_with_callback: set[str] = set()
    lifecycle_cache: dict[str, bool] = {}

    def entry_class_info(classname: str) -> tuple[bool, bool]:
        """Returns (is_entry_class, exported)."""
        component = component_by_class.get(classname)
        if component is not None:
            return True, component.exported
        if classname not in lifecycle_cache:
            lifecycle_cache[classname] = is_lifecycle_bearing_class(analysis, classname)
        return lifecycle_cache[classname], False

    for node, data in call_graph.nodes(data=True):
        classname = data.get("classname")
        is_entry, exported = entry_class_info(classname)
        if is_entry and data.get("methodname") in ENTRY_POINT_METHOD_NAMES:
            entry_nodes[node] = exported
            classes_with_callback.add(classname)

    for node, data in call_graph.nodes(data=True):
        classname = data.get("classname")
        if classname in classes_with_callback:
            continue
        is_entry, exported = entry_class_info(classname)
        if is_entry:
            entry_nodes[node] = exported

    return entry_nodes
