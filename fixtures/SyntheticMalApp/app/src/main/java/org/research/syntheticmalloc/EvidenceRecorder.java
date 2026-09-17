package org.research.syntheticmalloc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** In-memory audit sink. It has no I/O, IPC, network, or Android sensitive API. */
public final class EvidenceRecorder {
    private static final List<String> EVENTS = new ArrayList<>();
    public static void record(String event) { EVENTS.add(event); }
    public static List<String> snapshot() { return Collections.unmodifiableList(EVENTS); }
}
