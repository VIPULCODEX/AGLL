package org.research.realisticmalapp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** In-memory audit sink. It has no I/O, IPC, or network of its own; it
 * only records that a scenario method ran, it does not implement any
 * sensitive behavior itself. */
public final class EvidenceRecorder {
    private static final List<String> EVENTS = new ArrayList<>();
    public static void record(String event) { EVENTS.add(event); }
    public static List<String> snapshot() { return Collections.unmodifiableList(EVENTS); }
}
