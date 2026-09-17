package org.research.syntheticmalloc;

/** Inert model of decoy-state selection; it cannot hide components or alter settings. */
public final class TrickyScenario {
    public void selectDecoyState(boolean enabled) {
        String state = enabled ? "decoy-visible" : "normal-visible";
        EvidenceRecorder.record("simulated-decoy-state:" + state);
        explainState(state);
    }

    private void explainState(String state) {
        // No PackageManager calls, component changes, app hiding, or false dialogs.
        EvidenceRecorder.record("simulated-decoy-explanation:" + state);
    }
}
