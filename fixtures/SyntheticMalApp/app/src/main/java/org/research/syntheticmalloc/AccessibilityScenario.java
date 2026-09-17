package org.research.syntheticmalloc;

/** Inert model of the UI-state staging pattern reported for banking trojans. */
public final class AccessibilityScenario {
    public void stageUiModel(String packageLabel) {
        String model = "ui-model:" + packageLabel;
        EvidenceRecorder.record(model);
        emitSimulatedActionPlan(model);
    }

    private void emitSimulatedActionPlan(String model) {
        // Symbolic only: no AccessibilityService, gestures, overlays, or UI control.
        EvidenceRecorder.record("simulated-accessibility-plan:" + model.length());
    }
}
