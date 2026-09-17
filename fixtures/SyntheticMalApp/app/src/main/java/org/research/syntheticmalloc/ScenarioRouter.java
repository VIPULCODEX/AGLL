package org.research.syntheticmalloc;

/**
 * Callback wiring is intentionally present to exercise call-graph narrowing.
 * This class invokes callbacks synchronously so the fixture remains inert and
 * deterministic; Android framework registration is deliberately absent.
 */
public final class ScenarioRouter {
    public void registerCallbacks() {
        Runnable accessibility = new Runnable() {
            @Override public void run() { new AccessibilityScenario().stageUiModel("demo"); }
        };
        Runnable sms = new Runnable() {
            @Override public void run() { new SmsScenario().classifySyntheticEnvelope("fixture-token"); }
        };
        Runnable privacy = new Runnable() {
            @Override public void run() { new PrivacyScenario().deriveSyntheticProfile("fixture-user"); }
        };
        Runnable tricky = new Runnable() {
            @Override public void run() { new TrickyScenario().selectDecoyState(true); }
        };
        dispatch(accessibility); dispatch(sms); dispatch(privacy); dispatch(tricky);
    }

    private void dispatch(Runnable callback) { callback.run(); }
}
