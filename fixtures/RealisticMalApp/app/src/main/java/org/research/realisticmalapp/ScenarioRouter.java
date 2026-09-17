package org.research.realisticmalapp;

import android.content.Context;

/**
 * Callback wiring is intentionally present to exercise call-graph narrowing
 * (specifically the constructor-to-run() / lambda-dispatch edge case — see
 * ../../AGLL/PROGRESS.md KNOWN ISSUES on callback-dispatch heuristics).
 * Invokes callbacks synchronously; Android framework registration (e.g. a
 * real click listener) is deliberately absent, matching
 * ../../SyntheticMalApp's convention.
 */
public final class ScenarioRouter {
    public void registerCallbacks(final Context context) {
        Runnable location = new Runnable() {
            @Override public void run() { new PrivacyScenario().harvestDeviceLocation(context); }
        };
        Runnable contacts = new Runnable() {
            @Override public void run() { new PrivacyScenario().harvestContactDirectory(context); }
        };
        Runnable rootProbe = new Runnable() {
            @Override public void run() { new EscalationScenario().probeSystemPaths(); }
        };
        Runnable fileWrite = new Runnable() {
            @Override public void run() { new EscalationScenario().modifyPrivateConfigFile(context); }
        };
        dispatch(location); dispatch(contacts); dispatch(rootProbe); dispatch(fileWrite);
    }

    private void dispatch(Runnable callback) { callback.run(); }
}
