package org.research.syntheticmalloc;

/** Shared entry point deliberately separated from simulated behaviours. */
public final class ScenarioBootstrap {
    public void install() {
        ScenarioRouter router = new ScenarioRouter();
        router.registerCallbacks();
    }
}
