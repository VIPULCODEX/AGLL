package org.research.realisticmalapp;

import android.app.Activity;
import android.os.Bundle;

/** Launcher entry point for the fixture. See ../METHODOLOGY.md. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        new ScenarioRouter().registerCallbacks(this);
    }
}
