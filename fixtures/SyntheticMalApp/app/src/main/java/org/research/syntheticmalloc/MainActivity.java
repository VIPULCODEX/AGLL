package org.research.syntheticmalloc;

import android.app.Activity;
import android.os.Bundle;

/** Launcher for an inert, controlled analysis fixture. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        new ScenarioBootstrap().install();
    }
}
