package org.research.realisticmalapp;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

/** Non-exported Service entry point — tests AGLL's entry-point detection
 * against a Service lifecycle callback (onStartCommand), reached only via
 * an internal startService() call, not directly by the OS or another app.
 * See ../METHODOLOGY.md. */
public final class MaintenanceService extends Service {
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        new TrickyScenario().hideAppIcon(this);
        new TrickyScenario().readDeviceAndroidId(this);
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }
}
