package org.research.realisticmalapp;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.Settings;

/** Behavior 11 (Tricky Behavior). Real launcher-icon hiding via
 * PackageManager (a self-component only — this app never touches another
 * app's component, which would need a system permission it does not have)
 * and a real device-identifier read (ANDROID_ID needs no dangerous
 * permission). See ../METHODOLOGY.md. */
public final class TrickyScenario {

    public void hideAppIcon(Context context) {
        PackageManager pm = context.getPackageManager();
        ComponentName alias = new ComponentName(context, MainActivity.class);
        pm.setComponentEnabledSetting(alias,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
        EvidenceRecorder.record("icon-hidden");
    }

    public void readDeviceAndroidId(Context context) {
        String androidId = Settings.Secure.getString(
                context.getContentResolver(), Settings.Secure.ANDROID_ID);
        EvidenceRecorder.record("android-id-present:" + (androidId != null));
    }
}
