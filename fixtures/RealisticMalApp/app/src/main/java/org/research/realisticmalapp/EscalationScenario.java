package org.research.realisticmalapp;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/** Behavior 7 (Privilege Escalation), reinterpreted with real but harmless
 * APIs: a root-check pattern ("Root checking" from MalLoc's own behavior-7
 * "Look for" cues) and a write to the app's OWN private storage ("system
 * file operations" — this never touches a real system path or another
 * app's data; `openFileOutput` is sandboxed to this app by the OS). See
 * ../METHODOLOGY.md. */
public final class EscalationScenario {

    public void probeSystemPaths() {
        boolean suSuspected = new File("/system/xbin/su").exists()
                || new File("/system/bin/su").exists();
        EvidenceRecorder.record("root-probe:" + suSuspected);
    }

    public void modifyPrivateConfigFile(Context context) {
        try (FileOutputStream fos = context.openFileOutput("config.dat", Context.MODE_PRIVATE)) {
            fos.write("fixture-marker".getBytes());
        } catch (IOException e) {
            EvidenceRecorder.record("private-config-write-failed");
            return;
        }
        EvidenceRecorder.record("private-config-write-ok");
    }
}
