package org.research.realisticmalapp;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.provider.CallLog;
import android.telephony.TelephonyManager;

/** Behavior 2 (SMS/CALL Abuse), safely reinterpreted: this fixture reads
 * telephony identifiers and the call log ("telephony API usage" and
 * "monitoring call logs" from MalLoc's own behavior-2 "Look for" cues) but
 * never sends, intercepts, or deletes an SMS: no SEND_SMS/READ_SMS/
 * RECEIVE_SMS permission is declared anywhere in this app. See
 * fixtures/README.md. */
public final class TelephonyScenario {

    public void harvestPhoneIdentifiers(Context context) {
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        String line1 = null;
        if (tm != null) {
            try {
                line1 = tm.getLine1Number();
            } catch (SecurityException ignored) {
                // Expected without READ_PRIVILEGED_PHONE_STATE on modern targetSdk;
                // the static call site is what this fixture is testing, not the
                // runtime result.
            }
        }
        EvidenceRecorder.record("phone-number-present:" + (line1 != null));
    }

    public void harvestCallLogSnapshot(Context context) {
        ContentResolver resolver = context.getContentResolver();
        Cursor cursor = resolver.query(CallLog.Calls.CONTENT_URI, null, null, null, null);
        int count = cursor != null ? cursor.getCount() : 0;
        if (cursor != null) {
            cursor.close();
        }
        EvidenceRecorder.record("call-log-count:" + count);
    }
}
