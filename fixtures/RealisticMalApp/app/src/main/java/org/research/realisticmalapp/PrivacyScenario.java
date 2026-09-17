package org.research.realisticmalapp;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationManager;
import android.provider.ContactsContract;

/** Behavior 1 (Privacy Stealing). Real device-location and contacts reads,
 * kept on-device only — this app has no INTERNET permission and never
 * transmits anything anywhere. See ../METHODOLOGY.md. */
public final class PrivacyScenario {

    public void harvestDeviceLocation(Context context) {
        LocationManager lm = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (lm == null) {
            return;
        }
        Location last = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
        EvidenceRecorder.record("location-snapshot:" + (last != null ? "present" : "absent"));
    }

    public void harvestContactDirectory(Context context) {
        ContentResolver resolver = context.getContentResolver();
        Cursor cursor = resolver.query(ContactsContract.Contacts.CONTENT_URI,
                null, null, null, null);
        int count = cursor != null ? cursor.getCount() : 0;
        if (cursor != null) {
            cursor.close();
        }
        EvidenceRecorder.record("contact-count:" + count);
    }
}
