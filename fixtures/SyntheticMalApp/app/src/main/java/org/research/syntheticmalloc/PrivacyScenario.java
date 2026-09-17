package org.research.syntheticmalloc;

/** Inert model of profile aggregation; it accesses no device/user records. */
public final class PrivacyScenario {
    public void deriveSyntheticProfile(String fixtureIdentity) {
        String pseudonym = "profile:" + fixtureIdentity.length();
        EvidenceRecorder.record(pseudonym);
        queueLocalAudit(pseudonym);
    }

    private void queueLocalAudit(String pseudonym) {
        // No contacts, location, identifiers, persistence, or exfiltration.
        EvidenceRecorder.record("simulated-profile-audit:" + pseudonym);
    }
}
