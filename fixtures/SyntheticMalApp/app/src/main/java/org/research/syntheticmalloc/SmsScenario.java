package org.research.syntheticmalloc;

/** Inert model of message-token classification; it receives no SMS broadcast. */
public final class SmsScenario {
    public void classifySyntheticEnvelope(String fixtureToken) {
        String category = fixtureToken.startsWith("fixture-") ? "otp-like" : "other";
        EvidenceRecorder.record("simulated-message-class:" + category);
        retainOnlyFixtureMarker(category);
    }

    private void retainOnlyFixtureMarker(String category) {
        // No interception, abortBroadcast, deletion, forwarding, or telephony access.
        EvidenceRecorder.record("simulated-message-marker:" + category);
    }
}
