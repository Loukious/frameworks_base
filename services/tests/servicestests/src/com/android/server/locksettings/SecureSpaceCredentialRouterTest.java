/*
 * Copyright (C) 2026 The Android Open Source Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.server.locksettings;

import static com.android.server.locksettings.SecureSpaceCredentialRouter.*;
import static org.junit.Assert.*;

import org.junit.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Host tests for attempt policy; these do not emulate Gatekeeper, Weaver, or user switching. */
public class SecureSpaceCredentialRouterTest {
    private static final Candidate CURRENT = new Candidate(10, 100);
    private static final Candidate OWNER = new Candidate(0, 0);
    private static final Candidate OTHER = new Candidate(11, 101);
    private static final List<Candidate> USERS = List.of(CURRENT, OWNER, OTHER);
    private static final Probe WRONG = new Probe(INCORRECT, 0, false);
    private static final Probe MATCH = new Probe(MATCHED, 0, false);
    private static final Probe ERROR = new Probe(INCONCLUSIVE, 0, false);
    private static final Probe RETRY = new Probe(INCONCLUSIVE, 30_000, false);

    private static class FakeVerifier implements Verifier {
        final List<Candidate> checked = new ArrayList<>();
        final List<Probe> responses;
        int invalidAfter = Integer.MAX_VALUE;
        Candidate stale;

        FakeVerifier(Probe... responses) { this.responses = List.of(responses); }

        public boolean isCurrent(Candidate candidate) {
            return !candidate.equals(stale) && checked.size() < invalidAfter;
        }

        public Probe verify(Candidate candidate) {
            checked.add(candidate);
            return responses.get(checked.size() - 1);
        }
    }

    @Test
    public void currentMatchTakesPrecedenceWithoutProbingOtherUsers() {
        FakeVerifier verifier = new FakeVerifier(MATCH, MATCH, MATCH);
        Result result = check(USERS, verifier);
        assertEquals(CURRENT, result.matched);
        assertEquals(List.of(CURRENT), verifier.checked);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void alternateMatchCarriesActualSerialAndStopsScan() {
        FakeVerifier verifier = new FakeVerifier(WRONG, MATCH, MATCH);
        Result result = check(USERS, verifier);
        assertEquals(OWNER, result.matched);
        assertEquals(List.of(CURRENT, OWNER), verifier.checked);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void retryDoesNotBlockHealthyAlternateAndRetainsItsOwnTimeout() {
        FakeVerifier verifier = new FakeVerifier(RETRY, MATCH);
        Result result = check(USERS, verifier);
        assertEquals(OWNER, result.matched);
        assertEquals(30_000, result.attempts.get(0).probe().timeoutMillis());
        assertEquals(CURRENT, result.attempts.get(0).candidate());
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void retryThenWrongCannotAuthorizeDuress() {
        Result result = check(USERS, new FakeVerifier(RETRY, WRONG, WRONG));
        assertNull(result.matched);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void serviceErrorThenWrongCannotAuthorizeDuress() {
        Result result = check(USERS, new FakeVerifier(WRONG, ERROR, WRONG));
        assertNull(result.matched);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void onlyAllDefiniteWrongResultsCompleteNegativeDecision() {
        FakeVerifier verifier = new FakeVerifier(WRONG, WRONG, WRONG);
        Result result = check(USERS, verifier);
        assertNull(result.matched);
        assertTrue(result.allCertainlyIncorrect);
        assertEquals(USERS, verifier.checked);
    }

    @Test
    public void staleCandidateStopsBeforeSpendingItsNativeAttempt() {
        FakeVerifier verifier = new FakeVerifier(WRONG);
        verifier.stale = OWNER;
        Result result = check(USERS, verifier);
        assertEquals(List.of(CURRENT), verifier.checked);
        assertEquals(STALE, result.attempts.get(1).probe().outcome());
        assertNull(result.matched);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void foregroundChangeDuringSuccessfulVerificationRejectsHandoff() {
        FakeVerifier verifier = new FakeVerifier(MATCH);
        verifier.invalidAfter = 1;
        Result result = check(USERS, verifier);
        assertNull(result.matched);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void foregroundChangeAfterFailureStopsAdditionalProbes() {
        FakeVerifier verifier = new FakeVerifier(WRONG);
        verifier.invalidAfter = 1;
        Result result = check(USERS, verifier);
        assertEquals(List.of(CURRENT), verifier.checked);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void duplicateWrongWithNativeTimeoutRetainsBothFacts() {
        Probe duplicate = new Probe(INCORRECT, 60_000, true);
        Result result = check(List.of(CURRENT), new FakeVerifier(duplicate));
        assertTrue(result.allCertainlyIncorrect);
        assertTrue(result.attempts.get(0).probe().duplicate());
        assertEquals(60_000, result.attempts.get(0).probe().timeoutMillis());
    }

    @Test
    public void duplicateUserSnapshotRejectedBeforeAnyNativeAttempt() {
        FakeVerifier verifier = new FakeVerifier();
        try {
            check(List.of(CURRENT, OWNER, new Candidate(10, 102)), verifier);
            fail("Expected invalid snapshot");
        } catch (IllegalArgumentException expected) {
            assertTrue(verifier.checked.isEmpty());
        }
    }

    @Test
    public void resultDoesNotExposeMutableAttemptHistory() {
        Result result = check(List.of(CURRENT), new FakeVerifier(WRONG));
        try {
            result.attempts.clear();
            fail("Expected immutable result");
        } catch (UnsupportedOperationException expected) {
            assertEquals(1, result.attempts.size());
        }
    }

    @Test
    public void earlierUserChangedDuringLaterProbeInvalidatesNegativeDecision() {
        FakeVerifier verifier = new FakeVerifier(WRONG, WRONG, WRONG) {
            @Override
            public boolean isCurrent(Candidate candidate) {
                return !(checked.size() == 3 && candidate.equals(CURRENT));
            }
        };
        Result result = check(USERS, verifier);
        assertEquals(3, result.attempts.size());
        assertNull(result.matched);
        assertFalse(result.allCertainlyIncorrect);
    }

    @Test
    public void nativeTimeoutsBeyondIntegerRangeRemainIntact() {
        assertEquals(3_000_000_000L, timeoutMillis(Duration.ofMillis(3_000_000_000L)));
        assertEquals(0, timeoutMillis(Duration.ZERO));
        assertEquals(1, timeoutMillis(Duration.ofNanos(1)));
    }

    @Test
    public void overflowOrNegativeTimeoutFailsSecure() {
        assertEquals(Long.MAX_VALUE, timeoutMillis(Duration.ofSeconds(Long.MAX_VALUE)));
        assertEquals(Long.MAX_VALUE, timeoutMillis(Duration.ofMillis(-1)));
    }
    @Test(expected = IllegalArgumentException.class)
    public void oversizedCohort_spendsNoHardwareAttempts() {
        FakeVerifier verifier = new FakeVerifier(WRONG, WRONG, WRONG, WRONG, WRONG);
        try {
            check(List.of(CURRENT, OWNER, OTHER, new Candidate(12, 102), new Candidate(13, 103)),
                    verifier);
        } finally {
            assertTrue(verifier.checked.isEmpty());
        }
    }

}
