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

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Coordinates one concealed-entry attempt. The verifier must retain native rate limiting.
 *
 * <p>This class deliberately owns no credentials, UI callbacks, or duress actions. A duress
 * verifier may only run after a completed result whose {@link Result#allCertainlyIncorrect}
 * is true. A timeout or service error cannot establish that a normal credential was wrong.
 */
final class SecureSpaceCredentialRouter {
    static final int MAX_CANDIDATES = 4;
    static final int MATCHED = 1;
    static final int INCORRECT = 2;
    static final int INCONCLUSIVE = 3;
    static final int STALE = 4;

    /** Preserve long native lockouts; overflow and negative values must not become no timeout. */
    static long timeoutMillis(Duration timeout) {
        if (timeout.isZero()) {
            return 0;
        }
        if (timeout.isNegative()) {
            return Long.MAX_VALUE;
        }
        try {
            return Math.max(1, timeout.toMillis());
        } catch (ArithmeticException overflow) {
            return Long.MAX_VALUE;
        }
    }

    record Candidate(int userId, int serialNumber) {}

    record Probe(int outcome, long timeoutMillis, boolean duplicate) {
        Probe {
            if (outcome < MATCHED || outcome > STALE || timeoutMillis < 0) {
                throw new IllegalArgumentException("Invalid credential probe");
            }
        }
    }

    record Attempt(Candidate candidate, Probe probe) {}

    interface Verifier {
        /** Checks both foreground identity and candidate serial/eligibility, without probing. */
        boolean isCurrent(Candidate candidate);
        Probe verify(Candidate candidate);
    }

    static final class Result {
        final Candidate matched;
        final List<Attempt> attempts;
        final boolean allCertainlyIncorrect;

        private Result(Candidate matched, List<Attempt> attempts, boolean allIncorrect) {
            this.matched = matched;
            this.attempts = List.copyOf(attempts);
            allCertainlyIncorrect = allIncorrect;
        }
    }

    /** Current user comes first; subsequent order is fixed by the service's snapshot. */
    static Result check(List<Candidate> candidates, Verifier verifier) {
        candidates = List.copyOf(candidates);
        if (candidates.isEmpty() || candidates.size() > MAX_CANDIDATES) {
            throw new IllegalArgumentException("Credential cohort exceeds the native attempt budget");
        }
        // Reject malformed snapshots before spending any native attempts.
        Set<Integer> userIds = new HashSet<>();
        for (Candidate candidate : candidates) {
            if (candidate.userId() < 0 || candidate.serialNumber() < 0
                    || !userIds.add(candidate.userId())) {
                throw new IllegalArgumentException("Invalid routing snapshot");
            }
        }
        List<Attempt> attempts = new ArrayList<>();
        boolean allIncorrect = true;
        for (Candidate candidate : candidates) {
            if (!verifier.isCurrent(candidate)) {
                attempts.add(new Attempt(candidate, new Probe(STALE, 0, false)));
                return new Result(null, attempts, false);
            }
            Probe probe = verifier.verify(candidate);
            attempts.add(new Attempt(candidate, probe));
            // Even a valid credential cannot authorize a deleted/recreated user or a result
            // delivered after an unrelated foreground switch.
            if (!verifier.isCurrent(candidate) || probe.outcome() == STALE) {
                return new Result(null, attempts, false);
            }
            if (probe.outcome() == MATCHED) {
                return new Result(candidate, attempts, false);
            }
            allIncorrect &= probe.outcome() == INCORRECT;
            // A locked-out current user must not prevent a healthy space's valid credential
            // from matching. Each candidate is probed at most once; no automatic retries.
        }
        // A previously checked user's credential or identity may have changed while another
        // user's hardware check was in flight. A negative decision needs the whole snapshot.
        for (Candidate candidate : candidates) {
            if (!verifier.isCurrent(candidate)) {
                return new Result(null, attempts, false);
            }
        }
        return new Result(null, attempts, allIncorrect);
    }
}
