/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.locksettings;

import java.util.Objects;
import java.util.HashMap;
import java.util.Map;

/** One pending, short-lived capability. All methods are called under the service routing lock. */
final class SecureSpaceCredentialHandoff {
    static final long LIFETIME_MILLIS = 30_000;

    record Snapshot(long now, int foregroundUserId, long foregroundGeneration, long sessionEpoch, long strongAuthGeneration,
            boolean identitiesCurrent, boolean destinationUnlocked) {}

    record Grant(Object token, SecureSpaceCredentialRouter.Candidate origin,
            SecureSpaceCredentialRouter.Candidate destination, long originProtector,
            long destinationProtector, long foregroundGeneration, long sessionEpoch, long strongAuthGeneration,
            long issuedAt, long expiresAt) {}

    /** Tracks requests even when the same strong-auth flag was already set. */
    static final class RequirementGenerations {
        private long mSequence;
        private long mAllUsers;
        private final Map<Integer, Long> mUsers = new HashMap<>();

        synchronized void require(int reason, int userId) {
            if (reason == 0) return;
            if (mAllUsers < 0) return;
            if (mSequence == Long.MAX_VALUE) {
                mAllUsers = -1; // Permanently fail closed if the generation counter overflows.
                return;
            }
            long generation = ++mSequence;
            if (userId == -1) { // UserHandle.USER_ALL, keeping this host policy Android-free.
                mAllUsers = generation;
            } else {
                mUsers.put(userId, generation);
            }
        }

        synchronized long get(int userId) {
            return mAllUsers < 0 ? -1 : Math.max(mAllUsers, mUsers.getOrDefault(userId, 0L));
        }
    }

    private Grant mPending;
    private boolean mPrepared;

    void clear() {
        mPending = null;
        mPrepared = false;
    }

    Grant pending(Object token) {
        return mPending != null && mPending.token() == token ? mPending : null;
    }

    Grant issue(Object token, SecureSpaceCredentialRouter.Candidate origin,
            SecureSpaceCredentialRouter.Candidate destination, long originProtector,
            long destinationProtector, long foregroundGeneration, long sessionEpoch,
            long strongAuthGeneration, long now) {
        clear();
        Objects.requireNonNull(token);
        Objects.requireNonNull(origin);
        Objects.requireNonNull(destination);
        if (origin.userId() < 0 || origin.serialNumber() < 0
                || destination.userId() < 0 || destination.serialNumber() < 0
                || (origin.userId() == destination.userId() && !origin.equals(destination))
                || originProtector == 0 || destinationProtector == 0
                || foregroundGeneration < 0 || foregroundGeneration == Long.MAX_VALUE
                || sessionEpoch < 0 || strongAuthGeneration < 0 || now < 0 || now > Long.MAX_VALUE - LIFETIME_MILLIS) {
            return null;
        }
        mPending = new Grant(token, origin, destination, originProtector, destinationProtector,
                foregroundGeneration, sessionEpoch, strongAuthGeneration, now, now + LIFETIME_MILLIS);
        return mPending;
    }

    boolean prepare(Object token, Snapshot current) {
        Grant grant = pending(token);
        if (grant == null) return false;
        if (mPrepared || !fresh(grant, current)
                || current.foregroundUserId() != grant.origin().userId()
                || current.foregroundGeneration() != grant.foregroundGeneration()) {
            clear();
            return false;
        }
        mPrepared = true;
        return true;
    }

    boolean consume(Object token, int destinationId, int destinationSerial, Snapshot current) {
        Grant grant = pending(token);
        if (grant == null) return false;
        boolean prepared = mPrepared;
        clear(); // A failed consumption must not become usable after an unrelated later switch.
        long expectedGeneration = grant.foregroundGeneration()
                + (grant.origin().equals(grant.destination()) ? 0 : 1);
        return prepared && fresh(grant, current) && current.destinationUnlocked()
                && destinationId == grant.destination().userId()
                && destinationSerial == grant.destination().serialNumber()
                && current.foregroundUserId() == destinationId
                && current.foregroundGeneration() == expectedGeneration;
    }

    void cancel(Object token) {
        if (pending(token) != null) clear();
    }

    private boolean fresh(Grant grant, Snapshot current) {
        return current.identitiesCurrent() && current.now() >= grant.issuedAt()
                && current.now() < grant.expiresAt() && current.sessionEpoch() == grant.sessionEpoch()
                && current.strongAuthGeneration() == grant.strongAuthGeneration();
    }
}
