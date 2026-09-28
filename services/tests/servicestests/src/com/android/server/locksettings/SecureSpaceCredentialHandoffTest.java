/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.locksettings;

import static org.junit.Assert.*;
import org.junit.Test;

public class SecureSpaceCredentialHandoffTest {
    private final SecureSpaceCredentialHandoff mPolicy = new SecureSpaceCredentialHandoff();
    private final Object mToken = new Object();
    private final SecureSpaceCredentialRouter.Candidate mOrigin =
            new SecureSpaceCredentialRouter.Candidate(0, 0);
    private final SecureSpaceCredentialRouter.Candidate mDestination =
            new SecureSpaceCredentialRouter.Candidate(10, 31);

    private void issue() {
        assertNotNull(mPolicy.issue(mToken, mOrigin, mDestination, 11, 22, 4, 7, 1, 100));
    }

    private SecureSpaceCredentialHandoff.Snapshot snapshot(int user, long generation) {
        return new SecureSpaceCredentialHandoff.Snapshot(101, user, generation, 7, 1, true, true);
    }

    private void prepare() {
        issue();
        assertTrue(mPolicy.prepare(mToken, snapshot(0, 4)));
    }

    @Test public void deliberateSwitchGrantsDestinationExactlyOnce() {
        prepare();
        assertTrue(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
        assertFalse(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
    }

    @Test public void metadataWithoutPreparationCannotDismiss() {
        issue();
        assertFalse(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
        assertNull(mPolicy.pending(mToken));
    }

    @Test public void originalUserCannotConsumeAnAlternateMatch() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 0, 0, snapshot(0, 4)));
        assertFalse(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
    }

    @Test public void unrelatedSwitchAwayAndBackRejectsGrant() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31, snapshot(10, 7)));
    }

    @Test public void reusedDestinationIdCannotConsumeEarlierSerial() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 32, snapshot(10, 5)));
    }

    @Test public void sameUserMatchRequiresNoSwitchGeneration() {
        assertNotNull(mPolicy.issue(mToken, mOrigin, mOrigin, 11, 11, 4, 7, 1, 100));
        assertTrue(mPolicy.prepare(mToken, snapshot(0, 4)));
        assertTrue(mPolicy.consume(mToken, 0, 0, snapshot(0, 4)));
    }

    @Test public void screenOffAndOnInvalidatesVerifiedMatch() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31,
                new SecureSpaceCredentialHandoff.Snapshot(101, 10, 5, 8, 1, true, true)));
    }

    @Test public void credentialReplacementOrRemovedIdentityRejectsGrant() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31,
                new SecureSpaceCredentialHandoff.Snapshot(101, 10, 5, 7, 1, false, true)));
    }

    @Test public void destinationMustBeNativelyUnlocked() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31,
                new SecureSpaceCredentialHandoff.Snapshot(101, 10, 5, 7, 1, true, false)));
    }

    @Test public void expirationBoundaryRejectsGrant() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31,
                new SecureSpaceCredentialHandoff.Snapshot(30_100, 10, 5, 7, 1, true, true)));
    }

    @Test public void timeBeforeIssuanceCannotConsume() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31,
                new SecureSpaceCredentialHandoff.Snapshot(99, 10, 5, 7, 1, true, true)));
    }

    @Test public void lateCancellationDoesNotClearNextAttempt() {
        prepare();
        Object next = new Object();
        mPolicy.issue(next, mOrigin, mDestination, 11, 22, 4, 7, 1, 100);
        mPolicy.cancel(mToken);
        assertNotNull(mPolicy.pending(next));
        assertNull(mPolicy.pending(mToken));
    }

    @Test public void cancellationRevokesPreparedGrant() {
        prepare();
        mPolicy.cancel(mToken);
        assertFalse(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
    }

    @Test public void repeatedPreparationFailsClosed() {
        prepare();
        assertFalse(mPolicy.prepare(mToken, snapshot(0, 4)));
        assertFalse(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
    }

    @Test public void wrongCapabilityCannotPrepareConsumeOrCancelValidMatch() {
        prepare();
        Object wrong = new Object();
        assertFalse(mPolicy.prepare(wrong, snapshot(0, 4)));
        assertFalse(mPolicy.consume(wrong, 10, 31, snapshot(10, 5)));
        mPolicy.cancel(wrong);
        assertTrue(mPolicy.consume(mToken, 10, 31, snapshot(10, 5)));
    }

    @Test public void switchBeforePreparationRejectsGrant() {
        issue();
        assertFalse(mPolicy.prepare(mToken, snapshot(10, 5)));
        assertNull(mPolicy.pending(mToken));
    }

    @Test public void invalidIssueCannotPreservePreviousGrant() {
        prepare();
        assertNull(mPolicy.issue(new Object(), mOrigin, mDestination, 0, 22, 4, 7, 1, 100));
        assertNull(mPolicy.pending(mToken));
    }

    @Test public void deadlineOverflowFailsClosed() {
        assertNull(mPolicy.issue(mToken, mOrigin, mDestination,
                11, 22, 4, 7, 1, Long.MAX_VALUE));
    }
    @Test public void renewedStrongAuthRequirementRejectsOldProof() {
        prepare();
        assertFalse(mPolicy.consume(mToken, 10, 31,
                new SecureSpaceCredentialHandoff.Snapshot(101, 10, 5, 7, 2, true, true)));
    }
    @Test public void repeatedRequirementAdvancesEvenIfFlagDidNotChange() {
        SecureSpaceCredentialHandoff.RequirementGenerations generations =
                new SecureSpaceCredentialHandoff.RequirementGenerations();
        generations.require(1, 10);
        long first = generations.get(10);
        generations.require(1, 10);
        assertTrue(generations.get(10) > first);
    }

    @Test public void otherUsersRequirementDoesNotInvalidateHealthyDestination() {
        SecureSpaceCredentialHandoff.RequirementGenerations generations =
                new SecureSpaceCredentialHandoff.RequirementGenerations();
        generations.require(1, 0);
        assertEquals(0, generations.get(10));
        generations.require(1, -1);
        assertTrue(generations.get(10) > 0);
    }

    @Test public void clearingRequirementsDoesNotInventNewAuthenticationDemand() {
        SecureSpaceCredentialHandoff.RequirementGenerations generations =
                new SecureSpaceCredentialHandoff.RequirementGenerations();
        generations.require(1, 10);
        long first = generations.get(10);
        generations.require(0, 10);
        assertEquals(first, generations.get(10));
    }
}
