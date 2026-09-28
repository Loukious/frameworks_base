/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.systemui.securespaces;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.Application;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.UserManager;

import com.android.internal.widget.ISecureSpaceCredentialAttempt;
import com.android.internal.widget.LockscreenCredential;
import com.android.internal.widget.SecureSpaceCredentialResponse;
import com.android.systemui.keyguard.WakefulnessLifecycle;
import com.android.systemui.settings.UserTracker;
import com.android.systemui.user.domain.interactor.SelectedUserInteractor;
import com.android.systemui.util.concurrency.DelayableExecutor;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayDeque;
import java.util.concurrent.TimeUnit;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36, manifest = Config.NONE, application = Application.class)
public class SecureSpaceEntryCoordinatorTest {
    private final ArrayDeque<Runnable> mBackground = new ArrayDeque<>();
    private final ArrayDeque<Runnable> mMain = new ArrayDeque<>();
    private final ArrayDeque<Runnable> mDelayed = new ArrayDeque<>();
    private SecureSpaceEntryCoordinator.Backend mBackend;
    private SecureSpaceEntryCoordinator mCoordinator;
    private PowerManager mPower;
    private UserManager mUsers;
    private SecureSpaceEntryCoordinator.Host mHost;
    private IBinder mToken;
    private ISecureSpaceCredentialAttempt mWitness;
    private LockscreenCredential mCheckedCopy;
    private final Callback mCallback = new Callback();

    @Before
    public void setUp() throws Exception {
        mBackend = mock(SecureSpaceEntryCoordinator.Backend.class);
        mPower = mock(PowerManager.class);
        when(mPower.isInteractive()).thenReturn(true);
        mUsers = mock(UserManager.class);
        UserInfo owner = new UserInfo(0, "", UserInfo.FLAG_ADMIN | UserInfo.FLAG_FULL);
        owner.serialNumber = 1;
        when(mUsers.getUserInfo(0)).thenReturn(owner);
        when(mUsers.isUserUnlocked(any(android.os.UserHandle.class))).thenReturn(true);
        UserTracker tracker = mock(UserTracker.class);
        when(tracker.getUserId()).thenReturn(0);
        SelectedUserInteractor selected = mock(SelectedUserInteractor.class);
        when(selected.getSelectedUserId()).thenReturn(0);
        DelayableExecutor main = new DelayableExecutor() {
            public void execute(Runnable runnable) { mMain.add(runnable); }
            public Runnable executeDelayed(Runnable runnable, long delay, TimeUnit unit) {
                mDelayed.add(runnable);
                return () -> mDelayed.remove(runnable);
            }
            public Runnable executeAtTime(Runnable runnable, long uptime, TimeUnit unit) {
                throw new AssertionError("Unexpected timer");
            }
        };
        mCoordinator = new SecureSpaceEntryCoordinator(mBackend, mUsers, mPower, tracker,
                selected, mBackground::add, main, mock(WakefulnessLifecycle.class));
        mHost = mock(SecureSpaceEntryCoordinator.Host.class);
        when(mHost.isReady(0, 1)).thenReturn(true);
        mCoordinator.registerHost(mHost);
        mToken = new Binder();
        when(mBackend.check(any(), eq(0), eq(1), any())).thenAnswer(invocation -> {
            mCheckedCopy = invocation.getArgument(0);
            mWitness = invocation.getArgument(3);
            return matched();
        });
        when(mBackend.prepare(mToken)).thenReturn(true);
        when(mBackend.consume(mToken, 0, 1)).thenReturn(true);
        when(mBackend.isLeaseCurrent(mToken, 0, 1)).thenReturn(true);
    }

    @Test
    public void missedRevocationCallback_preventsPublication() {
        submit();
        drain();
        when(mBackend.isLeaseCurrent(mToken, 0, 1)).thenReturn(false);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
        verify(mHost).onPrimaryAuthenticationRevoked(0, 1);
    }

    @Test
    public void missedRevocationCallback_permanentlyRejectsBufferedProof() {
        final SecureSpaceEntryCoordinator.Proof[] published = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(proof -> published[0] = proof);
        submit();
        drain();
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        when(mBackend.isLeaseCurrent(mToken, 0, 1)).thenReturn(false);
        assertThat(mCoordinator.isProofCurrent(published[0])).isFalse();
        when(mBackend.isLeaseCurrent(mToken, 0, 1)).thenReturn(true);
        assertThat(mCoordinator.isProofCurrent(published[0])).isFalse();
    }

    @Test
    public void erasurePending_doesNotFallBackOrDismiss() {
        when(mBackend.check(any(), eq(0), eq(1), any()))
                .thenReturn(SecureSpaceCredentialResponse.erasurePending());
        submit();
        drain();
        verify(mBackend, never()).checkCurrent(any(), anyInt());
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
        assertThat(mCallback.accepted).isEqualTo(1);
        assertThat(mCoordinator.isErasurePending()).isTrue();
        assertThat(mCoordinator.isAwaitingPolicy()).isTrue();
        mCoordinator.cancel();
        assertThat(mCoordinator.isAwaitingPolicy()).isTrue();
    }

    @Test
    public void nativeErasureFence_survivesCancellationWithoutResponse() {
        when(mBackend.isErasurePending()).thenReturn(true);
        assertThat(mCoordinator.isAwaitingPolicy()).isTrue();
        when(mBackend.isErasurePending()).thenReturn(false);
        mCoordinator.cancel();
        assertThat(mCoordinator.isAwaitingPolicy()).isTrue();
    }

    @Test
    public void removedSecondarySurface_revokesConsumedAuthentication() {
        androidx.constraintlayout.widget.ConstraintLayout parent =
                new androidx.constraintlayout.widget.ConstraintLayout(
                        org.robolectric.RuntimeEnvironment.getApplication());
        mCoordinator.registerSecondaryPolicyHost(parent);
        submit();
        drain();
        mCoordinator.unregisterSecondaryPolicyHost(parent);
        verify(mHost).onPrimaryAuthenticationRevoked(0, 1);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
    }

    @Test
    public void finalClassicCompletion_rechecksNativeLeaseAfterPublication() {
        submit();
        drain();
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        assertThat(mCoordinator.isPublishedAuthenticationCurrent(0, 1)).isTrue();
        assertThat(mCoordinator.isPublishedAuthenticationCurrent(0, 2)).isFalse();
        when(mBackend.isLeaseCurrent(mToken, 0, 1)).thenReturn(false);
        assertThat(mCoordinator.isPublishedAuthenticationCurrent(0, 1)).isFalse();
    }

    private void acceptFingerprint() {
        when(mBackend.credentialType(0)).thenReturn(
                com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN);
        when(mBackend.attachFingerprint(eq(mToken), eq(0), eq(1), eq(0), eq(1), any()))
                .thenAnswer(invocation -> {
                    mWitness = invocation.getArgument(5);
                    return true;
                });
        when(mBackend.consumeFingerprint(mToken, 0, 1)).thenReturn(true);
        mCoordinator.acceptFingerprint(mToken, 0, 1, 0, 1, true, mCallback);
    }

    @Test
    public void fingerprint_usesNativeBiometricConsumeAndPreservesProofKind() {
        final SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        acceptFingerprint();
        drain();
        verify(mBackend).consumeFingerprint(mToken, 0, 1);
        verify(mBackend, never()).consume(any(), anyInt(), anyInt());
        verify(mHost).completeBiometricAuthentication(0, 1, true);
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        assertThat(proof[0].biometric).isTrue();
        assertThat(proof[0].strongBiometric).isTrue();
        assertThat(mCoordinator.isProofCurrent(proof[0])).isTrue();
    }

    @Test
    public void fingerprint_failedWitnessAttachmentCannotDismiss() {
        acceptFingerprint();
        when(mBackend.attachFingerprint(eq(mToken), eq(0), eq(1), eq(0), eq(1), any()))
                .thenReturn(false);
        drain();
        verify(mBackend, never()).consumeFingerprint(any(), anyInt(), anyInt());
        verify(mHost, never()).completeBiometricAuthentication(anyInt(), anyInt(), org.mockito.ArgumentMatchers.anyBoolean());
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
    }

    @Test
    public void fingerprint_primaryConsumeCannotSubstituteForBiometricConsume() {
        acceptFingerprint();
        when(mBackend.consumeFingerprint(mToken, 0, 1)).thenReturn(false);
        drain();
        verify(mBackend, never()).consume(any(), anyInt(), anyInt());
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
    }

    @Test
    public void fingerprint_sourceCancellationBeforeNativeAttachRejectsGrant() {
        acceptFingerprint();
        mCallback.active = false;
        drain();
        verify(mBackend, never()).consumeFingerprint(any(), anyInt(), anyInt());
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
    }

    private SecureSpaceCredentialResponse matched() {
        return new SecureSpaceCredentialResponse(0, 1, false, new int[]{0}, new int[]{1},
                new int[]{SecureSpaceCredentialResponse.MATCHED}, new long[]{0},
                new boolean[]{false}, mToken);
    }

    private void submit() {
        try (LockscreenCredential input = LockscreenCredential.createPin("1234")) {
            mCoordinator.submit(input, mCallback);
        }
    }

    private void drain() {
        int turns = 0;
        while (!mBackground.isEmpty() || !mMain.isEmpty()) {
            if (++turns > 30) throw new AssertionError("Unexpected executor loop");
            if (!mBackground.isEmpty()) mBackground.remove().run();
            if (!mMain.isEmpty()) mMain.remove().run();
        }
    }

    @Test
    public void currentMatch_requiresPreparationAndConsumptionBeforeHostCompletion() {
        submit();
        mBackground.remove().run();
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
        drain();
        org.junit.Assert.assertThrows(IllegalStateException.class,
                () -> mCheckedCopy.getCredential());
        verify(mBackend).prepare(mToken);
        verify(mBackend).consume(mToken, 0, 1);
        verify(mHost).completePrimaryAuthentication(0, 1);
        assertThat(mCallback.accepted).isEqualTo(1);
        assertThat(mCoordinator.isAwaitingPolicy()).isTrue();
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
    }

    @Test
    public void failedNativeConsumption_neverCompletesHost() {
        when(mBackend.consume(mToken, 0, 1)).thenReturn(false);
        submit();
        drain();
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
    }

    @Test
    public void cancellationRevokesInFlightWitnessAndDoesNotConsumeLateMatch() throws Exception {
        submit();
        mBackground.remove().run();
        assertThat(mWitness.isActive()).isTrue();
        mCoordinator.cancel();
        assertThat(mWitness.isActive()).isFalse();
        drain();
        verify(mBackend, never()).consume(any(), anyInt(), anyInt());
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
    }

    @Test
    public void screenOffRevokesWitnessWithoutWaitingForMainCallback() throws Exception {
        submit();
        mBackground.remove().run();
        when(mPower.isInteractive()).thenReturn(false);
        assertThat(mWitness.isActive()).isFalse();
        when(mPower.isInteractive()).thenReturn(true);
        assertThat(mWitness.isActive()).isFalse();
        drain();
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
    }

    @Test
    public void cancelledPublishedProof_cannotBeReplayedToSceneConsumer() {
        submit();
        drain();
        SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        assertThat(mCoordinator.isProofCurrent(proof[0])).isTrue();
        mCoordinator.cancel();
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
        verify(mHost).onPrimaryAuthenticationRevoked(0, 1);
    }

    @Test
    public void recycledSerial_rejectsPublishedProof() {
        submit();
        drain();
        SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        mUsers.getUserInfo(0).serialNumber = 2;
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
    }

    @Test
    public void publishedProof_expiresWithNativeAttemptLifetime() {
        submit();
        drain();
        SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofSeconds(31));
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
    }

    @Test
    public void publishedProof_rejectsRelockedCredentialEncryptedStorage() {
        submit();
        drain();
        SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        when(mUsers.isUserUnlocked(any(android.os.UserHandle.class))).thenReturn(false);
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
        when(mUsers.isUserUnlocked(any(android.os.UserHandle.class))).thenReturn(true);
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
    }

    @Test
    public void nativeRevocationAfterConsumption_preventsPolicyPublication() throws Exception {
        submit();
        drain();
        mWitness.invalidate();
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isFalse();
        drain();
        assertThat(mCoordinator.isAwaitingPolicy()).isFalse();
        verify(mHost).onPrimaryAuthenticationRevoked(0, 1);
    }

    @Test
    public void nativeRevocationAfterPublication_rejectsBufferedSceneProof() throws Exception {
        submit();
        drain();
        SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        mWitness.invalidate();
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
    }

    @Test
    public void lateOldLeaseRevocation_doesNotCancelNewAttempt() throws Exception {
        submit();
        drain();
        ISecureSpaceCredentialAttempt oldWitness = mWitness;
        submit();
        drain();
        oldWitness.invalidate();
        drain();
        assertThat(mWitness.isActive()).isTrue();
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
    }

    private void addAlternative() {
        UserInfo other = new UserInfo(10, "", UserInfo.FLAG_FULL);
        other.serialNumber = 2;
        when(mUsers.getUserInfo(10)).thenReturn(other);
    }

    @Test
    public void completedUnionRejection_reportsInactivePolicyOnce() {
        addAlternative();
        when(mBackend.check(any(), eq(0), eq(1), any())).thenReturn(
                new SecureSpaceCredentialResponse(-10000, -1, true,
                        new int[]{0, 10}, new int[]{1, 2},
                        new int[]{SecureSpaceCredentialResponse.INCORRECT,
                                SecureSpaceCredentialResponse.INCORRECT},
                        new long[]{0, 0}, new boolean[]{false, false}, null));
        submit();
        drain();
        verify(mBackend).reportFailedAttempt(10);
        verify(mBackend, never()).reportFailedAttempt(0);
        assertThat(mCallback.rejected).isEqualTo(1);
    }

    @Test
    public void normalMatch_doesNotReportDiscoveryFailureToInactivePolicy() {
        addAlternative();
        when(mBackend.check(any(), eq(0), eq(1), any())).thenReturn(
                new SecureSpaceCredentialResponse(10, 2, false,
                        new int[]{0, 10}, new int[]{1, 2},
                        new int[]{SecureSpaceCredentialResponse.INCORRECT,
                                SecureSpaceCredentialResponse.MATCHED},
                        new long[]{0, 0}, new boolean[]{false, false}, mToken));
        submit();
        drain();
        verify(mBackend, never()).reportFailedAttempt(anyInt());
    }

    @Test
    public void throttledCurrentUser_doesNotDisableHealthyAlternative() {
        addAlternative();
        when(mBackend.check(any(), eq(0), eq(1), any())).thenReturn(
                new SecureSpaceCredentialResponse(-10000, -1, false,
                        new int[]{0, 10}, new int[]{1, 2},
                        new int[]{SecureSpaceCredentialResponse.INCONCLUSIVE,
                                SecureSpaceCredentialResponse.INCORRECT},
                        new long[]{30_000, 0}, new boolean[]{false, false}, null));
        submit();
        drain();
        verify(mBackend, never()).reportFailedAttempt(anyInt());
        assertThat(mCoordinator.getLockoutEndTimeMillis()).isEqualTo(0);
    }

    @Test
    public void everyCandidateThrottled_usesShortestNativeTimeout() {
        addAlternative();
        long started = android.os.SystemClock.elapsedRealtime();
        when(mBackend.check(any(), eq(0), eq(1), any())).thenReturn(
                new SecureSpaceCredentialResponse(-10000, -1, false,
                        new int[]{0, 10}, new int[]{1, 2},
                        new int[]{SecureSpaceCredentialResponse.INCONCLUSIVE,
                                SecureSpaceCredentialResponse.INCONCLUSIVE},
                        new long[]{30_000, 1_500}, new boolean[]{false, false}, null));
        submit();
        drain();
        assertThat(mCoordinator.getLockoutEndTimeMillis()).isAtLeast(started + 1_500);
        assertThat(mCoordinator.getLockoutEndTimeMillis()).isLessThan(started + 30_000);
        verify(mBackend, never()).reportFailedAttempt(anyInt());
    }

    @Test
    public void lockedDestinationStorage_waitsBeforeNativeConsumption() {
        when(mUsers.isUserUnlocked(any(android.os.UserHandle.class))).thenReturn(false);
        submit();
        drain();
        verify(mBackend, never()).consume(any(), anyInt(), anyInt());
        verify(mHost, never()).completePrimaryAuthentication(anyInt(), anyInt());
        when(mUsers.isUserUnlocked(any(android.os.UserHandle.class))).thenReturn(true);
        mDelayed.removeLast().run();
        drain();
        verify(mBackend).consume(mToken, 0, 1);
        verify(mHost).completePrimaryAuthentication(0, 1);
    }

    @Test
    public void publishedProof_screenOffRevocationIsPermanent() {
        submit();
        drain();
        SecureSpaceEntryCoordinator.Proof[] proof = new SecureSpaceEntryCoordinator.Proof[1];
        mCoordinator.addProofListener(value -> proof[0] = value);
        assertThat(mCoordinator.publishPrimaryAuthentication(0, 1)).isTrue();
        when(mPower.isInteractive()).thenReturn(false);
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
        when(mPower.isInteractive()).thenReturn(true);
        assertThat(mCoordinator.isProofCurrent(proof[0])).isFalse();
    }

    private static class Callback implements SecureSpaceEntryCoordinator.Callback {
        boolean active = true;
        public boolean isActive() { return active; }
        int accepted;
        int rejected;
        public void onAccepted() { ++accepted; }
        public void onRejected(SecureSpaceCredentialResponse response) { ++rejected; }
    }
}
