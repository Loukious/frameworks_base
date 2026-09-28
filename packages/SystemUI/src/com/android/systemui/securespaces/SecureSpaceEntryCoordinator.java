/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.systemui.securespaces;

import android.app.ActivityManager;
import android.util.Log;
import android.content.Context;
import android.content.pm.UserInfo;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.SystemClock;
import android.os.UserManager;
import android.os.UserHandle;

import com.android.internal.widget.ISecureSpaceCredentialAttempt;
import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.LockscreenCredential;
import com.android.internal.widget.SecureSpaceCredentialResponse;
import com.android.internal.widget.VerifyCredentialResponse;
import com.android.systemui.dagger.SysUISingleton;
import com.android.systemui.dagger.qualifiers.Background;
import com.android.systemui.dagger.qualifiers.Main;
import com.android.systemui.keyguard.WakefulnessLifecycle;
import com.android.systemui.settings.UserTracker;
import com.android.systemui.user.domain.interactor.SelectedUserInteractor;
import com.android.systemui.util.concurrency.DelayableExecutor;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.inject.Inject;

/** Process-owned credential transaction, independent of either bouncer's view lifetime. */
@SysUISingleton
public final class SecureSpaceEntryCoordinator {
    private static final String TAG = "SecureSpaceEntry";
    public interface Host {
        /** Must check the selected identity and wait for the native security view to be ready. */
        boolean isReady(int userId, int serialNumber);
        /** Runs the normal SIM, secondary admin and keyguard dismissal policy. */
        void completePrimaryAuthentication(int userId, int serialNumber);
        default void completeBiometricAuthentication(int userId, int serialNumber, boolean strong) {}

        default void onPrimaryAuthenticationRevoked(int userId, int serialNumber) {}
    }

    public interface Callback {
        /** Delivered only while the originating attempt and selected identity are still current. */
        void onRejected(SecureSpaceCredentialResponse response);
        /** The native match is now owned by this coordinator, not by the source coroutine. */
        default void onAccepted() {}
        default boolean isActive() { return true; }
        default void onCurrentUserChecked(VerifyCredentialResponse response) {}
    }

    private static final long LIFETIME_MS = 30_000;
    interface Backend {
        int credentialType(int userId);
        SecureSpaceCredentialResponse check(LockscreenCredential input, int userId, int serial,
                ISecureSpaceCredentialAttempt witness);
        VerifyCredentialResponse checkCurrent(LockscreenCredential input, int userId);
        boolean prepare(IBinder token);
        boolean consume(IBinder token, int userId, int serial);
        boolean isLeaseCurrent(IBinder token, int userId, int serial);
        boolean attachFingerprint(IBinder token, int origin, int originSerial,
                int destination, int destinationSerial, ISecureSpaceCredentialAttempt witness);
        boolean consumeFingerprint(IBinder token, int userId, int serial);
        boolean isErasurePending();
        void cancel(IBinder token);
        int currentUser();
        boolean switchUser(int userId) throws Exception;
        void reportFailedAttempt(int userId);
        void reportLockout(Duration timeout, int userId);
    }

    private static Backend nativeBackend(LockPatternUtils locks) {
        return new Backend() {
            public int credentialType(int userId) { return locks.getCredentialTypeForUser(userId); }
            public SecureSpaceCredentialResponse check(LockscreenCredential input, int userId,
                    int serial, ISecureSpaceCredentialAttempt witness) {
                return locks.checkSecureSpaceCredential(input, userId, serial, witness);
            }
            public VerifyCredentialResponse checkCurrent(LockscreenCredential input, int userId) {
                try (LockscreenCredential typed = input.duplicateForSecureSpaceVerification(
                        locks.getCredentialTypeForUser(userId))) {
                    return typed == null ? VerifyCredentialResponse.OTHER_ERROR
                            : locks.checkCredential(typed, userId, null);
                }
            }
            public boolean prepare(IBinder token) {
                return locks.prepareSecureSpaceCredentialHandoff(token);
            }
            public boolean consume(IBinder token, int userId, int serial) {
                return locks.consumeSecureSpaceCredentialHandoff(token, userId, serial);
            }
            public boolean isLeaseCurrent(IBinder token, int userId, int serial) {
                return locks.isSecureSpaceAuthenticationLeaseCurrent(token, userId, serial);
            }
            public boolean attachFingerprint(IBinder token, int origin, int originSerial,
                    int destination, int destinationSerial, ISecureSpaceCredentialAttempt witness) {
                return locks.attachSecureSpaceFingerprintWitness(token, origin, originSerial,
                        destination, destinationSerial, witness);
            }
            public boolean consumeFingerprint(IBinder token, int userId, int serial) {
                return locks.consumeSecureSpaceFingerprintHandoff(token, userId, serial);
            }
            public boolean isErasurePending() { return locks.isSecureAuthErasurePending(); }
            public void cancel(IBinder token) { locks.cancelSecureSpaceCredentialHandoff(token); }
            public int currentUser() { return ActivityManager.getCurrentUser(); }
            public boolean switchUser(int userId) throws Exception {
                return ActivityManager.getService().switchUser(userId);
            }
            public void reportFailedAttempt(int userId) {
                locks.reportFailedPasswordAttempt(userId);
            }
            public void reportLockout(Duration timeout, int userId) {
                locks.reportPasswordLockout(timeout, userId);
            }
        };
    }

    private final Backend mBackend;
    private final UserManager mUsers;
    private final PowerManager mPower;
    private final UserTracker mUserTracker;
    private final SelectedUserInteractor mSelectedUser;
    private final Executor mBackground;
    private final DelayableExecutor mMain;
    private Host mHost;
    private volatile Request mRequest;
    private volatile Request mConsumedRequest;
    private record AggregateLockout(int userId, int serial, long endTime) {}
    private volatile AggregateLockout mAggregateLockout;

    /** Hardware retry for one inactive user cannot disable healthy alternatives. */
    public long getLockoutEndTimeMillis() {
        AggregateLockout lockout = mAggregateLockout;
        if (lockout == null || lockout.userId() != mSelectedUser.getSelectedUserId()
                || !hasIdentity(lockout.userId(), lockout.serial())
                || SystemClock.elapsedRealtime() >= lockout.endTime()) return 0;
        return lockout.endTime();
    }

    private volatile Proof mPublishedProof;
    private final CopyOnWriteArraySet<Consumer<Proof>> mProofListeners = new CopyOnWriteArraySet<>();

    public static final class Proof {
        public final int userId;
        public final int serialNumber;
        private final Request request;
        public final boolean biometric;
        public final boolean strongBiometric;
        private final AtomicBoolean active;
        private Proof(int userId, int serialNumber, Request request) {
            this.userId = userId;
            this.serialNumber = serialNumber;
            this.request = request;
            biometric = request.biometric;
            strongBiometric = request.strongBiometric;
            active = request.active;
        }
    }

    public void addProofListener(Consumer<Proof> listener) { mProofListeners.add(listener); }
    public void removeProofListener(Consumer<Proof> listener) { mProofListeners.remove(listener); }

    /** Each queued Scene consumer must validate the same proof identity when it receives it. */
    public boolean isProofCurrent(Proof proof) {
        if (proof == null || proof != mPublishedProof || !proof.request.isActive()) return false;
        boolean current = mPower.isInteractive() && !mUserTracker.isUserSwitching()
                && mBackend.currentUser() == proof.userId
                && mUserTracker.getUserId() == proof.userId
                && mSelectedUser.getSelectedUserId() == proof.userId
                && hasIdentity(proof.userId, proof.serialNumber)
                && mUsers.isUserUnlocked(UserHandle.of(proof.userId))
                && isNativeLeaseCurrent(proof.request) && proof.active.get();
        if (!current) proof.active.set(false);
        return current;
    }

    private boolean isNativeLeaseCurrent(Request request) {
        try {
            return !isErasurePending() && request.active.get() && mBackend.isLeaseCurrent(request.token,
                    request.destination, request.destinationSerial) && request.active.get();
        } catch (RuntimeException e) {
            return false;
        }
    }

    public boolean isPublishedAuthenticationCurrent(int userId, int serialNumber) {
        Proof proof = mPublishedProof;
        return proof != null && proof.userId == userId && proof.serialNumber == serialNumber
                && isProofCurrent(proof);
    }

    /** Called only after the native security host has passed all dismissal requirements. */
    public boolean publishPrimaryAuthentication(int userId, int serialNumber) {
        Request request = mConsumedRequest;
        if (request == null || !request.isActive() || request.destination != userId
                || request.destinationSerial != serialNumber
                || mBackend.currentUser() != userId
                || mSelectedUser.getSelectedUserId() != userId
                || !hasIdentity(userId, serialNumber)) return false;
        if (!isNativeLeaseCurrent(request)) {
            cancel();
            return false;
        }
        mConsumedRequest = null;
        Proof proof = new Proof(userId, serialNumber, request);
        mPublishedProof = proof;
        for (Consumer<Proof> listener : mProofListeners) listener.accept(proof);
        return true;
    }

    private final UserTracker.Callback mUserCallback = new UserTracker.Callback() {
        @Override
        public void onBeforeUserSwitching(int newUser, Runnable acknowledgement) {
            try {
                Proof proof = mPublishedProof;
                if (proof != null) proof.active.set(false);
                mPublishedProof = null;
                mConsumedRequest = null;
                Request request = mRequest;
                if (request != null && (!request.switchRequested.get()
                        || request.destination != newUser)) cancel();
            } finally {
                acknowledgement.run();
            }
        }
        @Override
        public void onUserChanged(int newUser, Context context) {
            Request request = mRequest;
            if (request != null && request.switchRequested.get()
                    && request.destination == newUser) {
                request.switchCompleted.set(true);
            }
            tryComplete();
        }
    };

    @Inject
    public SecureSpaceEntryCoordinator(LockPatternUtils locks, UserManager users,
            PowerManager power, UserTracker userTracker, SelectedUserInteractor selectedUser,
            @Background Executor background, @Main DelayableExecutor main,
            WakefulnessLifecycle wakefulness) {
        this(nativeBackend(locks), users, power, userTracker, selectedUser, background, main,
                wakefulness);
    }

    SecureSpaceEntryCoordinator(Backend backend, UserManager users, PowerManager power,
            UserTracker userTracker, SelectedUserInteractor selectedUser, Executor background,
            DelayableExecutor main, WakefulnessLifecycle wakefulness) {
        mBackend = backend;
        mUsers = users;
        mPower = power;
        mUserTracker = userTracker;
        mSelectedUser = selectedUser;
        mBackground = background;
        mMain = main;
        userTracker.addCallback(mUserCallback, main);
        wakefulness.addObserver(new WakefulnessLifecycle.Observer() {
            @Override
            public void onStartedGoingToSleep() { cancel(); }
        });
    }

    /** Concealed entry is enabled only for the native owner/Secure Space credential cohort. */
    public boolean isAvailable() {
        UserInfo current = mUsers.getUserInfo(mSelectedUser.getSelectedUserId());
        if (current == null || !(current.id == 0
                || UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(current.userType))) return false;
        int type = mBackend.credentialType(current.id);
        if (type != LockPatternUtils.CREDENTIAL_TYPE_PIN
                && type != LockPatternUtils.CREDENTIAL_TYPE_PASSWORD) return false;
        return true;
    }

    /**
     * Keep the normal PIN bouncer while every routable credential is a PIN. A password field is
     * needed only when the routing cohort contains a password, since it can accept both text
     * passwords and numeric PINs without revealing which destination owns a given credential.
     */
    public boolean usesNeutralInput(int userId) {
        UserInfo user = mUsers.getUserInfo(userId);
        if (user == null || !(user.id == 0
                || UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(user.userType))) {
            return false;
        }
        for (UserInfo candidate : mUsers.getAliveUsers()) {
            if (candidate == null || candidate.partial || candidate.preCreated
                    || !candidate.isEnabled() || !candidate.isFull()
                    || !(candidate.id == 0
                            || UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(
                                    candidate.userType))) {
                continue;
            }
            if (mBackend.credentialType(candidate.id)
                    == LockPatternUtils.CREDENTIAL_TYPE_PASSWORD) {
                return true;
            }
        }
        return false;
    }

    /** Main-thread registration; no names or other private metadata enter the host contract. */
    private final java.util.Set<Consumer<Boolean>> mSecondaryPolicyListeners =
            new java.util.concurrent.CopyOnWriteArraySet<>();
    private boolean mSecondaryPolicyVisible;

    public void addSecondaryPolicyListener(Consumer<Boolean> listener) {
        mSecondaryPolicyListeners.add(listener);
        listener.accept(mSecondaryPolicyVisible);
    }
    public void removeSecondaryPolicyListener(Consumer<Boolean> listener) {
        mSecondaryPolicyListeners.remove(listener);
    }
    public void setSecondaryPolicyVisible(boolean visible) {
        if (mSecondaryPolicyVisible == visible) return;
        mSecondaryPolicyVisible = visible;
        for (Consumer<Boolean> listener : mSecondaryPolicyListeners) listener.accept(visible);
    }

    private androidx.constraintlayout.widget.ConstraintLayout mSecondaryPolicyHost;

    public void registerSecondaryPolicyHost(androidx.constraintlayout.widget.ConstraintLayout host) {
        mSecondaryPolicyHost = host;
        tryComplete();
    }

    public void unregisterSecondaryPolicyHost(androidx.constraintlayout.widget.ConstraintLayout host) {
        if (mSecondaryPolicyHost != host) return;
        mSecondaryPolicyHost = null;
        if (mConsumedRequest != null || mPublishedProof != null) cancel();
    }

    public androidx.constraintlayout.widget.ConstraintLayout getSecondaryPolicyHost() {
        return mSecondaryPolicyHost != null && mSecondaryPolicyHost.isAttachedToWindow()
                && mSecondaryPolicyHost.isShown() ? mSecondaryPolicyHost : null;
    }

    public void registerHost(Host host) {
        mHost = host;
        tryComplete();
    }

    public void unregisterHost(Host host) {
        if (mHost != host) return;
        mHost = null;
        onSourcePaused();
    }

    /** A deliberate prepared switch may destroy the source view without abandoning its proof. */
    public void onSourcePaused() {
        if (mConsumedRequest != null) { cancel(); return; }
        if (mRequest != null && !mRequest.switchRequested.get()) cancel();
    }

    private volatile boolean mErasurePending;

    public boolean isErasurePending() {
        if (mErasurePending) return true;
        try {
            if (mBackend.isErasurePending()) mErasurePending = true;
        } catch (RuntimeException error) {
            return true;
        }
        return mErasurePending;
    }

    public boolean isAwaitingPolicy() {
        Request request = mRequest;
        return isErasurePending() || mConsumedRequest != null || (request != null && request.token != null);
    }

    public boolean isPreparedSwitch(Callback callback) {
        Request request = mRequest;
        return request != null && request.callback == callback && request.switchRequested.get();
    }

    /** Native-proof-backed switch in progress; ordinary user switching remains unchanged. */
    public boolean isAuthorizedSwitchTo(int userId) {
        Request request = mRequest;
        return request != null && request.token != null && request.switchRequested.get()
                && request.destination == userId && request.isActive()
                && hasIdentity(request.destination, request.destinationSerial);
    }

    public boolean isSwitchInProgress() {
        Request request = mRequest;
        return request != null && request.token != null && request.switchRequested.get()
                && request.isActive();
    }

    public void cancelSource(Callback callback) {
        Request request = mRequest;
        if (request != null && request.callback == callback && !request.switchRequested.get()) {
            request.active.set(false);
            mMain.execute(() -> { if (mRequest == request) cancel(); });
        }
    }

    /** Back, new input and screen off always revoke, including an in-flight Binder call. */
    public void cancel() {
        if (mRequest != null) Log.d(TAG, "Entry canceled; prepared=" + mRequest.prepared
                + ", token=" + (mRequest.token != null));
        setSecondaryPolicyVisible(false);
        Request consumed = mConsumedRequest;
        mConsumedRequest = null;
        if (consumed != null) {
            consumed.active.set(false);
            Host host = mHost;
            if (host != null) host.onPrimaryAuthenticationRevoked(
                    consumed.destination, consumed.destinationSerial);
        }
        Proof published = mPublishedProof;
        mPublishedProof = null;
        if (published != null) {
            published.active.set(false);
            // Publication transfers the request out of mConsumedRequest, but the legacy
            // bouncer may still be running its disappear animation. Notify the host for both
            // stages so a later relock cannot inherit an unfinishable disappearing state.
            Host host = mHost;
            if (host != null) host.onPrimaryAuthenticationRevoked(
                    published.userId, published.serialNumber);
        }
        Request request = mRequest;
        mRequest = null;
        if (request == null) return;
        request.active.set(false);
        IBinder token = request.token;
        if (token != null) mBackground.execute(() -> mBackend.cancel(token));
        if (mSelectedUser.getSelectedUserId() == request.origin
                && hasIdentity(request.origin, request.originSerial)) {
            request.callback.onRejected(SecureSpaceCredentialResponse.unavailable());
        }
    }

    /** Caller keeps ownership of its input; the background task owns an independent copy. */
    public void submit(LockscreenCredential credential, Callback callback) {
        Request pending = mRequest;
        if (pending != null && pending.token != null && pending.switchRequested.get()
                && pending.isActive()) {
            // A second bouncer submission must not revoke an authenticated switch.
            callback.onAccepted();
            return;
        }
        cancel();
        int origin = mSelectedUser.getSelectedUserId();
        UserInfo user = mUsers.getUserInfo(origin);
        if (user == null) {
            callback.onRejected(SecureSpaceCredentialResponse.unavailable());
            return;
        }
        Request request = new Request(origin, user.serialNumber, callback);
        LockscreenCredential copy = credential.duplicate();
        mRequest = request;
        mMain.executeDelayed(() -> {
            if (mRequest == request) cancel();
        }, LIFETIME_MS);
        mBackground.execute(() -> {
            SecureSpaceCredentialResponse response;
            try (copy) {
                response = mBackend.check(copy, request.origin,
                        request.originSerial, request.witness);
                if (!response.isErasurePending() && response.getUserIds().length == 0 && request.isActive()
                        && mUserTracker.getUserId() == request.origin
                        && mSelectedUser.getSelectedUserId() == request.origin
                        && hasIdentity(request.origin, request.originSerial)) {
                    // Unsupported policies use the original current-user authentication path.
                    // No alternate search or matched-user metadata authorizes this fallback.
                    VerifyCredentialResponse nativeResponse = mBackend.checkCurrent(copy,
                            request.origin);
                    long retryMillis = nativeResponse.getTimeout().toMillis();
                    long now = SystemClock.elapsedRealtime();
                    mMain.execute(() -> {
                        if (!isCurrent(request)) return;
                        mAggregateLockout = retryMillis > 0
                                ? new AggregateLockout(request.origin, request.originSerial,
                                        retryMillis > Long.MAX_VALUE - now
                                                ? Long.MAX_VALUE : now + retryMillis)
                                : null;
                        mRequest = null;
                        request.active.set(false);
                        if (mSelectedUser.getSelectedUserId() == request.origin
                                && hasIdentity(request.origin, request.originSerial)) {
                            request.callback.onCurrentUserChecked(nativeResponse);
                        }
                    });
                    return;
                }
            } catch (RuntimeException error) {
                response = SecureSpaceCredentialResponse.unavailable();
            }
            reportAttemptPolicy(request, response);
            SecureSpaceCredentialResponse completed = response;
            mMain.execute(() -> onChecked(request, completed));
        });
    }

    public void acceptFingerprint(IBinder token, int origin, int originSerial, int destination,
            int destinationSerial, boolean strong, Callback source) {
        cancel();
        if (token == null || isErasurePending() || !isAvailable()
                || !source.isActive() || mUserTracker.isUserSwitching()
                || mUserTracker.getUserId() != origin || mSelectedUser.getSelectedUserId() != origin
                || !hasIdentity(origin, originSerial) || !hasIdentity(destination, destinationSerial)) {
            cancelToken(token);
            return;
        }
        Request request = new Request(origin, originSerial, source);
        request.biometric = true;
        request.strongBiometric = strong;
        request.token = token;
        request.destination = destination;
        request.destinationSerial = destinationSerial;
        mRequest = request;
        mMain.executeDelayed(() -> { if (mRequest == request) cancel(); }, LIFETIME_MS);
        mBackground.execute(() -> {
            boolean attached = false;
            try {
                attached = request.isActive() && mBackend.attachFingerprint(token, origin,
                        originSerial, destination, destinationSerial, request.witness);
            } catch (RuntimeException error) { /* Fail closed. */ }
            final boolean accepted = attached;
            mMain.execute(() -> {
                if (!isCurrent(request)) { cancelToken(token); return; }
                if (!accepted) { Log.d(TAG, "Native entry preparation rejected"); cancel(); return; }
                onChecked(request, new SecureSpaceCredentialResponse(destination, destinationSerial,
                        false, new int[0], new int[0], new int[0], new long[0], new boolean[0], token));
            });
        });
    }

    private void reportAttemptPolicy(Request request, SecureSpaceCredentialResponse response) {
        if (response.isErasurePending() || !request.isActive() || mSelectedUser.getSelectedUserId() != request.origin
                || !hasIdentity(request.origin, request.originSerial)) return;
        int[] ids = response.getUserIds();
        int[] serials = response.getSerialNumbers();
        int[] outcomes = response.getOutcomes();
        long[] timeouts = response.getTimeoutMillis();
        long minimumTimeout = ids.length == 0 ? 0 : Long.MAX_VALUE;
        for (int index = 0; index < ids.length; index++) {
            if (!request.isActive() || !hasIdentity(ids[index], serials[index])) {
                minimumTimeout = 0;
                continue;
            }
            minimumTimeout = Math.min(minimumTimeout, timeouts[index]);
            try {
                if (timeouts[index] > 0) {
                    mBackend.reportLockout(Duration.ofMillis(timeouts[index]), ids[index]);
                }
                // Discovery failures cannot count toward an unrelated user's policy wipe when
                // another normal credential matched. Only a completed union rejection qualifies.
                // The originating user's normal UI path reports its own failure exactly once.
                if (response.isAllCertainlyIncorrect() && ids[index] != request.origin
                        && outcomes[index] == SecureSpaceCredentialResponse.INCORRECT) {
                    mBackend.reportFailedAttempt(ids[index]);
                }
            } catch (RuntimeException error) {
                // Native throttling remains in effect if policy reporting becomes unavailable.
            }
        }
        if (mRequest != request || !request.isActive()) return;
        if (response.getMatchedUserId() >= 0 || minimumTimeout == 0) {
            mAggregateLockout = null;
        } else {
            long now = SystemClock.elapsedRealtime();
            long deadline = minimumTimeout > Long.MAX_VALUE - now
                    ? Long.MAX_VALUE : now + minimumTimeout;
            mAggregateLockout = new AggregateLockout(request.origin, request.originSerial, deadline);
        }
    }

    private void onChecked(Request request, SecureSpaceCredentialResponse response) {
        Log.d(TAG, "Credential check returned; active=" + isCurrent(request)
                + ", proof=" + (response.getHandoffToken() != null));
        if (response.isErasurePending()) {
            mErasurePending = true;
            cancel();
            if (request.callback != null) request.callback.onAccepted();
            return;
        }
        if (!isCurrent(request)) {
            cancelToken(response.getHandoffToken());
            return;
        }
        IBinder token = response.getHandoffToken();
        if (token == null || response.getMatchedUserId() < 0) {
            request.active.set(false);
            mRequest = null;
            if (mSelectedUser.getSelectedUserId() == request.origin
                    && hasIdentity(request.origin, request.originSerial)) {
                request.callback.onRejected(response);
            }
            return;
        }
        request.token = token;
        request.destination = response.getMatchedUserId();
        request.destinationSerial = response.getMatchedSerialNumber();
        request.callback.onAccepted();
        mBackground.execute(() -> {
            boolean prepared = false;
            try {
                prepared = request.isActive() && mBackend.prepare(token);
                if (prepared && request.destination != request.origin) {
                    // Publish before switchUser: the source can be paused before callbacks arrive.
                    request.switchRequested.set(true);
                    prepared = request.isActive()
                            && mBackend.switchUser(request.destination);
                }
            } catch (Exception error) {
                prepared = false;
            }
            boolean accepted = prepared;
            mMain.execute(() -> {
                if (!isCurrent(request)) { cancelToken(token); return; }
                if (!accepted) { Log.d(TAG, "Native entry preparation rejected"); cancel(); return; }
                Log.d(TAG, "Native entry preparation succeeded");
                request.prepared = true;
                tryComplete();
            });
        });
    }

    private void tryComplete() {
        Request request = mRequest;
        if (request == null || !request.prepared || request.consuming) return;
        if (!isCurrent(request)) { cancel(); return; }
        Host host = mHost;
        if ((request.switchRequested.get() && !request.switchCompleted.get())
                || mUserTracker.getUserId() != request.destination
                || mBackend.currentUser() != request.destination
                || mUserTracker.isUserSwitching()
                || mSelectedUser.getSelectedUserId() != request.destination
                || !hasIdentity(request.destination, request.destinationSerial)
                || !mUsers.isUserUnlocked(android.os.UserHandle.of(request.destination))
                || host == null || !host.isReady(request.destination, request.destinationSerial)) {
            mMain.executeDelayed(this::tryComplete, 50);
            return;
        }
        Log.d(TAG, "Entry host ready; consuming native proof");
        request.consuming = true;
        mBackground.execute(() -> {
            boolean consumed = false;
            try {
                consumed = request.isActive() && (request.biometric
                        ? mBackend.consumeFingerprint(request.token, request.destination, request.destinationSerial)
                        : mBackend.consume(request.token, request.destination, request.destinationSerial));
            } catch (RuntimeException error) {
                // A failed native proof cannot be replaced with matched-user metadata.
            }
            boolean accepted = consumed;
            mMain.execute(() -> {
                if (!isCurrent(request)) return;
                Log.d(TAG, "Native proof consumption returned; accepted=" + accepted);
                if (!accepted || mHost != host
                        || (request.switchRequested.get() && !request.switchCompleted.get())
                        || mUserTracker.isUserSwitching()
                        || mSelectedUser.getSelectedUserId() != request.destination
                        || !hasIdentity(request.destination, request.destinationSerial)
                        || !host.isReady(request.destination, request.destinationSerial)) {
                    cancel();
                    return;
                }
                mRequest = null;
                // The policy proof must not retain a completed credential coroutine or view.
                request.callback = null;
                mConsumedRequest = request;
                if (request.biometric) {
                    host.completeBiometricAuthentication(request.destination, request.destinationSerial,
                            request.strongBiometric);
                } else {
                    host.completePrimaryAuthentication(request.destination, request.destinationSerial);
                }
            });
        });
    }

    private boolean isCurrent(Request request) {
        return mRequest == request && request.isActive();
    }

    private boolean hasIdentity(int userId, int serial) {
        UserInfo user = mUsers.getUserInfo(userId);
        return user != null && user.serialNumber == serial && !user.partial && !user.preCreated
                && user.isEnabled() && user.isFull();
    }

    private void cancelToken(IBinder token) {
        if (token != null) mBackground.execute(() -> mBackend.cancel(token));
    }

    private final class Request {
        final int origin;
        final int originSerial;
        volatile Callback callback;
        final long expiresAt = SystemClock.elapsedRealtime() + LIFETIME_MS;
        final AtomicBoolean active = new AtomicBoolean(true);
        boolean biometric;
        boolean strongBiometric;
        final AtomicBoolean switchRequested = new AtomicBoolean();
        final AtomicBoolean switchCompleted = new AtomicBoolean();
        volatile int destination = -1;
        volatile int destinationSerial = -1;
        volatile IBinder token;
        boolean prepared;
        boolean consuming;
        final ISecureSpaceCredentialAttempt witness = new ISecureSpaceCredentialAttempt.Stub() {
            @Override public boolean isActive() { return Request.this.isActive(); }
            @Override public void invalidate() {
                active.set(false);
                mMain.execute(() -> {
                    if (mRequest == Request.this || mConsumedRequest == Request.this
                            || (mPublishedProof != null
                                    && mPublishedProof.request == Request.this)) cancel();
                });
            }
        };
        Request(int origin, int serial, Callback callback) {
            this.origin = origin;
            originSerial = serial;
            this.callback = callback;
        }
        boolean isActive() {
            long now = SystemClock.elapsedRealtime();
            Callback source = callback;
            if (now >= expiresAt || !mPower.isInteractive()
                    || (!switchRequested.get() && source != null && !source.isActive())) {
                active.set(false);
            }
            return active.get();
        }
    }
}
