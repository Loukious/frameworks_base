/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.biometrics.sensors.fingerprint;

import android.content.Context;
import android.app.ActivityManagerInternal;
import android.app.admin.DevicePolicyManager;
import android.content.pm.UserInfo;
import android.hardware.fingerprint.Fingerprint;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import android.util.Slog;
import com.android.server.LocalServices;
import com.android.server.biometrics.HardwareAuthTokenUtils;
import com.android.server.locksettings.LockSettingsInternal;
import com.android.server.security.authenticationpolicy.SecureLockDeviceServiceInternal;
import java.util.ArrayList;
import java.util.List;

/** Shared HAL group with separately owned native user metadata and unmodified signed SIDs. */
public final class SecureSpaceFingerprintPool {
    private static final String TAG = "SecureSpaceFingerprintPool";
    private SecureSpaceFingerprintPool() {}

    public static boolean isSharedUser(Context context, int userId) {
        if (userId == 0) return true;
        UserInfo user = context.getSystemService(UserManager.class).getUserInfo(userId);
        return user != null && UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(user.userType);
    }

    public static int hardwareUserId(Context context, int logicalUserId) {
        return isSharedUser(context, logicalUserId) ? 0 : logicalUserId;
    }

    public static List<UserInfo> users(Context context) {
        List<UserInfo> users = new ArrayList<>();
        for (UserInfo user : context.getSystemService(UserManager.class).getUsers(false, false, false)) {
            if (user.id == 0 || UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(user.userType)) users.add(user);
        }
        return users;
    }

    public static boolean hasUnreadableMetadata(Context context, int sensorId) {
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) {
            // This legacy API returns BiometricUserState.isInvalidBiometricState().
            if (utils.hasValidBiometricUserState(context, user.id)) return true;
        }
        return false;
    }

    public static List<Fingerprint> allTemplates(Context context, int sensorId) {
        List<Fingerprint> result = new ArrayList<>();
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) result.addAll(utils.getBiometricsForUser(context, user.id));
        return result;
    }

    public static boolean ownsUniqueTemplate(Context context, int sensorId, int userId, int fingerId) {
        if (fingerId == 0 || hasUnreadableMetadata(context, sensorId)) return false;
        int owners = 0;
        boolean owned = false;
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) {
            for (Fingerprint template : utils.getBiometricsForUser(context, user.id)) {
                if (template.getBiometricId() != fingerId) continue;
                owners++;
                owned |= user.id == userId;
            }
        }
        return owned && owners == 1;
    }

    public static LockSettingsInternal.SecureSpaceFingerprintIdentity resolve(
            Context context, int sensorId, int fingerId, byte[] hardwareToken,
            int requestedUser, boolean trustedKeyguard) {
        return resolveInternal(context, sensorId, fingerId, hardwareToken, requestedUser,
                trustedKeyguard, false);
    }

    /**
     * Identifies a foreign Secure Space whose primary credential is still required.
     *
     * The current/origin user must already be fully unlocked and strong-auth eligible. The
     * returned destination is ownership metadata only; callers must not turn it into biometric
     * authentication or unlock CE storage with it.
     */
    public static LockSettingsInternal.SecureSpaceFingerprintIdentity resolveIdentification(
            Context context, int sensorId, int fingerId, byte[] hardwareToken,
            int requestedUser) {
        LockSettingsInternal locks = LocalServices.getService(LockSettingsInternal.class);
        if (locks == null) return null;
        var origin = locks.getSecureSpaceFingerprintIdentity(requestedUser);
        if (origin == null || !origin.storageUnlocked() || !origin.strongAuthAllowed()) {
            Slog.w(TAG, "Identification rejected: origin not primary-authenticated");
            return null;
        }
        var destination = resolveInternal(context, sensorId, fingerId, hardwareToken,
                requestedUser, true, true);
        if (destination == null || destination.userId() == requestedUser
                || !isSecureSpaceUser(context, destination.userId())
                || !isKeyguardFingerprintAllowed(context, destination.userId())
                || (destination.storageUnlocked() && destination.strongAuthAllowed())) {
            return null;
        }
        return destination;
    }

    private static LockSettingsInternal.SecureSpaceFingerprintIdentity resolveInternal(
            Context context, int sensorId, int fingerId, byte[] hardwareToken,
            int requestedUser, boolean trustedKeyguard, boolean identificationOnly) {
        if (hasUnreadableMetadata(context, sensorId)) {
            Slog.w(TAG, (identificationOnly ? "Identification" : "Authentication")
                    + " rejected: fingerprint metadata unavailable");
            return null;
        }
        if (hardwareToken == null || hardwareToken.length != 69 || hardwareToken[0] != 0) {
            Slog.w(TAG, (identificationOnly ? "Identification" : "Authentication")
                    + " rejected: signed hardware token unavailable");
            return null;
        }
        var hat = HardwareAuthTokenUtils.toHardwareAuthToken(hardwareToken);
        if ((hat.authenticatorType & 2) == 0 || hat.userId == 0) {
            Slog.w(TAG, (identificationOnly ? "Identification" : "Authentication")
                    + " rejected: signed fingerprint identity unavailable");
            return null;
        }
        LockSettingsInternal locks = LocalServices.getService(LockSettingsInternal.class);
        if (locks == null) {
            Slog.w(TAG, (identificationOnly ? "Identification" : "Authentication")
                    + " rejected: lock service unavailable");
            return null;
        }
        List<SecureSpaceFingerprintPolicy.Template> templates = new ArrayList<>();
        List<LockSettingsInternal.SecureSpaceFingerprintIdentity> identities = new ArrayList<>();
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) {
            var identity = locks.getSecureSpaceFingerprintIdentity(user.id);
            if (identity == null) {
                // Retain ambiguous metadata as an invalid owner rather than silently dropping it.
                for (Fingerprint template : utils.getBiometricsForUser(context, user.id)) {
                    templates.add(new SecureSpaceFingerprintPolicy.Template(template.getBiometricId(),
                            user.id, user.serialNumber, 0, false, false, false));
                }
                continue;
            }
            identities.add(identity);
            for (Fingerprint template : utils.getBiometricsForUser(context, user.id)) {
                boolean bound = locks.isSecureSpaceFingerprintBindingCurrent(sensorId,
                        template.getBiometricId(), identity);
                templates.add(new SecureSpaceFingerprintPolicy.Template(template.getBiometricId(),
                        user.id, user.serialNumber, identity.secureUserId(), bound,
                        identity.storageUnlocked(), identity.strongAuthAllowed()));
            }
        }
        var selected = identificationOnly
                ? SecureSpaceFingerprintPolicy.identify(templates, fingerId, hat.userId)
                : SecureSpaceFingerprintPolicy.resolve(templates, fingerId, hat.userId,
                        requestedUser, trustedKeyguard);
        if (selected == null) {
            boolean matchingTemplate = false;
            boolean signedSidMatch = false;
            boolean bindingCurrent = false;
            boolean storageUnlocked = false;
            boolean strongAuthAllowed = false;
            for (var candidate : templates) {
                if (candidate.fingerId() != fingerId) continue;
                matchingTemplate = true;
                signedSidMatch |= candidate.secureUserId() == hat.userId;
                bindingCurrent |= candidate.bindingCurrent();
                storageUnlocked |= candidate.storageUnlocked();
                strongAuthAllowed |= candidate.strongAuthAllowed();
            }
            Slog.w(TAG, (identificationOnly ? "Identification" : "Authentication")
                    + " rejected: template=" + matchingTemplate
                    + " signedSid=" + signedSidMatch + " binding=" + bindingCurrent
                    + " storage=" + storageUnlocked + " strongAuth=" + strongAuthAllowed);
            return null;
        }
        for (var identity : identities) {
            if (identity.userId() == selected.userId()
                    && identity.serialNumber() == selected.serialNumber()) return identity;
        }
        return null;
    }

    public static void updateAuthenticatorIds(Context context, int sensorId, int userId,
            long actualAuthenticatorId, java.util.Map<Integer, Long> ids) {
        if (!isSharedUser(context, userId)) {
            ids.put(userId, actualAuthenticatorId);
            return;
        }
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) {
            ids.put(user.id, utils.getBiometricsForUser(context, user.id).isEmpty()
                    ? 0L : actualAuthenticatorId);
        }
    }

    public static boolean hasConcealedUsers(Context context) {
        for (UserInfo user : users(context)) {
            if (user.id != 0) return true;
        }
        return false;
    }

    private static boolean isKeyguardFingerprintAllowed(Context context, int userId) {
        int biometricDefault = Settings.Secure.getIntForUser(context.getContentResolver(),
                Settings.Secure.BIOMETRIC_KEYGUARD_ENABLED, 1, userId);
        boolean enabled = Settings.Secure.getIntForUser(context.getContentResolver(),
                Settings.Secure.FINGERPRINT_KEYGUARD_ENABLED,
                biometricDefault == 1 ? 1 : 0, userId) != 0;
        int disabled = context.getSystemService(DevicePolicyManager.class)
                .getKeyguardDisabledFeatures(null, userId);
        return enabled && (disabled & DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT) == 0;
    }

    private static boolean isSecureSpaceUser(Context context, int userId) {
        UserInfo user = context.getSystemService(UserManager.class).getUserInfo(userId);
        return user != null && !user.partial && !user.preCreated && user.isFull()
                && user.isEnabled() && user.isInitialized()
                && UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(user.userType);
    }

    private static boolean isCurrentUserWithoutPendingSwitch(int userId) {
        ActivityManagerInternal am = LocalServices.getService(ActivityManagerInternal.class);
        if (am == null) return false;
        var users = am.getCurrentAndTargetUserIds();
        return users != null && users.first == userId && users.second == UserHandle.USER_NULL;
    }

    /** Fresh server-side recheck used immediately before an identification-only user switch. */
    public static boolean isIdentificationSwitchEligible(Context context, int sensorId, int fingerId,
            int originUser, int originSerial, long originForegroundGeneration,
            long originSessionEpoch, long originProtectorId, int destinationUser,
            int destinationSerial, long destinationSecureUserId, long destinationProtectorId) {
        if (sensorId < 0 || fingerId == 0 || destinationSecureUserId == 0
                || destinationProtectorId == 0 || originUser == destinationUser
                || !isCurrentUserWithoutPendingSwitch(originUser)
                || !isSecureSpaceUser(context, destinationUser)
                || !isKeyguardFingerprintAllowed(context, destinationUser)) {
            return false;
        }
        LockSettingsInternal locks = LocalServices.getService(LockSettingsInternal.class);
        if (locks == null) return false;
        var originSnapshot = new LockSettingsInternal.SecureSpaceFingerprintOrigin(originUser,
                originSerial, originForegroundGeneration, originSessionEpoch, originProtectorId);
        if (!locks.isSecureSpaceFingerprintOriginCurrent(originSnapshot)) return false;
        SecureLockDeviceServiceInternal secureLock =
                LocalServices.getService(SecureLockDeviceServiceInternal.class);
        if (secureLock != null && secureLock.isSecureLockDeviceEnabled()) return false;
        var destination = locks.getSecureSpaceFingerprintIdentity(destinationUser);
        if (destination == null || destination.serialNumber() != destinationSerial
                || destination.secureUserId() != destinationSecureUserId
                || destination.protectorId() != destinationProtectorId
                || (destination.storageUnlocked() && destination.strongAuthAllowed())) {
            return false;
        }
        if (!ownsUniqueTemplate(context, sensorId, destinationUser, fingerId)
                || !locks.isSecureSpaceFingerprintBindingCurrent(sensorId, fingerId, destination)) {
            return false;
        }
        UserManager users = context.getSystemService(UserManager.class);
        UserInfo originInfo = users.getUserInfo(originUser);
        if (originInfo == null || users.hasUserRestriction(UserManager.DISALLOW_USER_SWITCH,
                originInfo.getUserHandle())) {
            return false;
        }
        // The checks above cross LockSettings, UserManager and fingerprint metadata. Re-sample the
        // two externally mutable policy fences immediately before the final ActivityManager state
        // check so a policy/Secure Lock change during those slower reads fails closed.
        if (!isKeyguardFingerprintAllowed(context, destinationUser)) return false;
        secureLock = LocalServices.getService(SecureLockDeviceServiceInternal.class);
        if (secureLock != null && secureLock.isSecureLockDeviceEnabled()) return false;
        if (!locks.isSecureSpaceFingerprintOriginCurrent(originSnapshot)) return false;
        if (!locks.isSecureSpaceFingerprintIdentityCurrent(destination)) return false;
        if (!ownsUniqueTemplate(context, sensorId, destinationUser, fingerId)
                || !locks.isSecureSpaceFingerprintBindingCurrent(sensorId, fingerId, destination)) {
            return false;
        }
        originInfo = users.getUserInfo(originUser);
        if (originInfo == null || users.hasUserRestriction(UserManager.DISALLOW_USER_SWITCH,
                originInfo.getUserHandle())) {
            return false;
        }
        return isCurrentUserWithoutPendingSwitch(originUser);
    }

    public static boolean hasRoutingCandidate(Context context, int sensorId) {
        if (hasUnreadableMetadata(context, sensorId)) return false;
        LockSettingsInternal locks = LocalServices.getService(LockSettingsInternal.class);
        if (locks == null) return false;
        int currentUser = android.app.ActivityManager.getCurrentUser();
        var origin = locks.getSecureSpaceFingerprintIdentity(currentUser);
        boolean mayIdentifyLockedDestination = origin != null && origin.storageUnlocked()
                && origin.strongAuthAllowed();
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) {
            var identity = locks.getSecureSpaceFingerprintIdentity(user.id);
            if (identity == null) continue;
            boolean canAuthenticate = identity.storageUnlocked() && identity.strongAuthAllowed();
            boolean canIdentify = mayIdentifyLockedDestination && user.id != currentUser
                    && isSecureSpaceUser(context, user.id)
                    && isKeyguardFingerprintAllowed(context, user.id);
            if (!canAuthenticate && !canIdentify) continue;
            for (Fingerprint template : utils.getBiometricsForUser(context, user.id)) {
                if (ownsUniqueTemplate(context, sensorId, user.id, template.getBiometricId())
                        && locks.isSecureSpaceFingerprintBindingCurrent(sensorId,
                                template.getBiometricId(), identity)) return true;
            }
        }
        return false;
    }
}
