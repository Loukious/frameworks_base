/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.biometrics.sensors.fingerprint;

import android.content.Context;
import android.content.pm.UserInfo;
import android.hardware.fingerprint.Fingerprint;
import android.os.UserManager;
import android.util.Slog;
import com.android.server.LocalServices;
import com.android.server.biometrics.HardwareAuthTokenUtils;
import com.android.server.locksettings.LockSettingsInternal;
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
        if (hasUnreadableMetadata(context, sensorId)) {
            Slog.w(TAG, "Authentication rejected: fingerprint metadata unavailable");
            return null;
        }
        if (hardwareToken == null || hardwareToken.length != 69 || hardwareToken[0] != 0) {
            Slog.w(TAG, "Authentication rejected: signed hardware token unavailable");
            return null;
        }
        var hat = HardwareAuthTokenUtils.toHardwareAuthToken(hardwareToken);
        if ((hat.authenticatorType & 2) == 0 || hat.userId == 0) {
            Slog.w(TAG, "Authentication rejected: signed fingerprint identity unavailable");
            return null;
        }
        LockSettingsInternal locks = LocalServices.getService(LockSettingsInternal.class);
        if (locks == null) {
            Slog.w(TAG, "Authentication rejected: lock service unavailable");
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
        var selected = SecureSpaceFingerprintPolicy.resolve(templates, fingerId, hat.userId,
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
            Slog.w(TAG, "Authentication rejected: template=" + matchingTemplate
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

    public static boolean hasRoutingCandidate(Context context, int sensorId) {
        if (hasUnreadableMetadata(context, sensorId)) return false;
        LockSettingsInternal locks = LocalServices.getService(LockSettingsInternal.class);
        if (locks == null) return false;
        FingerprintUtils utils = FingerprintUtils.getInstance(sensorId);
        for (UserInfo user : users(context)) {
            var identity = locks.getSecureSpaceFingerprintIdentity(user.id);
            if (identity == null || !identity.storageUnlocked() || !identity.strongAuthAllowed()) continue;
            for (Fingerprint template : utils.getBiometricsForUser(context, user.id)) {
                if (ownsUniqueTemplate(context, sensorId, user.id, template.getBiometricId())
                        && locks.isSecureSpaceFingerprintBindingCurrent(sensorId,
                                template.getBiometricId(), identity)) return true;
            }
        }
        return false;
    }
}
