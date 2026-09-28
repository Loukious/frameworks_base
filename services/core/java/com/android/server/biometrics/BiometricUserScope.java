/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.biometrics;

import android.content.Context;
import android.content.pm.UserInfo;
import android.os.RemoteException;
import android.os.UserManager;
import android.security.GateKeeper;
import android.security.KeyStoreAuthorization;
import android.system.keystore2.ResponseCode;

/** Keeps unchanged signed biometric tokens inside their native full user/profile namespace. */
public final class BiometricUserScope {
    private BiometricUserScope() {}

    public static int addAuthToken(Context context, KeyStoreAuthorization authorization,
            byte[] token, int targetUser) {
        if (token == null || token.length != 69 || token[0] != 0) return ResponseCode.SYSTEM_ERROR;
        var hat = HardwareAuthTokenUtils.toHardwareAuthToken(token);
        if ((hat.authenticatorType & 2) == 0 || hat.userId == 0) return ResponseCode.SYSTEM_ERROR;
        UserManager users = context.getSystemService(UserManager.class);
        UserInfo user = users.getUserInfo(targetUser);
        if (user == null) return ResponseCode.SYSTEM_ERROR;
        UserInfo parent = user.isProfile() ? users.getProfileParent(targetUser) : null;
        int fullUser = parent == null ? targetUser : parent.id;
        int[] scope = users.getProfileIdsWithDisabled(fullUser);
        boolean targetPresent = false;
        boolean nativeSid = false;
        for (int scopedUser : scope) {
            targetPresent |= scopedUser == targetUser;
            try {
                long sid = GateKeeper.getService().getSecureUserId(scopedUser);
                nativeSid |= sid != 0 && sid == hat.userId;
            } catch (RemoteException | RuntimeException e) {
                return ResponseCode.SYSTEM_ERROR;
            }
        }
        if (!targetPresent || !nativeSid) return ResponseCode.SYSTEM_ERROR;
        return authorization.addAuthTokenForUsers(scope, token);
    }
}
