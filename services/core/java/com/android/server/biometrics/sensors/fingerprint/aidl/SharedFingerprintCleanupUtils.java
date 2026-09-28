/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.biometrics.sensors.fingerprint.aidl;

import android.content.Context;
import android.hardware.fingerprint.Fingerprint;
import com.android.server.biometrics.sensors.BiometricUtils;
import com.android.server.biometrics.sensors.fingerprint.SecureSpaceFingerprintPool;
import java.util.List;

/** Enumeration may remove stale metadata only from its unique native owner. */
final class SharedFingerprintCleanupUtils implements BiometricUtils<Fingerprint> {
    private final int sensorId;
    private final BiometricUtils<Fingerprint> delegate;
    SharedFingerprintCleanupUtils(int sensorId, BiometricUtils<Fingerprint> delegate) {
        this.sensorId = sensorId;
        this.delegate = delegate;
    }
    public List<Fingerprint> getBiometricsForUser(Context c, int u) {
        return delegate.getBiometricsForUser(c, u);
    }
    public void removeBiometricForUser(Context c, int ignoredUser, int id) {
        Integer owner = null;
        for (var user : SecureSpaceFingerprintPool.users(c)) {
            for (var finger : delegate.getBiometricsForUser(c, user.id)) {
                if (finger.getBiometricId() != id) continue;
                if (owner != null) return;
                owner = user.id;
            }
        }
        if (owner != null) delegate.removeBiometricForUser(c, owner, id);
    }
    public void addBiometricForUser(Context c, int u, Fingerprint f) {
        // An enumerated HAL identifier does not certify a native user/SID binding.
    }
    public void renameBiometricForUser(Context c, int u, int id, CharSequence n) {
        delegate.renameBiometricForUser(c, u, id, n);
    }
    public CharSequence getUniqueName(Context c, int u) { return delegate.getUniqueName(c,u); }
    public void setInvalidationInProgress(Context c,int u,boolean b) {
        delegate.setInvalidationInProgress(c,u,b);
    }
    public boolean isInvalidationInProgress(Context c,int u) {
        return delegate.isInvalidationInProgress(c,u);
    }
    public boolean hasValidBiometricUserState(Context c,int u) {
        for (var user : SecureSpaceFingerprintPool.users(c)) {
            // Existing FingerprintUtils returns the invalid-state flag despite this API name.
            if (delegate.hasValidBiometricUserState(c,user.id)) return true;
        }
        return false;
    }
    public void deleteStateForUser(int u) { delegate.deleteStateForUser(u); }
}
