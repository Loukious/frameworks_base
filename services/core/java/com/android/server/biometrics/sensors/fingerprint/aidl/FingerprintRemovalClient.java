/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.biometrics.sensors.fingerprint.aidl;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.Context;
import com.android.server.biometrics.sensors.fingerprint.SecureSpaceFingerprintPool;

import android.hardware.fingerprint.Fingerprint;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Slog;

import com.android.server.biometrics.log.BiometricContext;
import com.android.server.biometrics.log.BiometricLogger;
import com.android.server.biometrics.sensors.BiometricUtils;
import com.android.server.biometrics.sensors.ClientMonitorCallbackConverter;
import com.android.server.biometrics.sensors.RemovalClient;

import java.util.Map;
import java.util.function.Supplier;

/**
 * Fingerprint-specific removal client supporting the
 * {@link android.hardware.biometrics.fingerprint.IFingerprint} interface.
 */
public class FingerprintRemovalClient extends RemovalClient<Fingerprint, AidlSession> {
    private static final String TAG = "FingerprintRemovalClient";

    private final int[] mBiometricIds;
    private final int mRemovalReason;

    public FingerprintRemovalClient(@NonNull Context context,
            @NonNull Supplier<AidlSession> lazyDaemon, @NonNull IBinder token,
            @Nullable ClientMonitorCallbackConverter listener, int[] biometricIds, int userId,
            @NonNull String owner, @NonNull BiometricUtils<Fingerprint> utils, int sensorId,
            @NonNull BiometricLogger logger, @NonNull BiometricContext biometricContext,
            @NonNull Map<Integer, Long> authenticatorIds, int reason) {
        super(context, lazyDaemon, token, listener, userId, owner, utils, sensorId,
                logger, biometricContext, authenticatorIds, reason);
        mBiometricIds = biometricIds.clone();
        mRemovalReason = reason;
    }

    @Override
    protected void startHalOperation() {
        if (SecureSpaceFingerprintPool.isSharedUser(getContext(), getTargetUserId())) {
            if (SecureSpaceFingerprintPool.hasUnreadableMetadata(getContext(), getSensorId())) {
                rejectRemoval();
                return;
            }
            boolean cleanup = mRemovalReason == android.hardware.biometrics.BiometricsProtoEnums
                    .UNENROLL_REASON_DANGLING_HAL;
            for (int id : mBiometricIds) {
                boolean allowed = id > 0 && (cleanup
                        ? SecureSpaceFingerprintPool.allTemplates(getContext(), getSensorId())
                                .stream().noneMatch(f -> f.getBiometricId() == id)
                        : SecureSpaceFingerprintPool.ownsUniqueTemplate(getContext(),
                                getSensorId(), getTargetUserId(), id));
                if (!allowed) {
                    rejectRemoval();
                    return;
                }
            }
        }
        try {
            getFreshDaemon().getSession().removeEnrollments(mBiometricIds);
        } catch (RemoteException e) {
            Slog.e(TAG, "Remote exception when requesting remove", e);
            mCallback.onClientFinished(this, false /* success */);
        }
    }
    private void rejectRemoval() {
        try {
            if (getListener() != null) {
                getListener().onError(getSensorId(), getCookie(),
                        android.hardware.biometrics.BiometricConstants
                                .BIOMETRIC_ERROR_UNABLE_TO_PROCESS, 0);
            }
        } catch (RemoteException ignored) {
            Slog.w(TAG, "Fingerprint removal receiver disconnected");
        }
        mCallback.onClientFinished(this, false);
    }
}
