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
import android.content.Context;
import com.android.server.biometrics.sensors.fingerprint.SecureSpaceFingerprintPool;

import android.hardware.biometrics.BiometricAuthenticator;
import android.hardware.biometrics.BiometricsProtoEnums;
import android.hardware.fingerprint.Fingerprint;
import android.os.IBinder;
import android.util.Slog;

import com.android.server.biometrics.log.BiometricContext;
import com.android.server.biometrics.log.BiometricLogger;
import com.android.server.biometrics.sensors.BiometricNotificationUtils;
import com.android.server.biometrics.sensors.BiometricUtils;
import com.android.server.biometrics.sensors.InternalCleanupClient;
import com.android.server.biometrics.sensors.InternalEnumerateClient;
import com.android.server.biometrics.sensors.RemovalClient;
import com.android.server.biometrics.sensors.fingerprint.FingerprintUtils;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Fingerprint-specific internal cleanup client supporting the
 * {@link android.hardware.biometrics.fingerprint.IFingerprint} AIDL interface.
 */
public class FingerprintInternalCleanupClient
        extends InternalCleanupClient<Fingerprint, AidlSession> {

    private static final String TAG = "FingerprintInternalCleanupClient";

    public FingerprintInternalCleanupClient(@NonNull Context context,
            @NonNull Supplier<AidlSession> lazyDaemon,
            int userId, @NonNull String owner, int sensorId,
            @NonNull BiometricLogger logger, @NonNull BiometricContext biometricContext,
            @NonNull FingerprintUtils utils, @NonNull Map<Integer, Long> authenticatorIds) {
        super(context, lazyDaemon, userId, owner, sensorId, logger, biometricContext,
                utils, authenticatorIds);
    }

    @Override
    public void start(@NonNull com.android.server.biometrics.sensors.ClientMonitorCallback callback) {
        if (SecureSpaceFingerprintPool.isSharedUser(getContext(), getTargetUserId())
                && SecureSpaceFingerprintPool.hasUnreadableMetadata(getContext(), getSensorId())) {
            // Unknown ownership must never be converted into deletion of another user's slot.
            callback.onClientFinished(this, false);
            return;
        }
        super.start(callback);
    }

    @Override
    protected InternalEnumerateClient<AidlSession> getEnumerateClient(Context context,
            Supplier<AidlSession> lazyDaemon, IBinder token, int userId, String owner,
            List<Fingerprint> enrolledList, BiometricUtils<Fingerprint> utils, int sensorId,
            @NonNull BiometricLogger logger, @NonNull BiometricContext biometricContext) {
        if (SecureSpaceFingerprintPool.isSharedUser(context, userId)) {
            enrolledList = SecureSpaceFingerprintPool.allTemplates(context, sensorId);
            utils = new SharedFingerprintCleanupUtils(sensorId, utils);
        }
        return new FingerprintInternalEnumerateClient(context, lazyDaemon, token, userId, owner,
                enrolledList, utils, sensorId,
                logger.swapAction(context, BiometricsProtoEnums.ACTION_ENUMERATE),
                biometricContext);
    }

    @Override
    protected RemovalClient<Fingerprint, AidlSession> getRemovalClient(Context context,
            Supplier<AidlSession> lazyDaemon, IBinder token, int biometricId, int userId,
            String owner, BiometricUtils<Fingerprint> utils, int sensorId,
            @NonNull BiometricLogger logger, @NonNull BiometricContext biometricContext,
            Map<Integer, Long> authenticatorIds, int reason) {
        return new FingerprintRemovalClient(context, lazyDaemon, token,
                null /* ClientMonitorCallbackConverter */, new int[] {biometricId}, userId, owner,
                utils, sensorId, logger.swapAction(context, BiometricsProtoEnums.ACTION_REMOVE),
                biometricContext, authenticatorIds, reason);
    }

    @Override
    protected void onAddUnknownTemplate(int userId,
            @NonNull BiometricAuthenticator.Identifier identifier) {
        // Shared-group HAL discovery cannot establish native user/SID ownership.
        if (SecureSpaceFingerprintPool.isSharedUser(getContext(), userId)) return;
        mBiometricUtils.addBiometricForUser(
                getContext(), getTargetUserId(), (Fingerprint) identifier);
    }

    @Override
    public void handleInvalidBiometricState() {
        if (SecureSpaceFingerprintPool.isSharedUser(getContext(), getTargetUserId())) return;
        Slog.d(TAG, "Invalid fingerprint user state: delete the state.");
        mBiometricUtils.deleteStateForUser(getTargetUserId());
        BiometricNotificationUtils.showFingerprintLoeNotification(getContext());
    }

    @Override
    protected int getModality() {
        return BiometricsProtoEnums.MODALITY_FINGERPRINT;
    }
}
