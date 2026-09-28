/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.recoverysystem;

import android.hardware.security.secretkeeper.ISecretkeeper;
import android.os.IVold;
import android.os.ServiceManager;
import android.security.AndroidKeyStoreMaintenance;
import android.util.Slog;

import com.android.server.LocalServices;
import com.android.server.pm.UserManagerInternal;
import com.android.server.power.PowerManagerService;

import java.util.concurrent.atomic.AtomicBoolean;

/** Trusted in-process entry point; no Binder API and no factory-reset substitution. */
public final class SecureAuthDuressWipe {
    private static final String TAG = "SecureAuthDuressWipe";
    private static final AtomicBoolean STARTED = new AtomicBoolean();

    private SecureAuthDuressWipe() {}

    public static void run() {
        if (!STARTED.compareAndSet(false, true)) {
            return;
        }
        SecureAuthKeyErasure.run(new SecureAuthKeyErasure.Backend() {
            private IVold vold() {
                IVold service = IVold.Stub.asInterface(ServiceManager.getService("vold"));
                if (service == null) throw new IllegalStateException("vold unavailable");
                return service;
            }

            @Override
            public int[] getAllUserIds() {
                UserManagerInternal manager = LocalServices.getService(UserManagerInternal.class);
                if (manager == null) throw new IllegalStateException("user registry unavailable");
                return manager.getUserIdsForKeyErasure();
            }

            @Override
            public void deleteKeystoreKeys() throws Exception {
                AndroidKeyStoreMaintenance.deleteAllKeys();
            }

            @Override
            public void deleteSecretkeeperSecretsIfSupported() throws Exception {
                String name = ISecretkeeper.DESCRIPTOR + "/default";
                if (!ServiceManager.isDeclared(name)) return;
                // Do not wait indefinitely for an optional HAL during destruction.
                ISecretkeeper keeper = ISecretkeeper.Stub.asInterface(
                        ServiceManager.checkService(name));
                if (keeper == null) throw new IllegalStateException("Secretkeeper unavailable");
                keeper.deleteAll();
            }

            @Override
            public void destroyUserStorageKeys(int userId) throws Exception {
                // Evicting loaded keys before shutdown can cause slow/fatal userdata I/O.
                vold().destroyUserStorageKeys2(userId, false);
            }

            @Override
            public void destroySystemStorageKey() throws Exception {
                vold().destroySystemStorageKey();
            }

            @Override
            public void destroyMetadataKey() throws Exception {
                vold().destroyMetadataKey("/data");
            }

            @Override
            public void shutdown() {
                PowerManagerService.lowLevelShutdown(null);
            }

            @Override
            public void onFailure(String stage, Throwable failure) {
                // Do not persist private user IDs, credential bytes, or key-directory paths.
                Slog.e(TAG, "Key destruction stage failed: " + stage);
            }
        });
    }
}
