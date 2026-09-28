/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.recoverysystem;

/** All-user cryptographic erasure ordering. Only a committed duress decision may call this. */
final class SecureAuthKeyErasure {
    interface Backend {
        /** Native registry, including disabled users, profiles, and partially removed users. */
        int[] getAllUserIds() throws Exception;
        void deleteKeystoreKeys() throws Exception;
        void deleteSecretkeeperSecretsIfSupported() throws Exception;
        void destroyUserStorageKeys(int userId) throws Exception;
        void destroySystemStorageKey() throws Exception;
        void destroyMetadataKey() throws Exception;
        void shutdown();
        void onFailure(String stage, Throwable failure);
    }

    interface Operation {
        void run() throws Exception;
    }

    static void run(Backend backend) {
        // Snapshot before destroying keys: never enumerate a filtered public user list.
        int[] userIds = new int[0];
        try {
            userIds = backend.getAllUserIds().clone();
        } catch (Throwable failure) {
            report(backend, "user registry", failure);
        }
        attempt(backend, "keystore", backend::deleteKeystoreKeys);
        attempt(backend, "secretkeeper", backend::deleteSecretkeeperSecretsIfSupported);
        for (int userId : userIds) {
            attempt(backend, "user storage", () -> backend.destroyUserStorageKeys(userId));
        }
        attempt(backend, "system storage", backend::destroySystemStorageKey);
        attempt(backend, "metadata", backend::destroyMetadataKey);
        // Persisted keys are gone; loaded fscrypt keys may remain until poweroff.
        backend.shutdown();
    }

    private static void attempt(Backend backend, String stage, Operation operation) {
        try {
            operation.run();
        } catch (Throwable failure) {
            report(backend, stage, failure);
        }
    }

    private static void report(Backend backend, String stage, Throwable failure) {
        try {
            backend.onFailure(stage, failure);
        } catch (Throwable ignored) {
            // A broken diagnostic path must not interrupt remaining destruction or shutdown.
        }
    }
}
