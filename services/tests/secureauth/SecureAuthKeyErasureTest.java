/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.recoverysystem;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class SecureAuthKeyErasureTest {
    private static final class Backend implements SecureAuthKeyErasure.Backend {
        final List<String> events = new ArrayList<>();
        String failAt;
        boolean failDiagnostics;
        int[] users = {0, 10, 11, 12, 150};

        private void record(String event) {
            events.add(event);
            if (event.equals(failAt)) throw new IllegalStateException("simulated failure");
        }

        public int[] getAllUserIds() { record("registry"); return users; }
        public void deleteKeystoreKeys() { record("keystore"); }
        public void deleteSecretkeeperSecretsIfSupported() { record("secretkeeper"); }
        public void destroyUserStorageKeys(int id) { record("user:" + id); }
        public void destroySystemStorageKey() { record("system"); }
        public void destroyMetadataKey() { record("metadata"); }
        public void shutdown() { record("shutdown"); }
        public void onFailure(String stage, Throwable failure) {
            if (failDiagnostics) throw new IllegalStateException("diagnostic failure");
        }
    }

    private static List<String> completeSequence() {
        return List.of("registry", "keystore", "secretkeeper", "user:0", "user:10",
                "user:11", "user:12", "user:150", "system", "metadata", "shutdown");
    }

    @Test
    public void erasesEveryNativeIdentityAndFinishesWithShutdown() {
        Backend backend = new Backend();
        SecureAuthKeyErasure.run(backend);
        assertEquals(completeSequence(), backend.events);
    }

    @Test
    public void eachDestructionFailureStillAttemptsAllOtherKeysAndShutdown() {
        for (String stage : completeSequence().subList(1, 10)) {
            Backend backend = new Backend();
            backend.failAt = stage;
            SecureAuthKeyErasure.run(backend);
            assertEquals("Failure at " + stage, completeSequence(), backend.events);
        }
    }

    @Test
    public void registryFailureStillDestroysGlobalKeysAndShutsDown() {
        Backend backend = new Backend();
        backend.failAt = "registry";
        SecureAuthKeyErasure.run(backend);
        assertEquals(List.of("registry", "keystore", "secretkeeper", "system", "metadata",
                "shutdown"), backend.events);
    }

    @Test
    public void failedDiagnosticsCannotInterruptErasure() {
        Backend backend = new Backend();
        backend.failAt = "keystore";
        backend.failDiagnostics = true;
        SecureAuthKeyErasure.run(backend);
        assertEquals(completeSequence(), backend.events);
    }

    @Test
    public void emptyRegistryStillErasesSystemAndMetadataKeys() {
        Backend backend = new Backend();
        backend.users = new int[0];
        SecureAuthKeyErasure.run(backend);
        assertEquals(List.of("registry", "keystore", "secretkeeper", "system", "metadata",
                "shutdown"), backend.events);
    }
}
