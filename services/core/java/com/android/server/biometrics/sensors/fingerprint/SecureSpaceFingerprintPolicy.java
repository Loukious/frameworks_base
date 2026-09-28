/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.biometrics.sensors.fingerprint;

import java.util.List;

/** Decisions over native template ownership and signed hardware-token identities. */
final class SecureSpaceFingerprintPolicy {
    record Template(int fingerId, int userId, int serialNumber, long secureUserId,
            boolean bindingCurrent, boolean storageUnlocked, boolean strongAuthAllowed) {}

    static Template resolve(List<Template> templates, int fingerId, long signedSecureUserId,
            int requestedUserId, boolean trustedKeyguard) {
        // Native template IDs are opaque uint32 values represented by signed Java ints.
        if (fingerId == 0 || signedSecureUserId == 0) return null;
        Template owner = null;
        for (Template template : templates) {
            if (template.fingerId() != fingerId) continue;
            // Ambiguous native metadata never authorizes a user, even if one SID matches.
            if (owner != null) return null;
            owner = template;
        }
        if (owner == null || !owner.bindingCurrent() || owner.secureUserId() == 0
                || owner.secureUserId() != signedSecureUserId) return null;
        if (trustedKeyguard) {
            return owner.storageUnlocked() && owner.strongAuthAllowed() ? owner : null;
        }
        return owner.userId() == requestedUserId ? owner : null;
    }
}
