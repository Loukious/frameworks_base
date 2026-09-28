/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.locksettings;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/** Receipt certifying disjoint duress secrets against a native credential namespace. */
final class SecureAuthDuressReservation {
    record Identity(int userId, int serialNumber, long protectorId) {
        Identity {
            if (userId < 0 || serialNumber < 0 || protectorId == 0) {
                throw new IllegalArgumentException("Invalid native credential identity");
            }
        }
    }
    private final byte[] binding;
    private final List<Identity> identities;

    private SecureAuthDuressReservation(byte[] binding, List<Identity> identities) {
        if (binding.length != 32 || identities.isEmpty() || identities.size() > 4) {
            throw new IllegalArgumentException("Invalid reservation dimensions");
        }
        int previous = -1;
        for (Identity identity : identities) {
            if (identity.userId() <= previous) {
                throw new IllegalArgumentException("Unordered or repeated native user");
            }
            previous = identity.userId();
        }
        this.binding = binding.clone();
        this.identities = List.copyOf(identities);
    }

    static SecureAuthDuressReservation certify(byte[] encodedVerifiers, List<Identity> identities) {
        return new SecureAuthDuressReservation(digest(encodedVerifiers), identities);
    }

    boolean covers(byte[] encodedVerifiers, List<Identity> current) {
        return !current.isEmpty() && MessageDigest.isEqual(binding, digest(encodedVerifiers))
                && current.size() <= 4 && identities.containsAll(current);
    }

    byte[] encode() {
        ByteBuffer out = ByteBuffer.allocate(34 + 16 * identities.size());
        out.put((byte) 1).put(binding).put((byte) identities.size());
        for (Identity identity : identities) {
            out.putInt(identity.userId()).putInt(identity.serialNumber()).putLong(identity.protectorId());
        }
        return out.array();
    }

    static SecureAuthDuressReservation decode(byte[] bytes) {
        if (bytes == null || bytes.length < 50 || bytes.length > 98) {
            throw new IllegalArgumentException("Invalid reservation length");
        }
        ByteBuffer in = ByteBuffer.wrap(bytes);
        if (in.get() != 1) throw new IllegalArgumentException("Invalid reservation version");
        byte[] binding = new byte[32];
        in.get(binding);
        int count = Byte.toUnsignedInt(in.get());
        if (count < 1 || count > 4 || in.remaining() != count * 16) {
            throw new IllegalArgumentException("Invalid reservation count");
        }
        java.util.ArrayList<Identity> identities = new java.util.ArrayList<>();
        for (int i = 0; i < count; i++) {
            identities.add(new Identity(in.getInt(), in.getInt(), in.getLong()));
        }
        return new SecureAuthDuressReservation(binding, identities);
    }

    private static byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
