/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.locksettings;

import java.nio.ByteBuffer;
import java.util.Objects;

/** Bounded serialization of duress-only stretched verifiers; never normal-user credentials. */
final class SecureAuthDuressCodec {
    private static final int VERSION = 1;
    private static final int SALT_SIZE = 16;
    private static final int DIGEST_SIZE = 32;
    private static final int RECORD_SIZE = 4 + SALT_SIZE + DIGEST_SIZE;
    private static final int ENCODED_SIZE = 1 + 2 * RECORD_SIZE;

    record Verifier(int type, int logN, int logR, int logP, byte[] salt, byte[] digest) {
        Verifier {
            // Types 3/4 are the stable native PIN/password types. Bound corrupted scrypt costs.
            if ((type != 3 && type != 4) || logN < 9 || logN > 14
                    || logR < 0 || logR > 4 || logP < 0 || logP > 3) {
                throw new IllegalArgumentException("Invalid duress verifier parameters");
            }
            Objects.requireNonNull(salt);
            Objects.requireNonNull(digest);
            if (salt.length != SALT_SIZE || digest.length != DIGEST_SIZE) {
                throw new IllegalArgumentException("Invalid duress verifier size");
            }
            salt = salt.clone();
            digest = digest.clone();
        }

        @Override public byte[] salt() { return salt.clone(); }
        @Override public byte[] digest() { return digest.clone(); }
    }

    record Pair(Verifier pin, Verifier password) {
        Pair {
            if (pin.type() != 3 || password.type() != 4) {
                throw new IllegalArgumentException("Invalid duress verifier types");
            }
        }
    }

    static byte[] encode(Pair pair) {
        ByteBuffer buffer = ByteBuffer.allocate(ENCODED_SIZE);
        buffer.put((byte) VERSION);
        write(buffer, pair.pin());
        write(buffer, pair.password());
        return buffer.array();
    }

    static Pair decode(byte[] encoded) {
        if (encoded == null || encoded.length != ENCODED_SIZE) {
            throw new IllegalArgumentException("Invalid duress verifier storage size");
        }
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        if (Byte.toUnsignedInt(buffer.get()) != VERSION) {
            throw new IllegalArgumentException("Unknown duress verifier storage version");
        }
        return new Pair(read(buffer), read(buffer));
    }

    private static void write(ByteBuffer buffer, Verifier verifier) {
        buffer.put((byte) verifier.type()).put((byte) verifier.logN())
                .put((byte) verifier.logR()).put((byte) verifier.logP());
        buffer.put(verifier.salt());
        buffer.put(verifier.digest());
    }

    private static Verifier read(ByteBuffer buffer) {
        int type = Byte.toUnsignedInt(buffer.get());
        int logN = Byte.toUnsignedInt(buffer.get());
        int logR = Byte.toUnsignedInt(buffer.get());
        int logP = Byte.toUnsignedInt(buffer.get());
        byte[] salt = new byte[SALT_SIZE];
        byte[] digest = new byte[DIGEST_SIZE];
        buffer.get(salt).get(digest);
        return new Verifier(type, logN, logR, logP, salt, digest);
    }
}
