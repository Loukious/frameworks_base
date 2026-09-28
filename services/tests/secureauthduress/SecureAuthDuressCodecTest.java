/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.locksettings;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Arrays;

public class SecureAuthDuressCodecTest {
    private static SecureAuthDuressCodec.Pair pair() {
        byte[] salt = new byte[16];
        byte[] digest = new byte[32];
        Arrays.fill(salt, (byte) 17);
        Arrays.fill(digest, (byte) 42);
        return new SecureAuthDuressCodec.Pair(
                new SecureAuthDuressCodec.Verifier(3, 9, 3, 1, salt, digest),
                new SecureAuthDuressCodec.Verifier(4, 9, 3, 1, salt, digest));
    }

    private static void rejects(byte[] encoded) {
        try {
            SecureAuthDuressCodec.decode(encoded);
            fail("Accepted invalid verifier storage");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void storageRoundTripRetainsNativeStretchParametersAndBothTypes() {
        SecureAuthDuressCodec.Pair source = pair();
        SecureAuthDuressCodec.Pair decoded = SecureAuthDuressCodec.decode(
                SecureAuthDuressCodec.encode(source));
        assertEquals(3, decoded.pin().type());
        assertEquals(4, decoded.password().type());
        assertEquals(9, decoded.pin().logN());
        assertEquals(3, decoded.pin().logR());
        assertEquals(1, decoded.pin().logP());
        assertArrayEquals(source.pin().salt(), decoded.pin().salt());
        assertArrayEquals(source.password().digest(), decoded.password().digest());
    }

    @Test
    public void mutableCallerBuffersCannotAlterVerifier() {
        byte[] salt = new byte[16];
        byte[] digest = new byte[32];
        SecureAuthDuressCodec.Verifier verifier =
                new SecureAuthDuressCodec.Verifier(3, 9, 3, 1, salt, digest);
        Arrays.fill(salt, (byte) 9);
        Arrays.fill(digest, (byte) 9);
        Arrays.fill(verifier.salt(), (byte) 8);
        Arrays.fill(verifier.digest(), (byte) 8);
        assertArrayEquals(new byte[16], verifier.salt());
        assertArrayEquals(new byte[32], verifier.digest());
    }

    @Test
    public void everyTruncationAndTrailingDataAreRejected() {
        byte[] encoded = SecureAuthDuressCodec.encode(pair());
        for (int length = 0; length < encoded.length; length++) {
            rejects(Arrays.copyOf(encoded, length));
        }
        rejects(Arrays.copyOf(encoded, encoded.length + 1));
        rejects(null);
    }

    @Test
    public void unknownVersionCannotBecomeDuressMatch() {
        byte[] encoded = SecureAuthDuressCodec.encode(pair());
        encoded[0] = (byte) 255;
        rejects(encoded);
    }

    @Test
    public void incorrectOrReversedCredentialTypesAreRejected() {
        byte[] encoded = SecureAuthDuressCodec.encode(pair());
        encoded[1] = 4;
        rejects(encoded);
        encoded[1] = 0;
        rejects(encoded);
        encoded = SecureAuthDuressCodec.encode(pair());
        encoded[53] = 3;
        rejects(encoded);
    }

    @Test
    public void corruptScryptCostsCannotRequestUnboundedResources() {
        for (int offset : new int[]{2, 3, 4, 54, 55, 56}) {
            byte[] encoded = SecureAuthDuressCodec.encode(pair());
            encoded[offset] = (byte) 255;
            rejects(encoded);
        }
    }

    @Test
    public void decodedVerifierDoesNotRetainMutableStorageBuffer() {
        byte[] encoded = SecureAuthDuressCodec.encode(pair());
        SecureAuthDuressCodec.Pair decoded = SecureAuthDuressCodec.decode(encoded);
        Arrays.fill(encoded, (byte) 0);
        assertArrayEquals(pair().pin().salt(), decoded.pin().salt());
        assertArrayEquals(pair().password().digest(), decoded.password().digest());
    }
}
