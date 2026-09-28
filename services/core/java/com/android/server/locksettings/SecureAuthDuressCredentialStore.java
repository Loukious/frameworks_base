/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.locksettings;

import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PASSWORD;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN;
import static com.android.internal.widget.LockPatternUtils.PIN_LENGTH_UNAVAILABLE;

import android.os.UserHandle;

import com.android.internal.util.ArrayUtils;
import com.android.internal.widget.LockscreenCredential;
import com.android.server.locksettings.SyntheticPasswordManager.PasswordData;

import java.security.MessageDigest;

import libcore.util.HexEncoding;

/** GrapheneOS-inspired stretching for dedicated duress secrets, without a normal-PIN oracle. */
final class SecureAuthDuressCredentialStore {
    private static final String STORAGE_KEY = "secure_auth_duress_verifiers_v1";
    private static final String RESERVATION_KEY = "secure_auth_duress_reservation_v1";
    private static final int ENCODED_HEX_LENGTH = 210;
    private final LockSettingsStorage mStorage;
    private final SyntheticPasswordManager mSpManager;

    SecureAuthDuressCredentialStore(LockSettingsStorage storage,
            SyntheticPasswordManager spManager) {
        mStorage = storage;
        mSpManager = spManager;
    }

    // The trusted service must freshly verify the owner before calling mutation or disclosure.
    String prepareEnrollment(LockscreenCredential pin, LockscreenCredential password) {
        if (pin.isNone() && password.isNone()) {
            return null;
        }
        validate(pin, CREDENTIAL_TYPE_PIN);
        validate(password, CREDENTIAL_TYPE_PASSWORD);
        SecureAuthDuressCodec.Pair pair = new SecureAuthDuressCodec.Pair(
                create(pin), create(password));
        return HexEncoding.encodeToString(SecureAuthDuressCodec.encode(pair));
    }

    void commitEnrollment(String encoded, java.util.List<SecureAuthDuressReservation.Identity> certified) {
        if (encoded == null) {
            mStorage.removeKey(RESERVATION_KEY, UserHandle.USER_SYSTEM);
        } else {
            SecureAuthDuressReservation receipt = SecureAuthDuressReservation.certify(
                    HexEncoding.decode(encoded), certified);
            mStorage.setString(RESERVATION_KEY,
                    HexEncoding.encodeToString(receipt.encode()), UserHandle.USER_SYSTEM);
        }
        if (encoded == null) {
            mStorage.removeKey(STORAGE_KEY, UserHandle.USER_SYSTEM);
        } else {
            mStorage.setString(STORAGE_KEY, encoded, UserHandle.USER_SYSTEM);
        }
    }

    boolean reservationCovers(java.util.List<SecureAuthDuressReservation.Identity> current) {
        String encoded = mStorage.getString(STORAGE_KEY, null, UserHandle.USER_SYSTEM);
        String receipt = mStorage.getString(RESERVATION_KEY, null, UserHandle.USER_SYSTEM);
        if (encoded == null || encoded.length() != ENCODED_HEX_LENGTH || receipt == null
                || receipt.length() < 100 || receipt.length() > 196) return false;
        try {
            return SecureAuthDuressReservation.decode(HexEncoding.decode(receipt))
                    .covers(HexEncoding.decode(encoded), current);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }

    void refreshReservation(java.util.List<SecureAuthDuressReservation.Identity> current) {
        String encoded = mStorage.getString(STORAGE_KEY, null, UserHandle.USER_SYSTEM);
        if (encoded == null) return;
        if (current.isEmpty() || current.size() > 4) {
            mStorage.removeKey(RESERVATION_KEY, UserHandle.USER_SYSTEM);
            return;
        }
        SecureAuthDuressReservation receipt = SecureAuthDuressReservation.certify(
                HexEncoding.decode(encoded), current);
        mStorage.setString(RESERVATION_KEY,
                HexEncoding.encodeToString(receipt.encode()), UserHandle.USER_SYSTEM);
    }

    boolean isConfigured() {
        // Protected status must still permit removal of an invalid stored record.
        return mStorage.getString(STORAGE_KEY, null, UserHandle.USER_SYSTEM) != null;
    }

    /** Caller must first establish a fresh, complete native normal-credential rejection. */
    boolean matchesAfterNormalRejection(LockscreenCredential input) {
        if ((!input.isPin() && !input.isPassword()) || input.hasInvalidChars()) return false;
        SecureAuthDuressCodec.Pair pair = load();
        if (pair == null) return false;
        return matches(pair.pin(), input) || matches(pair.password(), input);
    }

    private SecureAuthDuressCodec.Pair load() {
        String encoded = mStorage.getString(STORAGE_KEY, null, UserHandle.USER_SYSTEM);
        if (encoded == null) return null;
        if (encoded.length() != ENCODED_HEX_LENGTH) {
            throw new IllegalStateException("Invalid duress verifier storage");
        }
        return SecureAuthDuressCodec.decode(HexEncoding.decode(encoded));
    }

    private SecureAuthDuressCodec.Verifier create(LockscreenCredential credential) {
        PasswordData data = PasswordData.create(credential.getType(), PIN_LENGTH_UNAVAILABLE);
        byte[] stretched = mSpManager.stretchLskf(credential, data);
        try {
            return new SecureAuthDuressCodec.Verifier(data.credentialType, data.scryptLogN,
                    data.scryptLogR, data.scryptLogP, data.salt, stretched);
        } finally {
            ArrayUtils.zeroize(stretched);
        }
    }

    private boolean matches(SecureAuthDuressCodec.Verifier verifier, LockscreenCredential input) {
        PasswordData data = new PasswordData();
        data.credentialType = verifier.type();
        data.scryptLogN = (byte) verifier.logN();
        data.scryptLogR = (byte) verifier.logR();
        data.scryptLogP = (byte) verifier.logP();
        data.salt = verifier.salt();
        data.pinLength = PIN_LENGTH_UNAVAILABLE;
        try (LockscreenCredential copy =
                input.duplicateForSecureSpaceVerification(data.credentialType)) {
            if (copy == null) return false;
            byte[] stretched = mSpManager.stretchLskf(copy, data);
            byte[] expected = verifier.digest();
            try {
                return MessageDigest.isEqual(expected, stretched);
            } finally {
                ArrayUtils.zeroize(stretched);
                ArrayUtils.zeroize(expected);
            }
        }
    }

    private static void validate(LockscreenCredential credential, int expectedType) {
        if (credential.getType() != expectedType || credential.isUnifiedProfilePassword()) {
            throw new IllegalArgumentException("Incorrect duress credential type");
        }
        credential.validateBasicRequirements();
        if (expectedType == CREDENTIAL_TYPE_PIN) {
            for (byte digit : credential.getCredential()) {
                if (digit < '0' || digit > '9') {
                    throw new IllegalArgumentException("Duress PIN must contain digits");
                }
            }
        }
    }
}
