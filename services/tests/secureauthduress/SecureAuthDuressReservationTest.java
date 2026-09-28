package com.android.server.locksettings;

import static org.junit.Assert.*;
import java.util.List;
import org.junit.Test;

public class SecureAuthDuressReservationTest {
    private final byte[] pair = new byte[]{1,2,3};
    private final SecureAuthDuressReservation.Identity owner =
            new SecureAuthDuressReservation.Identity(0, 1, -25);
    private final SecureAuthDuressReservation.Identity space =
            new SecureAuthDuressReservation.Identity(10, 2, 35);
    @Test public void roundTripCoversExactNativeNamespace() {
        var receipt = SecureAuthDuressReservation.certify(pair, List.of(owner, space));
        assertTrue(SecureAuthDuressReservation.decode(receipt.encode()).covers(pair, List.of(owner, space)));
    }
    @Test public void removedUserDoesNotInvalidateRemainingReservation() {
        var receipt = SecureAuthDuressReservation.certify(pair, List.of(owner, space));
        assertTrue(receipt.covers(pair, List.of(owner)));
    }
    @Test public void changedSerialOrProtectorCannotReuseReservation() {
        var receipt = SecureAuthDuressReservation.certify(pair, List.of(owner, space));
        assertFalse(receipt.covers(pair, List.of(owner,
                new SecureAuthDuressReservation.Identity(10, 3, 35))));
        assertFalse(receipt.covers(pair, List.of(owner,
                new SecureAuthDuressReservation.Identity(10, 2, 36))));
    }
    @Test public void newNativeUserIsNotCertified() {
        var receipt = SecureAuthDuressReservation.certify(pair, List.of(owner));
        assertFalse(receipt.covers(pair, List.of(owner, space)));
    }
    @Test public void changedDuressPairIsNotCertified() {
        var receipt = SecureAuthDuressReservation.certify(pair, List.of(owner));
        assertFalse(receipt.covers(new byte[]{1,2,4}, List.of(owner)));
    }
    @Test public void malformedVersionLengthAndCountFailClosed() {
        var bytes = SecureAuthDuressReservation.certify(pair, List.of(owner)).encode();
        for (int length = 0; length < bytes.length; length++) {
            byte[] shortBytes = java.util.Arrays.copyOf(bytes, length);
            assertThrows(IllegalArgumentException.class, () -> SecureAuthDuressReservation.decode(shortBytes));
        }
        byte[] trailing = java.util.Arrays.copyOf(bytes, bytes.length + 1);
        assertThrows(IllegalArgumentException.class, () -> SecureAuthDuressReservation.decode(trailing));
        bytes[0] = 2;
        assertThrows(IllegalArgumentException.class, () -> SecureAuthDuressReservation.decode(bytes));
    }
    @Test public void repeatedOrUnorderedNativeIdentityRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                SecureAuthDuressReservation.certify(pair, List.of(owner, owner)));
        assertThrows(IllegalArgumentException.class, () ->
                SecureAuthDuressReservation.certify(pair, List.of(space, owner)));
    }
    @Test public void decodedReservationRejectsZeroProtector() {
        byte[] bytes = SecureAuthDuressReservation.certify(pair, List.of(owner)).encode();
        java.util.Arrays.fill(bytes, 42, 50, (byte) 0);
        assertThrows(IllegalArgumentException.class, () -> SecureAuthDuressReservation.decode(bytes));
    }
}
