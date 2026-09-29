package com.android.server.biometrics.sensors.fingerprint;
import static org.junit.Assert.*;
import java.util.List;
import org.junit.Test;

public class SecureSpaceFingerprintPolicyTest {
    @Test public void highBitNativeIdRetainsAuthenticationAndOwnershipChecks() {
        int id = 0x92000001;
        var space = template(id, 10, 50, true, true, true);
        assertEquals(space, SecureSpaceFingerprintPolicy.resolve(List.of(space), id, 50, 0, true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(List.of(space), id, 50, 0, false));
        assertNull(SecureSpaceFingerprintPolicy.resolve(List.of(space), id, 51, 0, true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(space, template(id, 0, 55, true, true, true)), id, 50, 0, true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(id,10,50,true,false,true)), id,50,0,true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(id,10,50,true,true,false)), id,50,0,true));
    }
    @Test public void zeroNativeTemplateIdFailsClosed() {
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(0,10,50,true,true,true)), 0,50,0,true));
    }
    private SecureSpaceFingerprintPolicy.Template template(int id, int uid, long sid,
            boolean current, boolean unlocked, boolean allowed) {
        return new SecureSpaceFingerprintPolicy.Template(id, uid, uid + 1, sid,
                current, unlocked, allowed);
    }
    @Test public void appCannotUseForeignFingerEvenWithValidHardwareToken() {
        var space = template(7, 10, 50, true, true, true);
        assertNull(SecureSpaceFingerprintPolicy.resolve(List.of(space), 7, 50, 0, false));
        assertEquals(space, SecureSpaceFingerprintPolicy.resolve(List.of(space), 7, 50, 10, false));
    }
    @Test public void keyguardCanRouteOnlyWarmStrongAuthEligibleDestination() {
        var space = template(7, 10, 50, true, true, true);
        assertEquals(space, SecureSpaceFingerprintPolicy.resolve(List.of(space), 7, 50, 0, true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(7,10,50,true,false,true)), 7,50,0,true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(7,10,50,true,true,false)), 7,50,0,true));
    }
    @Test public void keyguardIdentificationFindsLockedOwnerWithoutAuthenticatingIt() {
        var locked = template(7, 10, 50, true, false, false);
        assertEquals(locked, SecureSpaceFingerprintPolicy.identify(List.of(locked), 7, 50));
        assertNull(SecureSpaceFingerprintPolicy.resolve(List.of(locked), 7, 50, 0, true));
    }
    @Test public void identificationStillRejectsStaleAmbiguousOrWrongSidOwnership() {
        var locked = template(7, 10, 50, true, false, false);
        assertNull(SecureSpaceFingerprintPolicy.identify(List.of(locked), 7, 51));
        assertNull(SecureSpaceFingerprintPolicy.identify(
                List.of(template(7,10,50,false,false,false)), 7, 50));
        assertNull(SecureSpaceFingerprintPolicy.identify(
                List.of(locked, template(7,0,55,true,true,true)), 7, 50));
    }
    @Test public void tokenSidCannotBeRelabelledToMetadataUser() {
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(7,10,50,true,true,true)), 7,51,0,true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(7,10,50,true,true,true)), 7,0,0,true));
    }
    @Test public void staleOrAmbiguousOwnershipFailsClosed() {
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(7,10,50,false,true,true)), 7,50,0,true));
        assertNull(SecureSpaceFingerprintPolicy.resolve(
                List.of(template(7,10,50,true,true,true), template(7,0,55,true,true,true)),
                7,50,0,true));
    }
}
