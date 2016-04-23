package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.junit.Test;

import static junit.framework.Assert.assertTrue;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class Argon2PasswordTest {

    private final Argon2Password password = new Argon2Password();

    @Test
    public void testPWHash(){
        String result = password.hash(ARGON2_PWHASH_MESSAGE.getBytes(),
                HEX,
                ARGON2_PWHASH_SALT.getBytes(),
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE);
        assertEquals("Hash is invalid", ARGON2_PWHASH_DIGEST, result);
    }

    @Test
    public void testPWHashEmptyString(){
        String result = password.hash("".getBytes(),
                HEX,
                ARGON2_PWHASH_SALT.getBytes(),
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE);
        assertEquals("Hash is invalid", ARGON2_PWHASH_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testPWHashNullByte() {
        try {
            password.hash("\0".getBytes(),
                    HEX,
                    ARGON2_PWHASH_SALT.getBytes(),
                    NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
                    NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE);
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testPWHashStorage(){
        String result = password.hash(ARGON2_PWHASH_MESSAGE.getBytes(),
                HEX,
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE);
        byte[] hashed = HEX.decode(result);

        // Must return true
        boolean verified1 = password.verify(hashed, ARGON2_PWHASH_MESSAGE.getBytes());
        assertTrue("Invalid password", verified1);

        // Must return false since it's an invalid
        boolean verified2 = password.verify(hashed, ("i" + ARGON2_PWHASH_MESSAGE).getBytes());
        assertTrue("Valid password", !verified2);
    }

    @Test
    public void testPWHashKeyDerivation() {
        String result = password.hash(NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES,
                ARGON2_PWHASH_MESSAGE.getBytes(),
                HEX,
                ARGON2_PWHASH_SALT.getBytes(),
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE);
        byte[] hashed = HEX.decode(result);

        // Must receive expected size
        assertEquals(NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES, hashed.length);
    }
}
