package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;

public class Argon2Password {

    public Argon2Password() {
    }

    public String hash(byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        return hash(CRYPTO_PWHASH_ARGON2I_OUTBYTES, passwd, encoder, salt, opslimit, memlimit);
    }

    public String hash(int length, byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        byte[] buffer = new byte[length];
        sodium().crypto_pwhash_argon2i(buffer, buffer.length, passwd, passwd.length, salt, opslimit, memlimit, CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13);
        return encoder.encode(buffer);
    }

    public String hash(byte[] passwd, Encoder encoder, int opslimit, long memlimit) {
        byte[] buffer = new byte[CRYPTO_PWHASH_ARGON2I_STRBYTES];
        sodium().crypto_pwhash_argon2i_str(buffer, passwd, passwd.length, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public boolean verify(byte[] hashed_passwd, byte[] passwd) {
        int result = sodium().crypto_pwhash_argon2i_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }
}