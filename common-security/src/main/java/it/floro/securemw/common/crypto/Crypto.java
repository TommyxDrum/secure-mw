package it.floro.securemw.common.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

public class Crypto {

    public static final int GCM_TAG_BITS = 128;    // tag GCM = 16 byte
    public static final int GCM_IV_LEN   = 12;     // iv raccomandato = 12 byte

    private final SecretKey aesKey;
    private final SecretKey hmacKey;
    private final SecureRandom rng = new SecureRandom();

    /**
     * @param aesKeyB64  chiave AES (32 byte → 256 bit) codificata Base64
     * @param hmacKeyB64 chiave HMAC (32 byte) codificata Base64
     */
    public Crypto(String aesKeyB64, String hmacKeyB64) {
        byte[] aes = Base64.getDecoder().decode(Objects.requireNonNull(aesKeyB64, "aesKeyB64 null"));
        byte[] hmk = Base64.getDecoder().decode(Objects.requireNonNull(hmacKeyB64, "hmacKeyB64 null"));

        if (aes.length != 32) {
            throw new IllegalArgumentException("AES key must be 32 bytes (256-bit). Got: " + aes.length);
        }
        if (hmk.length < 16) {
            throw new IllegalArgumentException("HMAC key should be >= 16 bytes. Got: " + hmk.length);
        }

        this.aesKey  = new SecretKeySpec(aes, "AES");
        this.hmacKey = new SecretKeySpec(hmk, "HmacSHA256");
    }

    //HMAC

    // Calcola HMAC-SHA256 su data.
    public byte[] sign(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("HMAC sign error", e);
        }
    }

    //Verifica HMAC-SHA256; solleva eccezione se non coincide.
    public void verifyHmac(byte[] data, byte[] expectedSig) {
        byte[] actual = sign(data);
        if (!constantTimeEquals(actual, expectedSig)) {
            throw new IllegalStateException("Bad signature");
        }
    }

    //AES

    // Genera un IV casuale da 12 byte (raccomandazione NIST per GCM).
    public byte[] newIv() {
        byte[] iv = new byte[GCM_IV_LEN];
        rng.nextBytes(iv);
        return iv;
    }

    //Cifra con IV casuale; ritorna iv + ciphertext in un contenitore.
    public EncResult encrypt(byte[] plaintext) {
        byte[] iv = newIv();
        byte[] ct = encrypt(iv, plaintext);
        return new EncResult(iv, ct);
    }

    // Cifra con IV fornito (12 byte).
    public byte[] encrypt(byte[] iv, byte[] plaintext) {
        try {
            if (iv == null || iv.length != GCM_IV_LEN) {
                throw new IllegalArgumentException("IV must be 12 bytes for GCM");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("AES-GCM encrypt error", e);
        }
    }

    // Decifra (richiede IV usato in cifratura e il ciphertext completo di tag GCM).
    public byte[] decrypt(byte[] iv, byte[] ciphertext) {
        try {
            if (iv == null || iv.length != GCM_IV_LEN) {
                throw new IllegalArgumentException("IV must be 12 bytes for GCM");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("AES-GCM decrypt error", e);
        }
    }

    //Utility

    public static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        int res = 0;
        for (int i = 0; i < a.length; i++) res |= (a[i] ^ b[i]);
        return res == 0;
    }

    /** Contenitore risultato cifratura (iv + ciphertext). */
    public record EncResult(byte[] iv, byte[] ciphertext) {}

    public Map<String, String> encryptAndSign(byte[] plaintext) {
        EncResult enc = encrypt(plaintext);                 // AES-GCM
        byte[] iv = enc.iv();
        byte[] ct = enc.ciphertext();

        // HMAC su (iv || ciphertext)
        byte[] msgForMac = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, msgForMac, 0, iv.length);
        System.arraycopy(ct, 0, msgForMac, iv.length, ct.length);
        byte[] sig = sign(msgForMac);

        return Map.of(
                "iv",        b64(iv),
                "ciphertext", b64(ct),
                "sig",       b64(sig)
        );
    }
        public Map<String,String> encryptAndSign(String plaintextUtf8) {
            return encryptAndSign(plaintextUtf8.getBytes(StandardCharsets.UTF_8));
        }
}

