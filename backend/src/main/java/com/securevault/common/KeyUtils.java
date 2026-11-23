package com.securevault.common;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public final class KeyUtils {
    private KeyUtils() {}

    /**
     * Decodes a base64 key, or securely expands it to 64 bytes using SHA-512 if fewer than minBytes.
     * This ensures full compatibility with cloud platforms (e.g. Render generateValue) that provision
     * 32-character random tokens while enforcing cryptographic 256/512-bit key strength.
     */
    public static byte[] decodeOrDerive(String keyStr, int minBytes) {
        if (keyStr == null || keyStr.isBlank()) {
            throw new IllegalArgumentException("Key must not be blank.");
        }
        String rawTrimmed = keyStr.trim();
        byte[] bytes;
        try {
            bytes = Decoders.BASE64.decode(rawTrimmed);
        } catch (Exception e) {
            bytes = rawTrimmed.getBytes(StandardCharsets.UTF_8);
        }
        if (bytes.length < minBytes) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                bytes = md.digest(rawTrimmed.getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException ignored) {}
        }
        return bytes;
    }

    public static SecretKey jwtSigningKey(String secretBase64) {
        byte[] keyBytes = decodeOrDerive(secretBase64, 48);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
