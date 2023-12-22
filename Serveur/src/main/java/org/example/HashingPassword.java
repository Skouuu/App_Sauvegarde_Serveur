package org.example;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Base64;

public class HashingPassword {

    public static byte[] decodeSalt(String encodedSalt) {
        return Base64.getDecoder().decode(encodedSalt);
    }

    public static SecretKey generateEncryptionKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 1000;
        char[] chars = password.toCharArray();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256); // 256 bits pour AES
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    public static String keyToString(SecretKey secretKey) {
        // Encoder la clé en utilisant Base64
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static byte[] decodeStringToBytes(String keyString) {
        return Base64.getDecoder().decode(keyString);
    }

    public static SecretKey stringToKey(String keyString, String algorithm) {
        byte[] decodedKey = decodeStringToBytes(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
    }

    public static boolean validatePassword(String originalPassword, String storedKeyString, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Générer une clé à partir du mot de passe original, du sel et des itérations
        SecretKey testKey = generateEncryptionKey(originalPassword, salt);

        // Convertir cette clé générée en chaîne de caractères
        String testKeyString = keyToString(testKey);

        // Comparer la clé générée avec la clé stockée
        return testKeyString.equals(storedKeyString);
    }
}