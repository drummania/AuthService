package auth.entity;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Password {

    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128;

    final SecureRandom random;
    final byte[] salt;
    final byte[] hash;

    public Password(String password) {

        random = new SecureRandom();
        salt = new byte[16];
        random.nextBytes(salt);
        hash = hash(password, salt);
    }

    public byte[] getHash() {
        return hash;
    }

    public boolean match(String password) {
        return Arrays.equals(hash(password, salt), getHash());
    }

    private byte[] hash(String password, byte[] salt) {

        final char[] pw = password.toCharArray();

        final PBEKeySpec spec = new PBEKeySpec(pw, salt, ITERATIONS, KEY_LENGTH);
        Arrays.fill(pw, Character.MIN_VALUE);

        try {
            SecretKeyFactory key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return key.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }
}