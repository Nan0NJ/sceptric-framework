/**
 *      Check with mentor:
 *      Current Limitation:
 *      Only generates random keys internally, so no way to provide an existing key.
 *      DISCUSS WITH THIS:
 *          - Should I make SecretKey reusable, yet it is not intended to check that part?
 *          If so then later... (for me)
 *          -  Add a constructor to accept a SecretKey for key reuse.
 *          -  Instead of Reusing IV, to make it fresh with every encryption.
 */

package backend.algorithms.symmetric;
import backend.services.CryptographicAlgorithm;

//              Uses Java's standard cryptographic libraries for security and performance.
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *      AES implementation.
 *      Allows switching between ECB, CBC, and GCM modes,
 *      Modification of key sizes of 128, 192, and 256 bits.
 */
public class AES implements CryptographicAlgorithm {

    /**
     *      Constructs of AES instance with the specified mode, padding, and key size.
     *      The AES mode (ECB, CBC, GCM)
     *      The padding scheme (PKCS5Padding, NoPadding)
     *      The key size in bits (128, 192, or 256)
     */
    private final Cipher cipher;
    private final SecretKey key;
    private final String mode;
    private final String padding;
    private byte[] iv;

    public AES(String mode, String padding, int keySize) throws Exception {
        this.mode = mode;
        this.padding = padding;

        String transformation = mode.equals("GCM") ? "AES/GCM/NoPadding" : "AES/" + mode + "/" + padding;
        this.cipher = Cipher.getInstance(transformation);
        this.key = generateKey(keySize);

        if (!mode.equals("ECB")) {
            this.iv = new byte[mode.equals("GCM") ? 12 : 16];
            new SecureRandom().nextBytes(this.iv);
        }
    }

    /**
     *      Generates a random AES key of the specified size.
     *      @param keySize The key size in bits (128, 192, 256)
     *      @return A randomly generated AES key
     *      @throws Exception If key generation fails
     */
    private SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    /**
     *      Encrypts the given plaintext using AES.
     *      @param plainText The input text to be encrypted
     *      @return The encrypted output as a Base64-encoded string
     *      @throws Exception If encryption fails
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) throw new IllegalArgumentException("Plaintext cannot be null");

        byte[] inputBytes = plainText.getBytes(StandardCharsets.UTF_8);

        if (mode.equals("GCM")) {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        } else if (mode.equals("CBC")) {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        } else { // ECB
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        byte[] encrypted = cipher.doFinal(inputBytes);

        if (!mode.equals("ECB")) {
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(combined);
        }
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     *      Decrypts the given Base64-encoded ciphertext using AES.
     *      @param cipherText The encrypted text to be decrypted
     *      @return The decrypted output as a String
     *      @throws Exception If decryption fails
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) throw new IllegalArgumentException("Ciphertext cannot be null");

        byte[] decoded = Base64.getDecoder().decode(cipherText);

        if (!mode.equals("ECB")) {
            int ivLength = mode.equals("GCM") ? 12 : 16;
            if (decoded.length < ivLength) {
                throw new IllegalArgumentException("Invalid ciphertext: too short");
            }
            iv = new byte[ivLength];
            System.arraycopy(decoded, 0, iv, 0, ivLength);

            byte[] encrypted = new byte[decoded.length - ivLength];
            System.arraycopy(decoded, ivLength, encrypted, 0, encrypted.length);

            if (mode.equals("GCM")) {
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            } else { // CBC
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            }
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
        }
    }

    /**
     *      Returns the name of the AES algorithm being used.
     *      @return Algorithm name in the format "AES-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "AES-" + mode + "-" + padding;
    }
}