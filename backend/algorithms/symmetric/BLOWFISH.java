/**
 *      Check with mentor:
 *      Current Limitation:
 *      Only generates random keys internally, so no way to provide an existing key.
 *      DISCUSS WITH THIS:
 *          - Should I make SecretKey reusable, yet it is not intended to check that part?
 *          - Should I check all modes ? Just to have them?
 *          - For performance testing, should I only check with padding? Because better analysis.
 *          If so then later... (for me)
 *          -  Add a constructor to accept a SecretKey for key reuse.
 */


package backend.algorithms.symmetric;
import backend.services.CryptographicAlgorithm;

//              Uses Java's standard cryptographic libraries for security and performance.
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *      Blowfish implementation.
 *      Allows switching between ECB, CBC, CFB, OFB, and CTR modes,
 *      The key sizes ranging from 32 to 448 bits.
 */
public class BLOWFISH implements CryptographicAlgorithm {

    /**
     *      Constructs of Blowfish instance with the specified mode, padding, and key size.
     *      The Blowfish mode (ECB, CBC, CFB, OFB, CTR)
     *      The padding scheme (PKCS5Padding, NoPadding)
     *      The key size in bits (32 - 448)
     */
    private final Cipher cipher;
    private final SecretKey key;
    private final String mode;
    private final String padding;
    private byte[] iv;

    public BLOWFISH(String mode, String padding, int keySize) throws Exception {
        this.mode = mode;
        this.padding = padding;

        String transformation;
        if (mode.equals("CTR") || mode.equals("OFB")) {
            transformation = "Blowfish/" + mode + "/NoPadding";
        } else {
            transformation = "Blowfish/" + mode + "/" + padding;
        }

        this.cipher = Cipher.getInstance(transformation);
        this.key = generateKey(keySize);

        if (!mode.equals("ECB")) {
            this.iv = new byte[8]; // Fixed 8-byte IVs
            new SecureRandom().nextBytes(this.iv);
        }
    }

    private SecretKey generateKey(int keySize) throws Exception {
        if (keySize < 32 || keySize > 448 || keySize % 8 != 0) {
            throw new IllegalArgumentException("Invalid key size. Blowfish supports key sizes from 32 to 448 bits in multiples of 8.");
        }
        KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    /**
     *      Encrypts the given plaintext using DES.
     *      @param plainText The input text to be encrypted
     *      @return The encrypted output as a Base64-encoded string
     *      @throws Exception If encryption fails
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) throw new IllegalArgumentException("Plaintext cannot be null");

        byte[] inputBytes = plainText.getBytes(StandardCharsets.UTF_8);

        if (padding.equals("NoPadding") && (mode.equals("ECB") || mode.equals("CBC"))) {
            int blockSize = 8;
            if (inputBytes.length % blockSize != 0) {
                throw new IllegalArgumentException(
                        "Input length must be a multiple of " + blockSize + " bytes for " + mode + "/NoPadding; got " + inputBytes.length + " bytes"
                );
            }
        }

        if (!mode.equals("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        } else {
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
            int ivLength = 8;
            if (decoded.length < ivLength) {
                throw new IllegalArgumentException("Invalid ciphertext: too short");
            }
            iv = new byte[ivLength];
            System.arraycopy(decoded, 0, iv, 0, ivLength);

            byte[] encrypted = new byte[decoded.length - ivLength];
            System.arraycopy(decoded, ivLength, encrypted, 0, encrypted.length);

            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
        }
    }

    /**
     *      Returns the name of the AES algorithm being used.
     *      @return Algorithm name in the format "DES-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "Blowfish-" + mode + "-" + padding;
    }
}
