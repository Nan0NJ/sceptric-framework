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
 *      RC5 (Rivest Cipher 5) implementation.
 *      Block cipher,
 *      Supports ECB, CBC, CFB, and CTR modes.
 *      Varying Key size 32-2048 bits,
 *      Varying rounds.
 */
public class RC5 implements CryptographicAlgorithm {

    /**
     *      Constructs of RC5 instance with the specified mode, padding, key size, and number of rounds.
     *      The RC5 mode (ECB, CBC, CFB, CTR)
     *      The padding scheme (PKCS5Padding, NoPadding)
     *      Varying key size (32-2048)
     *      Varying rounds (1-255)
     */
    private final Cipher cipher;
    private final SecretKey key;
    private final String mode;
    private final String padding;
    private final int rounds;
    private byte[] iv;

    public RC5(String mode, String padding, int keySize, int rounds) throws Exception {
        if (keySize < 32 || keySize > 2048 || keySize % 8 != 0) {
            throw new IllegalArgumentException("Invalid key size. RC5 supports key sizes from 32 to 2048 bits in multiples of 8.");
        }
        if (rounds < 1 || rounds > 255) {
            throw new IllegalArgumentException("Invalid round count. RC5 supports between 1 and 255 rounds.");
        }

        this.mode = mode;
        this.padding = padding;
        this.rounds = rounds;

        String transformation = "RC5/" + mode + "/" + padding;
        this.cipher = Cipher.getInstance(transformation);
        this.key = generateKey(keySize);

        if (!mode.equals("ECB")) {
            this.iv = new byte[8]; // Fixed 8-byte IV
            new SecureRandom().nextBytes(this.iv);
        }
    }

    private SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("RC5");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    /**
     *      Encrypts the given plaintext using IDEA.
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

        if (mode.equals("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
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
     *      Decrypts the given Base64-encoded ciphertext using IDEA.
     *      @param cipherText The encrypted text to be decrypted
     *      @return The decrypted output as a String
     *      @throws Exception If decryption fails
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) throw new IllegalArgumentException("Ciphertext cannot be null");

        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] encryptedBytes;

        if (!mode.equals("ECB")) {
            int ivLength = 8;
            if (decoded.length < ivLength) {
                throw new IllegalArgumentException("Invalid ciphertext: too short");
            }
            iv = new byte[ivLength];
            System.arraycopy(decoded, 0, iv, 0, ivLength);
            encryptedBytes = new byte[decoded.length - ivLength];
            System.arraycopy(decoded, ivLength, encryptedBytes, 0, encryptedBytes.length);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } else {
            encryptedBytes = decoded;
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     *      Returns the name of the IDEA algorithm being used.
     *      @return Algorithm name in the format "IDEA-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "RC5-" + mode + "-" + padding + "-" + rounds + "Rounds";
    }
}