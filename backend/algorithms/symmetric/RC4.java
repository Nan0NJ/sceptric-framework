/**
 *      Check with mentor:
 *      Should RC4 be counted in one of the algorithms?
 *      Small biases may allow recovery of the plaintext without needing the key.
 */

package backend.algorithms.symmetric;
import backend.services.CryptographicAlgorithm;

//              Uses Java's standard cryptographic libraries for security and performance.
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 *      RC4 (Rivest Cipher 4) implementation.
 *      Stream cipher,
 *      Varying Key size 40-2048 bits.
 */
public class RC4 implements CryptographicAlgorithm {

    /**
     *      Constructs of RC4 instance.
     *      Varying key size (40-2048).
     */
    private final Cipher cipher;
    private final SecretKey key;

    public RC4(int keySize) throws Exception {
        if (keySize < 40 || keySize > 2048 || keySize % 8 != 0) {
            throw new IllegalArgumentException("Invalid key size. RC4 supports key sizes from 40 to 2048 bits in multiples of 8.");
        }

        this.cipher = Cipher.getInstance("RC4");
        this.key = generateKey(keySize);
    }

    private SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
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

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
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

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     *      Returns the name of the IDEA algorithm being used.
     *      @return Algorithm name in the format "IDEA-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "RC4";
    }
}
