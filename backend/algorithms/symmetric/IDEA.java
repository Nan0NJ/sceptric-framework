/**
 *      Check with mentor:
 *      Is IDEA okey to use since patent is expired?
 *      Is my implementation with Bouncy Castle good enough? If not what to fix?
 *      Talk About NoPadding and if its necessary for testing ?
 */

package backend.algorithms.symmetric;
import backend.services.CryptographicAlgorithm;
//              Uses Java's standard cryptographic libraries for security and performance.
//              + Additional Bouncy Castle JCA (since IDEA is not supported in JCE)
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 *      IDEA (International Data Encryption Algorithm) implementation using Bouncy Castle.
 *      Allows switching  between ECB, CBC, CFB, OFB, and CTR modes,
 *      Fixed key size of 128 bits.
 */
public class IDEA implements CryptographicAlgorithm {

    /**
     *      Constructs of IDEA instance with the specified mode, padding, and key size.
     *      The IDEA mode (ECB, CBC, CFB, OFB, CTR)
     *      The padding scheme (PKCS5Padding, NoPadding)
     *      Fixed key size (56)
     */
    private final Cipher cipher;
    private final SecretKey key;
    private final String mode;
    private final String padding;
    private byte[] iv;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public IDEA(String mode, String padding) throws Exception {
        this.mode = mode;
        this.padding = padding;

        String transformation = "IDEA/" + mode + "/" + padding;
        this.cipher = Cipher.getInstance(transformation, "BC");
        this.key = generateKey();

        if (!mode.equals("ECB")) {
            this.iv = new byte[8]; // Fixed 8-byte IVs
            new SecureRandom().nextBytes(this.iv);
        }
    }

    private SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("IDEA", "BC");
        keyGen.init(128); // Fixed 128-bit key size
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

        if (!mode.equals("ECB")) {
            iv = new byte[8]; // Generate fresh IV for each encryption
            new SecureRandom().nextBytes(iv);
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
     *      Decrypts the given Base64-encoded ciphertext using IDEA.
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
     *      Returns the name of the IDEA algorithm being used.
     *      @return Algorithm name in the format "IDEA-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "IDEA-" + mode + "-" + padding;
    }
}