package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/**
 *      Secure Authenticated Messaging (SAM) Protocol.
 *      Combines DSA for digital signatures with AES for encryption to ensure authenticity and confidentiality.
 *      Generates its own AES key internally by default.
 */
public class SAM implements CryptographicAlgorithm {
    /**
     *      Constructs of SAM protocol instance with the using DSA and AES.
     */
    private final DSA dsa;                    // DSA instance for signing/verification
    private final SecretKeySpec aesKey;       // AES key for encryption (generated internally or provided)
    private final int keySize;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *      Default constructor: Generates a random 16-byte AES-128 key internally.
     */
    public SAM(int dsaKeySize) throws Exception {
        this(dsaKeySize, generateRandomAESKey(16)); // Default to AES-128
    }

    /**
     *      Constructor with external AES key: Allows passing a pre-shared key.
     */
    public SAM(int dsaKeySize, byte[] aesKeyBytes) throws Exception {
        if (dsaKeySize != 1024 && dsaKeySize != 2048 && dsaKeySize != 3072) {
            throw new IllegalArgumentException("Invalid DSA key size. SAM supports 1024, 2048, or 3072 bits.");
        }
        this.keySize = dsaKeySize;
        this.dsa = new DSA(dsaKeySize);

        // Validate AES key length (16, 24, or 32 bytes for AES-128, AES-192, or AES-256 as it should.)
        if (aesKeyBytes.length != 16 && aesKeyBytes.length != 24 && aesKeyBytes.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes.");
        }
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");
    }

    ///     Generates a random AES key of the specified length.
    private static byte[] generateRandomAESKey(int length) {
        byte[] keyBytes = new byte[length];
        new SecureRandom().nextBytes(keyBytes);
        return keyBytes;
    }

    /**
     *      Encrypts and signs a plaintext message.
     *      Format: Base64(IV + Ciphertext) + ":" + Base64(Signature)
     *      @param plainText The plaintext message to encrypt.
     *      @return A Base64-encoded string containing the encrypted data and signature.
     *      @throws Exception If encryption or signing fails.
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encrypted = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        String signature = dsa.sign(plainText);

        byte[] encryptedBytes = Arrays.copyOf(iv, iv.length + encrypted.length);
        System.arraycopy(encrypted, 0, encryptedBytes, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedBytes) + ":" + signature;
    }

    /**
     *      Decrypts and verifies a ciphertext.
     *      Expects format: Base64(IV + Ciphertext) + ":" + Base64(Signature)
     *      @param cipherText The encrypted and signed message.
     *      @return The decrypted plaintext if the signature is valid.
     *      @throws Exception If decryption or verification fails.
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        // Split the ciphertext and signature
        String[] parts = cipherText.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid SAM ciphertext format.");
        }
        String encryptedData = parts[0];
        String signature = parts[1];

        // Decode and extract IV and ciphertext
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] iv = Arrays.copyOfRange(decoded, 0, 16);
        byte[] encrypted = Arrays.copyOfRange(decoded, 16, decoded.length);

        // Decrypt
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decrypted = aesCipher.doFinal(encrypted);
        String plainText = new String(decrypted, StandardCharsets.UTF_8);

        // Verify signature
        boolean isValid = dsa.verify(plainText, signature);
        if (!isValid) {
            throw new SecurityException("Signature verification failed.");
        }

        return plainText;
    }

    /**
     *      Returns the algorithm name.
     *      @return A string representation of the algorithm used.
     */
    @Override
    public String getAlgorithmName() {
        return "SAM-DSA-AES-" + keySize + " bits";
    }
}