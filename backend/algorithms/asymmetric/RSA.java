package backend.algorithms.asymmetric;
import backend.services.CryptographicAlgorithm;
//              Uses Java's standard cryptographic libraries for security and performance.
//              + Additional Bouncy Castle JCA (since IDEA is not supported in JCE)
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 *      RSA (Rivest-Shamir-Adleman) implementation using Bouncy Castle.
 *      Varying key sizes (1024, 2048, 4096 bits).
 */
public class RSA implements CryptographicAlgorithm {

    /**
     *      Constructs of RSA instance with the specified padding, and key size.
     *      The padding scheme (PKCS1Padding, and NoPadding)
     *      Varying key size (1024, 2048, 4096).
     */
    private final Cipher cipher;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final String padding;
    private final int keySize;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public RSA(String padding, int keySize) throws Exception {
        if (keySize < 1024 || keySize > 4096 || keySize % 1024 != 0) {
            throw new IllegalArgumentException("Invalid key size. RSA supports 1024, 2048, or 4096 bits.");
        }
        this.padding = padding;
        this.keySize = keySize;

        String transformation = "RSA/ECB/" + padding;
        this.cipher = Cipher.getInstance(transformation, "BC");

        KeyPair keyPair = generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     *      Encrypts the given plaintext using RC6.
     *      @param plainText The input text to be encrypted
     *      @return The encrypted output as a Base64-encoded string
     *      @throws Exception If encryption fails
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) throw new IllegalArgumentException("Plaintext cannot be null");

        // Adjust block size for PKCS1Padding (11-byte overhead) or NoPadding (full block size)
        int paddingOverhead = padding.equals("PKCS1Padding") ? 11 : 0;
        int maxBlockSize = (keySize / 8) - paddingOverhead;

        byte[] inputBytes = plainText.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt in chunks
        for (int i = 0; i < inputBytes.length; i += maxBlockSize) {
            int length = Math.min(inputBytes.length - i, maxBlockSize);
            byte[] encryptedBlock = cipher.doFinal(inputBytes, i, length);
            outputStream.write(encryptedBlock);
        }

        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }


    /**
     *      Decrypts the given Base64-encoded ciphertext using RC6.
     *      @param cipherText The encrypted text to be decrypted
     *      @return The decrypted output as a String
     *      @throws Exception If decryption fails
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) throw new IllegalArgumentException("Ciphertext cannot be null");

        byte[] encryptedBytes = Base64.getDecoder().decode(cipherText);
        int blockSize = keySize / 8; // RSA block size

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decrypt in chunks
        for (int i = 0; i < encryptedBytes.length; i += blockSize) {
            int length = Math.min(encryptedBytes.length - i, blockSize);
            byte[] decryptedBlock = cipher.doFinal(encryptedBytes, i, length);
            outputStream.write(decryptedBlock);
        }

        return new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
    }


    /**
     *      Returns the name of the RC6 algorithm being used.
     *      @return Algorithm name in the format "IDEA-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "RSA-" + padding + "-" + keySize + " bits";
    }
}