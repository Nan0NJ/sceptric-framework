package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/**
 *      Diffie-Hellman (DH) Key Exchange implementation using Bouncy Castle.
 *      Combines DH key exchange with AES encryption to simulate a hybrid cryptographic system -- showcasing TLS protocol.
 *      Supports key sizes of 1024, 2048, and 4096 bits.
 */
public class DH implements CryptographicAlgorithm {

    /**
     *      Constructs a DH instance with the specified key size, performing key exchange once.
     *      Varying key sizes: 1024, 2048, 4096 bits.
     */
    private final PublicKey publicKey;       /// Alice's public key
    private final PrivateKey privateKey;     /// Alice's private key
    private final PublicKey bobPublicKey;    /// Bob's public key (simulated second party)
    private final int keySize;
    private final SecretKeySpec aesKey;      /// Derived AES key from shared secret

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public DH(int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Invalid key size. DH supports 1024, 2048, or 4096 bits.");
        }
        this.keySize = keySize;

        /// Generate Alice's key pair
        KeyPair aliceKeyPair = generateKeyPair();
        this.publicKey = aliceKeyPair.getPublic();
        this.privateKey = aliceKeyPair.getPrivate();

        /// Generate Bob's key pair for simulation
        KeyPair bobKeyPair = generateKeyPair();
        this.bobPublicKey = bobKeyPair.getPublic();

        /// Perform key agreement once to generate shared secret
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(bobPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        /// Derive AES key using SHA-256 for security
        this.aesKey = deriveAESKey(sharedSecret);
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private SecretKeySpec deriveAESKey(byte[] sharedSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedSecret = sha256.digest(sharedSecret);
        /// Use first 16 bytes for AES-128; Use first 24 bytes for AES-192; Use first 32 bytes for 256;
        byte[] keyBytes = Arrays.copyOf(hashedSecret, 16);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     *      Encrypts the given plaintext using AES with the DH-derived key.
     *      @param plainText The input text to be encrypted.
     *      @return Base64-encoded string containing IV and ciphertext.
     *      @throws Exception If encryption fails.
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encrypted = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     *      Decrypts the given Base64-encoded ciphertext using AES with the DH-derived key.
     *      @param cipherText The encrypted text (IV + ciphertext).
     *      @return The decrypted plaintext.
     *      @throws Exception If decryption fails.
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] iv = Arrays.copyOfRange(decoded, 0, 16);
        byte[] encrypted = Arrays.copyOfRange(decoded, 16, decoded.length);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decrypted = aesCipher.doFinal(encrypted);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     *      Generates a shared secret using the other party's public key (for external use).
     *      @param receivedPublicKey The other party's public key.
     *      @return The Base64-encoded shared secret.
     *      @throws Exception If key agreement fails.
     */
    public String generateSharedSecret(PublicKey receivedPublicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(receivedPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return Base64.getEncoder().encodeToString(sharedSecret);
    }

    /**
     *      Retrieves the public key for sharing with another party.
     *      @return The Base64-encoded public key.
     */
    public String getEncodedPublicKey() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     *      Converts a Base64-encoded public key string back into a PublicKey object.
     *      @param encodedPublicKey The Base64-encoded public key.
     *      @return The PublicKey object.
     *      @throws Exception If key conversion fails.
     */
    public static PublicKey decodePublicKey(String encodedPublicKey) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(decodedBytes));
    }

    /**
     *      Returns the name of the algorithm for identification in the framework.
     *      @return Algorithm name as a String.
     */
    @Override
    public String getAlgorithmName() {
        return "DH-AES-128-PKCS5Padding-" + keySize + " bits";
    }
}