package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 *      DSA (Digital Signature Algorithm) implementation using Bouncy Castle.
 *      Used for digital signatures (signing and verification), not encryption.
 *      Varying key sizes (1024, 2048, 3072 bits).
 *      CAN WE IMPLEMENT A SAM (SECURE AUTHENTICATED MESSAGING PROTOCOL TO WORK WITH ENCRYPTION AND DECRYPTION)
 */
public class DSA implements CryptographicAlgorithm {

    /**
     *      Constructs of DSA instance with the specified key size.
     *      The padding scheme (SHA-256)
     *      Varying key size (1024, 2048, 3072).
     */
    private final Signature signature;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySize;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public DSA(int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 3072) {
            throw new IllegalArgumentException("Invalid key size. DSA supports 1024, 2048, or 3072 bits.");
        }
        this.keySize = keySize;
        this.signature = Signature.getInstance("SHA256withDSA", "BC");

        KeyPair keyPair = generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * Signs a message using the private key.
     * @param message The message to be signed.
     * @return The Base64-encoded digital signature.
     * @throws Exception If signing fails.
     */
    public String sign(String message) throws Exception {
        if (message == null) throw new IllegalArgumentException("Message cannot be null");

        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    /**
     * Verifies a digital signature using the public key.
     * @param message The original message.
     * @param signedMessage The Base64-encoded digital signature.
     * @return True if the signature is valid, false otherwise.
     * @throws Exception If verification fails.
     */
    public boolean verify(String message, String signedMessage) throws Exception {
        if (message == null || signedMessage == null) throw new IllegalArgumentException("Message and signature cannot be null");

        signature.initVerify(publicKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] decodedSignature = Base64.getDecoder().decode(signedMessage);
        return signature.verify(decodedSignature);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getEncodedPublicKey() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey decodePublicKey(String encodedPublicKey) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");
        return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(decodedBytes));
    }

    @Override
    public String encrypt(String plainText) throws Exception {
        throw new UnsupportedOperationException("DSA is a signing algorithm and does not support encryption. Check SAM Protocol where DSA is used.");
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
        throw new UnsupportedOperationException("DSA is a signing algorithm and does not support decryption. Check SAM Protocol where DSA is used.");
    }

    public String getAlgorithmName() {
        return "DSA-SHA256-" + keySize + " bits";
    }

}