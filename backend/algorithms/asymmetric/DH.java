package backend.algorithms.asymmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

/**
 *      Diffie-Hellman (DH) Key Exchange implementation using Bouncy Castle.
 *      Used for secure key exchange between two parties.
 *      Varying key sizes of 1024, 2048, and 4096 bits.
 */
public class DH {

    /**
     *      Constructs of DH instance with the specified key size.
     *      Varying key size (1024, 2048, 4096).
     */
    private final KeyAgreement keyAgreement;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySize;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public DH (int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Invalid key size. DH supports 1024, 2048, or 4096 bits.");
        }
        this.keySize = keySize;

        KeyPair keyPair = generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        this.keyAgreement = KeyAgreement.getInstance("DH", "BC");
        this.keyAgreement.init(privateKey);
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * Generates a shared secret using the other party's public key.
     * @param receivedPublicKey The other party's public key.
     * @return The Base64-encoded shared secret.
     * @throws Exception If key agreement fails.
     */
    public String generateSharedSecret(PublicKey receivedPublicKey) throws Exception {
        keyAgreement.doPhase(receivedPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return Base64.getEncoder().encodeToString(sharedSecret);
    }

    /**
     * Retrieves the public key for sharing with another party.
     * @return The Base64-encoded public key.
     */
    public String getEncodedPublicKey() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Converts a Base64-encoded public key string back into a PublicKey object.
     * @param encodedPublicKey The Base64-encoded public key.
     * @return The PublicKey object.
     * @throws Exception If key conversion fails.
     */
    public static PublicKey decodePublicKey(String encodedPublicKey) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(decodedBytes));
    }

    public String getAlgorithmName() {
        return "Diffie-Hellman-" + keySize + " bits";
    }
}
