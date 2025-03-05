package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 *      ElGamal encryption implementation using Bouncy Castle.
 *      Supports key sizes 1024, 2048, and 4096 bits.
 *      Implements the CryptographicAlgorithm interface for encryption and decryption.
 */
public class ELGAMAL implements CryptographicAlgorithm {

    /**
     *      Constructs of El Gamal instance with the specified key size.
     *      Varying key size (1024, 2048, 4096).
     */
    private final Cipher cipher;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySize;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ELGAMAL (int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Invalid key size. ElGamal supports 1024, 2048, or 4096 bits.");
        }
        this.keySize = keySize;

        KeyPair keyPair = generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        this.cipher = Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     *      Encrypts the given plaintext using El Gamal.
     *      @param plainText The input text to be encrypted
     *      @return The encrypted output as a Base64-encoded string
     *      @throws Exception If encryption fails
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) throw new IllegalArgumentException("Plaintext cannot be null");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     *      Decrypts the given Base64-encoded ciphertext using El Gamal.
     *      @param cipherText The encrypted text to be decrypted
     *      @return The decrypted output as a String
     *      @throws Exception If decryption fails
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) throw new IllegalArgumentException("Ciphertext cannot be null");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     *      Returns the name of the El Gamal algorithm being used.
     *      @return Algorithm name in the format "IDEA-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "ElGamal-" + keySize + " bits";
    }
}
