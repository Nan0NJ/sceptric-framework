package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 *      ElGamal hybrid encryption implementation using Bouncy Castle.
 *      Standard uses ElGamal for key exchange and AES for data encryption. --- PGP (Pretty Good Privacy)
 *      Supports key sizes 1024, 2048, and 4096 bits.
 */
public class ELGAMAL implements CryptographicAlgorithm {

    private final Cipher elGamalCipher;
    private final Cipher aesCipher;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySize;
    private static final int AES_KEY_SIZE = 32; // 256 bits in bytes

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ELGAMAL(int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Invalid key size. ElGamal supports 1024, 2048, or 4096 bits.");
        }
        this.keySize = keySize;

        KeyPair keyPair = generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        this.elGamalCipher = Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC"); // Use PKCS1 for consistency
        this.aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        return keyGen.generateKey();
    }

    /**
     *      Encrypts the given plaintext using ElGamal for key exchange and AES for data.
     *      @param plainText The input text to be encrypted
     *      @return The encrypted output as a Base64-encoded string (ElGamal-encrypted AES key + IV + ciphertext)
     *      @throws Exception If encryption fails
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) throw new IllegalArgumentException("Plaintext cannot be null");

        // Generate AES key (256 bits = 32 bytes)
        SecretKey aesKey = generateAESKey();
        byte[] aesKeyBytes = aesKey.getEncoded(); // Always 32 bytes

        // Encrypt AES key with ElGamal
        elGamalCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAESKey = elGamalCipher.doFinal(aesKeyBytes);

        // Encrypt data with AES
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV(); // 16 bytes
        byte[] inputBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = aesCipher.doFinal(inputBytes);

        // Combine encrypted key, IV, and ciphertext with length prefixes for clarity
        ByteBuffer output = ByteBuffer.allocate(4 + encryptedAESKey.length + 4 + iv.length + cipherBytes.length);
        output.putInt(encryptedAESKey.length); // Prefix key length
        output.put(encryptedAESKey);
        output.putInt(iv.length); // Prefix IV length (always 16, but for flexibility)
        output.put(iv);
        output.put(cipherBytes);

        return Base64.getEncoder().encodeToString(output.array());
    }

    /**
     *      Decrypts the given Base64-encoded ciphertext using ElGamal to recover the AES key and AES for data.
     *      @param cipherText The encrypted text to be decrypted
     *      @return The decrypted output as a String
     *      @throws Exception If decryption fails
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) throw new IllegalArgumentException("Ciphertext cannot be null");

        byte[] data = Base64.getDecoder().decode(cipherText);
        ByteBuffer buffer = ByteBuffer.wrap(data);

        // Extract encrypted AES key with length prefix
        int encryptedKeyLength = buffer.getInt();
        byte[] encryptedAESKey = new byte[encryptedKeyLength];
        buffer.get(encryptedAESKey);

        // Extract IV with length prefix
        int ivLength = buffer.getInt();
        byte[] iv = new byte[ivLength];
        buffer.get(iv);

        // Extract ciphertext
        byte[] cipherBytes = new byte[buffer.remaining()];
        buffer.get(cipherBytes);

        // Decrypt AES key with ElGamal
        elGamalCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedAESKeyBytes = elGamalCipher.doFinal(encryptedAESKey);

        // Use exactly 32 bytes for AES-256
        if (decryptedAESKeyBytes.length < AES_KEY_SIZE) {
            throw new IllegalStateException("Decrypted AES key too short: " + decryptedAESKeyBytes.length);
        }
        byte[] aesKeyBytes = new byte[AES_KEY_SIZE];
        System.arraycopy(decryptedAESKeyBytes, 0, aesKeyBytes, 0, AES_KEY_SIZE);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt data with AES
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plainBytes = aesCipher.doFinal(cipherBytes);

        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     *      Returns the name of the ElGamal hybrid algorithm.
     *      @return Algorithm name
     */
    @Override
    public String getAlgorithmName() {
        return "ElGamal-" + keySize + "-Hybrid-AES";
    }
}