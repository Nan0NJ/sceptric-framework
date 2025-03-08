package backend.algorithms.symmetric;
import backend.services.CryptographicAlgorithm;

// Uses Java's standard cryptographic libraries with Bouncy Castle for RC5 support.
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class RC5 implements CryptographicAlgorithm {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Constructs an RC5 instance with the specified mode, padding, and key size.
     * Note: RC5 in Bouncy Castle uses a fixed number of rounds (12).
     * The RC5 mode (ECB, CBC, CFB, CTR, OFB)
     * The padding scheme (PKCS5Padding, NoPadding)
     * Varying key size (32-2048)
     */
    private final Cipher cipher;
    private final SecretKey key;
    private final String mode;
    private final String padding;
    private byte[] iv;

    public RC5(String mode, String padding, int keySize) throws Exception {
        if (keySize < 32 || keySize > 2048 || keySize % 8 != 0) {
            throw new IllegalArgumentException("Invalid key size. RC5 supports key sizes from 32 to 2048 bits in multiples of 8.");
        }

        this.mode = mode;
        this.padding = padding;

        String transformation;
        if (mode.equals("ECB")) {
            transformation = "RC5/ECB/" + padding;
        } else if (mode.equals("CBC")) {
            transformation = "RC5/CBC/" + padding;
        } else if (mode.equals("CTR")) {
            transformation = "RC5/CTR/NoPadding";
            if (!padding.equals("NoPadding")) {
                throw new IllegalArgumentException("CTR mode requires NoPadding");
            }
        } else if (mode.equals("CFB")) {
            transformation = "RC5/CFB64/NoPadding";
            if (!padding.equals("NoPadding")) {
                throw new IllegalArgumentException("CFB mode requires NoPadding");
            }
        } else if (mode.equals("OFB")) {
            transformation = "RC5/OFB64/NoPadding";
            if (!padding.equals("NoPadding")) {
                throw new IllegalArgumentException("OFB mode requires NoPadding");
            }
        } else {
            throw new UnsupportedOperationException("Unsupported mode: " + mode);
        }

        this.cipher = Cipher.getInstance(transformation, "BC");
        this.key = generateKey(keySize);

        if (!mode.equals("ECB")) {
            this.iv = new byte[8]; // Fixed 8-byte IVs for RC5's 64-bit block size
            new SecureRandom().nextBytes(this.iv);
        }
    }

    private SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("RC5", "BC");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    /**
     * Encrypts the given plaintext using RC5.
     * @param plainText The input text to be encrypted
     * @return The encrypted output as a Base64-encoded string
     * @throws Exception If encryption fails
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
     * Decrypts the given Base64-encoded ciphertext using RC5.
     * @param cipherText The encrypted text to be decrypted
     * @return The decrypted output as a String
     * @throws Exception If decryption fails
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
     * Returns the name of the RC5 algorithm being used.
     * @return Algorithm name in the format "RC5-mode-padding"
     */
    @Override
    public String getAlgorithmName() {
        return "RC5-" + mode + "-" + padding;
    }
}