package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 *      Paillier encryption implementation with hybrid AES for real-world use.
 *      Supports key sizes 1024, 2048, and 4096 bits, using AES-256 for bulk data.
 */
public class PAILLIER implements CryptographicAlgorithm {

    /**
     *      Constructs a Paillier instance with the specified key size for hybrid encryption.
     *      Varying key size in bits (1024, 2048, or 4096).
     */
    private final int keySize;
    private final BigInteger n, nsquare, g, lambda, mu;
    private final SecureRandom random;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PAILLIER(int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Invalid key size. Paillier supports 1024, 2048, or 4096 bits.");
        }
        this.keySize = keySize;
        this.random = new SecureRandom();

        int primeBitLength = keySize / 2;
        BigInteger p = BigInteger.probablePrime(primeBitLength, random);
        BigInteger q = BigInteger.probablePrime(primeBitLength, random);
        while (p.equals(q)) {
            q = BigInteger.probablePrime(primeBitLength, random);
        }

        this.n = p.multiply(q);
        this.nsquare = n.multiply(n);
        this.lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        this.g = n.add(BigInteger.ONE);
        BigInteger gLambda = g.modPow(lambda, nsquare);
        BigInteger L = gLambda.subtract(BigInteger.ONE).divide(n);
        this.mu = L.modInverse(n);
    }

    /**
     * Encrypts the given plaintext using hybrid encryption: AES for data, Paillier for the AES key.
     * @param plainText The input text to be encrypted.
     * @return The encrypted output as a Base64-encoded string (IV:encryptedData:encryptedKey).
     * @throws Exception If encryption fails or plaintext is invalid.
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) {
            throw new IllegalArgumentException("Plaintext cannot be null");
        }

        byte[] aesKey = new byte[32]; // 256-bit AES key
        random.nextBytes(aesKey);
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
        byte[] iv = aesCipher.getIV();
        byte[] encryptedData = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        BigInteger aesKeyBigInt = new BigInteger(1, aesKey);
        if (aesKeyBigInt.compareTo(n) >= 0) {
            throw new IllegalStateException("AES key too large for Paillier key size!");
        }
        BigInteger r = new BigInteger(n.bitLength(), random).mod(n);
        if (r.equals(BigInteger.ZERO)) {
            r = BigInteger.ONE;
        }
        BigInteger encryptedKey = g.modPow(aesKeyBigInt, nsquare)
                .multiply(r.modPow(n, nsquare))
                .mod(nsquare);

        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String dataBase64 = Base64.getEncoder().encodeToString(encryptedData);
        String keyBase64 = Base64.getEncoder().encodeToString(encryptedKey.toByteArray());
        return ivBase64 + ":" + dataBase64 + ":" + keyBase64;
    }

    /**
     * Decrypts the given Base64-encoded hybrid ciphertext using Paillier and AES.
     * @param cipherText The encrypted text (IV:encryptedData:encryptedKey) to be decrypted.
     * @return The decrypted output as a String.
     * @throws Exception If decryption fails or ciphertext is invalid.
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }

        String[] parts = cipherText.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid ciphertext format");
        }
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedData = Base64.getDecoder().decode(parts[1]);
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(parts[2]);

        BigInteger encryptedKey = new BigInteger(encryptedKeyBytes);
        BigInteger cLambda = encryptedKey.modPow(lambda, nsquare);
        BigInteger L = cLambda.subtract(BigInteger.ONE).divide(n);
        BigInteger aesKeyBigInt = L.multiply(mu).mod(n);

        // Normalize the AES key to exactly 32 bytes
        byte[] aesKey = aesKeyBigInt.toByteArray();
        byte[] fixedAesKey = new byte[32];
        if (aesKey.length > 32) {
            // If longer than 32 bytes, take the last 32 bytes (right-aligned)
            System.arraycopy(aesKey, aesKey.length - 32, fixedAesKey, 0, 32);
        } else {
            // If shorter, pad with leading zeros
            System.arraycopy(aesKey, 0, fixedAesKey, 32 - aesKey.length, aesKey.length);
        }

        SecretKeySpec aesKeySpec = new SecretKeySpec(fixedAesKey, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] decryptedData = aesCipher.doFinal(encryptedData);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * Returns the name of the hybrid Paillier algorithm being used.
     * @return Algorithm name in the format "Paillier-Hybrid-<keySize> bits (AES-256)".
     */
    @Override
    public String getAlgorithmName() {
        return "Paillier-Hybrid-" + keySize + " bits (AES-256)";
    }
}