package backend.algorithms.asymmetric;

import backend.services.CryptographicAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 *      Paillier encryption implementation using Bouncy Castle.
 *      Supports key sizes 1024, 2048, and 4096 bits.
 */
public class PAILIER implements CryptographicAlgorithm {

    /**
     *      Constructs a Paillier instance with the specified key size.
     *      Varying key size in bits (1024, 2048, or 4096).

     */
    private final int keySize;
    private final BigInteger n, nsquare, g, lambda, mu;
    private final SecureRandom random;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PAILIER(int keySize) throws Exception {
        // Validate key size
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Invalid key size. Paillier supports 1024, 2048, or 4096 bits.");
        }
        this.keySize = keySize;
        this.random = new SecureRandom();

        // Generate two primes p and q, each of bit length keySize/2
        int primeBitLength = keySize / 2;
        BigInteger p = BigInteger.probablePrime(primeBitLength, random);
        BigInteger q = BigInteger.probablePrime(primeBitLength, random);
        // Ensure p and q are distinct
        while (p.equals(q)) {
            q = BigInteger.probablePrime(primeBitLength, random);
        }

        // Compute n = p * q
        this.n = p.multiply(q);
        this.nsquare = n.multiply(n);

        // Compute lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger gcd = pMinus1.gcd(qMinus1);
        this.lambda = pMinus1.multiply(qMinus1).divide(gcd);

        // Set g = n + 1
        this.g = n.add(BigInteger.ONE);

        // Compute mu = (L(g^lambda mod n^2))^{-1} mod n
        BigInteger gLambda = g.modPow(lambda, nsquare);
        BigInteger L = gLambda.subtract(BigInteger.ONE).divide(n);
        this.mu = L.modInverse(n);
    }

    /**
     * Encrypts the given plaintext using Paillier encryption.
     * @param plainText The input text to be encrypted.
     * @return The encrypted output as a Base64-encoded string.
     * @throws Exception If encryption fails or plaintext is invalid.
     */
    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) {
            throw new IllegalArgumentException("Plaintext cannot be null");
        }

        // Convert plaintext string to BigInteger
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        BigInteger m = new BigInteger(1, plainBytes); // Ensure positive interpretation
        if (m.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Plaintext is too large for the key size.");
        }

        // Choose random r in [1, n-1]
        BigInteger r = new BigInteger(n.bitLength(), random).mod(n);
        if (r.equals(BigInteger.ZERO)) {
            r = BigInteger.ONE; // Avoid r = 0, though probability is negligible
        }

        // Compute ciphertext: c = g^m * r^n mod n^2
        BigInteger ciphertext = g.modPow(m, nsquare)
                .multiply(r.modPow(n, nsquare))
                .mod(nsquare);

        // Return Base64-encoded string
        return Base64.getEncoder().encodeToString(ciphertext.toByteArray());
    }

    /**
     * Decrypts the given Base64-encoded ciphertext using Paillier decryption.
     * @param cipherText The encrypted text to be decrypted.
     * @return The decrypted output as a String.
     * @throws Exception If decryption fails or ciphertext is invalid.
     */
    @Override
    public String decrypt(String cipherText) throws Exception {
        if (cipherText == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }

        // Decode Base64 ciphertext to BigInteger
        byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
        BigInteger c = new BigInteger(cipherBytes);

        // Decrypt: m = L(c^lambda mod n^2) * mu mod n
        BigInteger cLambda = c.modPow(lambda, nsquare);
        BigInteger L = cLambda.subtract(BigInteger.ONE).divide(n);
        BigInteger m = L.multiply(mu).mod(n);

        // Convert back to string
        byte[] plainBytes = m.toByteArray();
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Returns the name of the Paillier algorithm being used.
     * @return Algorithm name in the format "Paillier-<keySize> bits".
     */
    @Override
    public String getAlgorithmName() {
        return "Paillier-" + keySize + " bits";
    }
}