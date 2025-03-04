package backend.services;

/**
 *      This interface defines the structure for cryptographic algorithms
 *      to ensure they are interchangeable in the benchmarking framework.
 */

public interface CryptographicAlgorithm {
    /**
     *      Encrypts the given plain text using the implemented algorithm.
     *      @param plainText The input text to be encrypted.
     *      @return The encrypted output as a String.
     *      Key algorithm on which performance is measured.
     */
    String encrypt(String plainText);

    /**
     *      Decrypts the given cipher text using the implemented algorithm.
     *      @param cipherText The encrypted text to be decrypted.
     *      @return The decrypted output as a String.
     *      Used in terms of testing to check correctness of algorithm.
     */
    String decrypt(String cipherText);

    /**
     *      Returns the name of the cryptographic algorithm being used.
     *      @return Algorithm name as a String.
     *      Used as an Identifier in the UI frontend development.
     */
    String getAlgorithmName();
}
