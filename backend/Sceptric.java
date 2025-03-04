package backend;

import backend.services.CryptographicAlgorithm;
import backend.algorithms.symmetric.AES;

public class Sceptric {

    public static void main(String[] args) throws Exception {
        testAES();
    }

    /**
     *      Tests AES encryption and decryption to verify correctness.
     */
    public static void testAES() throws Exception {

        // First checking if ECB is DETERMINISTIC
        CryptographicAlgorithm cipherORG = new AES("ECB", "PKCS5Padding", 128);
        String encrypted1 = cipherORG.encrypt("Hello, World!");
        String encrypted2 = cipherORG.encrypt("Hello, World!");

        System.out.println("Testing ECB determinism with same instance:");
        System.out.println("Encrypted 1: " + encrypted1);
        System.out.println("Encrypted 2: " + encrypted2);
        System.out.println("Are ciphertexts equal? " + encrypted1.equals(encrypted2));

        String[] modes = {"ECB", "CBC", "GCM"};
        String[] paddings = {"PKCS5Padding"};
        int[] keySizes = {128, 256};
        String testString = "Let's check if it will encrypt correctly";

        for (String mode : modes) {
            for (String padding : paddings) {
                for (int keySize : keySizes) {
                    try {
                        CryptographicAlgorithm cipher = new AES(mode, padding, keySize);
                        System.out.println("\nTesting " + cipher.getAlgorithmName() + " with " + keySize + " bits:");
                        System.out.println("Original: " + testString);

                        String encrypted = cipher.encrypt(testString);
                        System.out.println("Encrypted: " + encrypted);

                        String decrypted = cipher.decrypt(encrypted);
                        System.out.println("Decrypted: " + decrypted);

                        System.out.println("Success: " + testString.equals(decrypted));
                    } catch (Exception e) {
                        System.err.println("AES test failed for " + mode + "/" + padding + "/" + keySize + ": " + e.getMessage());
                    }
                }
            }
        }
    }
}