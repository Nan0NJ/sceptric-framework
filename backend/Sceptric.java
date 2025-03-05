package backend;

import backend.services.CryptographicAlgorithm;
import backend.algorithms.symmetric.AES;
import backend.algorithms.symmetric.DES;
import backend.algorithms.symmetric.DES3;

public class Sceptric {

    public static void main(String[] args) throws Exception {
        testAES();
        System.out.println("----------------------------------------------------");
        testDES();
        System.out.println("----------------------------------------------------");
        testDES3();
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
        int[] keySizes = {128, 192, 256};
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
    /**
     *      Tests DES encryption and decryption to verify correctness.
     */
    public static void testDES() throws Exception {

        // Test ECB determinism with a single DES instance
        CryptographicAlgorithm desCipher = new DES("ECB", "PKCS5Padding");
        String encrypted1 = desCipher.encrypt("Hello, World!");
        String encrypted2 = desCipher.encrypt("Hello, World!");

        System.out.println("\nTesting DES ECB determinism with same instance:");
        System.out.println("Encrypted 1: " + encrypted1);
        System.out.println("Encrypted 2: " + encrypted2);
        System.out.println("Are ciphertexts equal? " + encrypted1.equals(encrypted2));

        String[] modes = {"ECB", "CBC", "CFB", "CTR"};
        String[] paddings = {"NoPadding", "PKCS5Padding"};
        String testString = "Let's check if DES encrypts correctly!!!";

        for (String mode : modes) {
            for (String padding : paddings) {
                try {
                    // CTR mode must use NoPadding
                    if (mode.equals("CTR") && padding.equals("PKCS5Padding")) {
                        continue; // Skip invalid combination
                    }

                    CryptographicAlgorithm cipher = new DES(mode, padding);
                    System.out.println("\nTesting " + cipher.getAlgorithmName() + ":");
                    System.out.println("Original: " + testString);

                    String encrypted = cipher.encrypt(testString);
                    System.out.println("Encrypted: " + encrypted);

                    String decrypted = cipher.decrypt(encrypted);
                    System.out.println("Decrypted: " + decrypted);

                    System.out.println("Success: " + testString.equals(decrypted));
                } catch (Exception e) {
                    System.err.println("DES test failed for " + mode + "/" + padding + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     *      Tests 3DES encryption and decryption to verify correctness.
     */
    public static void testDES3() throws Exception {

        // Test ECB determinism
        CryptographicAlgorithm cipherORG = new DES3("ECB", "PKCS5Padding");
        String encrypted1 = cipherORG.encrypt("Hello, World!");
        String encrypted2 = cipherORG.encrypt("Hello, World!");
        System.out.println("\nTesting ECB determinism:");
        System.out.println("Encrypted 1: " + encrypted1);
        System.out.println("Encrypted 2: " + encrypted2);
        System.out.println("Are ciphertexts equal? " + encrypted1.equals(encrypted2));

        String[] modes = {"ECB", "CBC", "CFB", "CTR"};
        String[] paddings = {"PKCS5Padding", "NoPadding"};
        String testString = "Let's check if 3DES encrypts correctly!!";

        for (String mode : modes) {
            for (String padding : paddings) {
                try {
                    CryptographicAlgorithm cipher = new DES3(mode, padding);
                    System.out.println("\nTesting " + cipher.getAlgorithmName() + ":");
                    System.out.println("Original: " + testString);

                    String encrypted = cipher.encrypt(testString);
                    System.out.println("Encrypted: " + encrypted);

                    String decrypted = cipher.decrypt(encrypted);
                    System.out.println("Decrypted: " + decrypted);

                    System.out.println("Success: " + testString.equals(decrypted));
                } catch (Exception e) {
                    System.err.println("DES3 test failed for " + mode + "/" + padding + ": " + e.getMessage());
                }
            }
        }
    }
}