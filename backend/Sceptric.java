package backend;

import backend.algorithms.symmetric.*;
import backend.services.CryptographicAlgorithm;

public class Sceptric {

    public static void main(String[] args) throws Exception {
        testAES();
        System.out.println("----------------------------------------------------");
        testDES();
        System.out.println("----------------------------------------------------");
        testDES3();
        System.out.println("----------------------------------------------------");
        testBLOWFISH();
        System.out.println("----------------------------------------------------");
        testIDEA();
        System.out.println("----------------------------------------------------");
        testRC4();
        System.out.println("----------------------------------------------------");
        testRC5();
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
    /**
     * Tests Blowfish encryption and decryption to verify correctness.
     */
    public static void testBLOWFISH() throws Exception {
        // Test ECB determinism
        CryptographicAlgorithm cipherORG = new BLOWFISH("ECB", "PKCS5Padding", 128);
        String encrypted1 = cipherORG.encrypt("Hello, World!");
        String encrypted2 = cipherORG.encrypt("Hello, World!");
        System.out.println("\nTesting ECB determinism:");
        System.out.println("Encrypted 1: " + encrypted1);
        System.out.println("Encrypted 2: " + encrypted2);
        System.out.println("Are ciphertexts equal? " + encrypted1.equals(encrypted2));

        String[] modes = {"ECB", "CBC", "CFB", "CTR"};
        String[] paddings = {"PKCS5Padding", "NoPadding"};
        int[] keySizes = {32, 64, 128, 192, 256, 448}; // Blowfish supports key sizes from 32 to 448 bits
        String testString = "Let's check if Blowfish encrypts correct";

        for (String mode : modes) {
            for (String padding : paddings) {
                for (int keySize : keySizes) {
                    try {
                        CryptographicAlgorithm cipher = new BLOWFISH(mode, padding, keySize);
                        System.out.println("\nTesting " + cipher.getAlgorithmName() + " with " + keySize + " bits:");
                        System.out.println("Original: " + testString);

                        String encrypted = cipher.encrypt(testString);
                        System.out.println("Encrypted: " + encrypted);

                        String decrypted = cipher.decrypt(encrypted);
                        System.out.println("Decrypted: " + decrypted);

                        System.out.println("Success: " + testString.equals(decrypted));
                    } catch (Exception e) {
                        System.err.println("Blowfish test failed for " + mode + "/" + padding + "/" + keySize + ": " + e.getMessage());
                    }
                }
            }
        }
    }
    /**
     *      Tests IDEA encryption and decryption to verify correctness.
     */
    public static void testIDEA() throws Exception {

        // Test ECB determinism with a single IDEA instance
        CryptographicAlgorithm desCipher = new IDEA("ECB", "PKCS5Padding");
        String encrypted1 = desCipher.encrypt("Hello, World!");
        String encrypted2 = desCipher.encrypt("Hello, World!");

        System.out.println("\nTesting IDEA ECB determinism with same instance:");
        System.out.println("Encrypted 1: " + encrypted1);
        System.out.println("Encrypted 2: " + encrypted2);
        System.out.println("Are ciphertexts equal? " + encrypted1.equals(encrypted2));

        String[] modes = {"ECB", "CBC", "CFB", "CTR"};
        String[] paddings = {"NoPadding", "PKCS5Padding"};
        String testString = "Let's check if IDEA encrypts correctly!!";

        for (String mode : modes) {
            for (String padding : paddings) {
                try {
                    // CTR mode must use NoPadding
                    if (mode.equals("CTR") && padding.equals("PKCS5Padding")) {
                        continue; // Skip invalid combination
                    }

                    CryptographicAlgorithm cipher = new IDEA(mode, padding);
                    System.out.println("\nTesting " + cipher.getAlgorithmName() + ":");
                    System.out.println("Original: " + testString);

                    String encrypted = cipher.encrypt(testString);
                    System.out.println("Encrypted: " + encrypted);

                    String decrypted = cipher.decrypt(encrypted);
                    System.out.println("Decrypted: " + decrypted);

                    System.out.println("Success: " + testString.equals(decrypted));
                } catch (Exception e) {
                    System.err.println("IDEA test failed for " + mode + "/" + padding + ": " + e.getMessage());
                }
            }
        }
    }
    /**
     *      Tests RC4 encryption and decryption to verify correctness.
     */
    public static void testRC4() throws Exception {
        int[] keySizes = {40, 64, 128, 192, 256, 512, 1024, 2048}; // RC4 supports 40 to 2048-bit keys
        String testString = "Let's check if RC4 encrypts correctly!!";

        for (int keySize : keySizes) {
            try {
                CryptographicAlgorithm cipher = new RC4(keySize);
                System.out.println("\nTesting RC4 with " + keySize + " bits:");
                System.out.println("Original: " + testString);

                String encrypted = cipher.encrypt(testString);
                System.out.println("Encrypted: " + encrypted);

                String decrypted = cipher.decrypt(encrypted);
                System.out.println("Decrypted: " + decrypted);

                System.out.println("Success: " + testString.equals(decrypted));
            } catch (Exception e) {
                System.err.println("RC4 test failed for key size " + keySize + ": " + e.getMessage());
            }
        }
    }
    /**
     * Tests RC5 encryption and decryption to verify correctness.
     */
    public static void testRC5() throws Exception {
        String[] modes = {"ECB", "CBC", "CFB", "CTR"};
        String[] paddings = {"PKCS5Padding", "NoPadding"};
        int[] keySizes = {32, 64, 128, 192, 256, 512, 1024, 2048}; // RC5 supports 32 to 2048-bit keys
        int[] rounds = {12, 16, 20}; // Common RC5 rounds
        String testString = "Let's check if RC5 encrypts correctly!!!";

        for (String mode : modes) {
            for (String padding : paddings) {
                for (int keySize : keySizes) {
                    for (int round : rounds) {
                        try {
                            CryptographicAlgorithm cipher = new RC5(mode, padding, keySize, round);
                            System.out.println("\nTesting " + cipher.getAlgorithmName() + " with " + keySize + " bits and " + round + " rounds:");
                            System.out.println("Original: " + testString);

                            String encrypted = cipher.encrypt(testString);
                            System.out.println("Encrypted: " + encrypted);

                            String decrypted = cipher.decrypt(encrypted);
                            System.out.println("Decrypted: " + decrypted);

                            System.out.println("Success: " + testString.equals(decrypted));
                        } catch (Exception e) {
                            System.err.println("RC5 test failed for " + mode + "/" + padding + "/" + keySize + "/" + round + " rounds: " + e.getMessage());
                        }
                    }
                }
            }
        }
    }
}