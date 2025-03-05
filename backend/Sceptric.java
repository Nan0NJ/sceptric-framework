package backend;

import backend.algorithms.symmetric.*;
import backend.algorithms.asymmetric.*;
import backend.services.CryptographicAlgorithm;

import java.security.PublicKey;

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
        System.out.println("----------------------------------------------------");
        testRC6();
        System.out.println("----------------------------------------------------\n" +
                "NOT STARTING WITH THE ASYMMETRIC ALGORITHMS\n" +
                "----------------------------------------------------");
        testRSA();
        System.out.println("----------------------------------------------------");
        testDSA();
        System.out.println("----------------------------------------------------");
        testDH();
        System.out.println("----------------------------------------------------");
        testELGAMAL();
        System.out.println("----------------------------------------------------");
        testPaillier();
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
    /**
     * Tests RC6 encryption and decryption to verify correctness.
     */
    public static void testRC6() throws Exception {
        String[] modes = {"ECB", "CBC", "CFB", "CTR"};
        String[] paddings = {"PKCS5Padding", "NoPadding"};
        int[] keySizes = {128, 192, 256}; // RC6 supports 32 to 2048-bit keys
        int[] rounds = {12, 16, 20}; // Common RC6 rounds
        String testString = "Let's check if RC6 encrypts true";

        for (String mode : modes) {
            for (String padding : paddings) {
                for (int keySize : keySizes) {
                    for (int round : rounds) {
                        try {
                            CryptographicAlgorithm cipher = new RC6(mode, padding, keySize, round);
                            System.out.println("\nTesting " + cipher.getAlgorithmName() + " with " + keySize + " bits and " + round + " rounds:");
                            System.out.println("Original: " + testString);

                            String encrypted = cipher.encrypt(testString);
                            System.out.println("Encrypted: " + encrypted);

                            String decrypted = cipher.decrypt(encrypted);
                            System.out.println("Decrypted: " + decrypted);

                            System.out.println("Success: " + testString.equals(decrypted));
                        } catch (Exception e) {
                            System.err.println("RC6 test failed for " + mode + "/" + padding + "/" + keySize + "/" + round + " rounds: " + e.getMessage());
                        }
                    }
                }
            }
        }
    }
    /**
     * Tests RSA encryption and decryption to verify correctness.
     */
    public static void testRSA() throws Exception {
        String[] paddings = {"OAEPWithSHA-256AndMGF1Padding", "PKCS1Padding", "NoPadding"};
        int[] keySizes = {1024, 2048, 4096}; // RSA supports 1024, 2048, and 4096-bit keys
        String testString = "Let's check if RSA encrypts correctly!!!";

        for (String padding : paddings) {
            for (int keySize : keySizes) {
                try {
                    CryptographicAlgorithm cipher = new RSA(padding, keySize);
                    System.out.println("\nTesting " + cipher.getAlgorithmName() + " with " + keySize + " bits:");
                    System.out.println("Original: " + testString);

                    String encrypted = cipher.encrypt(testString);
                    System.out.println("Encrypted: " + encrypted);

                    String decrypted = cipher.decrypt(encrypted);
                    System.out.println("Decrypted: " + decrypted);

                    System.out.println("Success: " + testString.equals(decrypted));
                } catch (Exception e) {
                    System.err.println("RSA test failed for " + padding + "/" + keySize + ": " + e.getMessage());
                }
            }
        }
    }
    /**
     * Tests DSA signing and verification.
     */
    public static void testDSA() throws Exception {
        int[] keySizes = {1024, 2048, 3072}; // DSA supports 1024, 2048, and 3072-bit keys
        String testString = "Let's check if DSA signing works correctly!!!";

        for (int keySize : keySizes) {
            try {
                DSA dsa = new DSA(keySize);
                System.out.println("\nTesting " + dsa.getAlgorithmName() + " with " + keySize + " bits:");
                System.out.println("Original: " + testString);

                String signature = dsa.sign(testString);
                System.out.println("Signature: " + signature);

                boolean isValid = dsa.verify(testString, signature);
                System.out.println("Verification: " + (isValid ? "Success" : "Failure"));
            } catch (Exception e) {
                System.err.println("DSA test failed for " + keySize + " bits: " + e.getMessage());
            }
        }
    }
    /**
     * Tests Diffie-Hellman key exchange to verify shared secret agreement.
     */
    public static void testDH() throws Exception {
        int[] keySizes = {1024, 2048}; // Supported DH key sizes
        // 4096 is too large so bottleneck causes it to take a lot of time --- meaning that big key size doesn't mean better overall.
        for (int keySize : keySizes) {
            try {
                System.out.println("\nTesting Diffie-Hellman key exchange with " + keySize + " bits:");

                // Generate key pairs for Alice and Bob
                DH alice = new DH(keySize);
                DH bob = new DH(keySize);

                // Exchange public keys
                String alicePublicKeyEncoded = alice.getEncodedPublicKey();
                String bobPublicKeyEncoded = bob.getEncodedPublicKey();

                PublicKey alicePublicKey = DH.decodePublicKey(alicePublicKeyEncoded);
                PublicKey bobPublicKey = DH.decodePublicKey(bobPublicKeyEncoded);

                // Compute shared secrets
                String aliceSharedSecret = alice.generateSharedSecret(bobPublicKey);
                String bobSharedSecret = bob.generateSharedSecret(alicePublicKey);

                System.out.println("Alice's Shared Secret: " + aliceSharedSecret);
                System.out.println("Bob's Shared Secret: " + bobSharedSecret);

                // Verify both parties derive the same shared secret
                boolean isSuccess = aliceSharedSecret.equals(bobSharedSecret);
                System.out.println("Shared Secret Match: " + (isSuccess ? "Success" : "Failure"));
            } catch (Exception e) {
                System.err.println("Diffie-Hellman test failed for " + keySize + " bits: " + e.getMessage());
            }
        }
    }
    /**
     * Tests ElGamal encryption and decryption to verify correctness and probabilistic behavior.
     */
    public static void testELGAMAL() {
        int[] keySizes = {1024, 2048}; // Supported key sizes
        // 4096 is too large so bottleneck causes it to take a lot of time --- meaning that big key size doesn't mean better overall.
        String testString = "Let's check if it will encrypt correctly"; // Consistent with testAES

        for (int keySize : keySizes) {
            try {
                CryptographicAlgorithm elgamal = new ELGAMAL(keySize);
                System.out.println("\nTesting " + elgamal.getAlgorithmName() + ":");
                System.out.println("Original: " + testString);

                // First encryption
                String encrypted1 = elgamal.encrypt(testString);
                System.out.println("Encrypted 1: " + encrypted1);

                // Second encryption to test probabilistic property
                String encrypted2 = elgamal.encrypt(testString);
                System.out.println("Encrypted 2: " + encrypted2);

                // Verify that ciphertexts are different
                System.out.println("Are ciphertexts different? " + !encrypted1.equals(encrypted2));

                // Decrypt both ciphertexts
                String decrypted1 = elgamal.decrypt(encrypted1);
                System.out.println("Decrypted 1: " + decrypted1);
                System.out.println("Success 1: " + testString.equals(decrypted1));

                String decrypted2 = elgamal.decrypt(encrypted2);
                System.out.println("Decrypted 2: " + decrypted2);
                System.out.println("Success 2: " + testString.equals(decrypted2));
            } catch (Exception e) {
                System.err.println("ElGamal test failed for key size " + keySize + ": " + e.getMessage());
            }
        }
    }
    /**
     * Tests Paillier encryption and decryption to verify correctness.
     */
    public static void testPaillier() {
        int[] keySizes = {1024, 2048};
        // 4096 is too large so bottleneck causes it to take a lot of time --- meaning that big key size doesn't mean better overall.
        String testString = "Let's check if it will encrypt correctly";

        for (int keySize : keySizes) {
            try {
                CryptographicAlgorithm cipher = new PAILIER(keySize);
                System.out.println("\nTesting " + cipher.getAlgorithmName());
                System.out.println("Original: " + testString);

                String encrypted = cipher.encrypt(testString);
                System.out.println("Encrypted: " + encrypted);

                String decrypted = cipher.decrypt(encrypted);
                System.out.println("Decrypted: " + decrypted);

                System.out.println("Success: " + testString.equals(decrypted));
            } catch (Exception e) {
                System.err.println("Paillier test failed for key size " + keySize + ": " + e.getMessage());
            }
        }
    }
}