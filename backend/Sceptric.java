package backend;

import backend.algorithms.symmetric.*;
import backend.algorithms.asymmetric.*;
import backend.services.CryptographicAlgorithm;

import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.PowerSource;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.OperatingSystem;
import oshi.software.os.OSProcess;


import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Sceptric {

    ///     Enum to store all algorithm configurations
    public enum AlgorithmType {
        // AES Algorithms
        AES_ECB_128("AES", "ECB", "PKCS5Padding", 128),
        AES_ECB_192("AES", "ECB", "PKCS5Padding", 192),
        AES_ECB_256("AES", "ECB", "PKCS5Padding", 256),
        AES_CBC_128("AES", "CBC", "PKCS5Padding", 128),
        AES_CBC_192("AES", "CBC", "PKCS5Padding", 192),
        AES_CBC_256("AES", "CBC", "PKCS5Padding", 256),
        AES_CTR_128("AES", "CTR", "PKCS5Padding", 128),
        AES_CTR_192("AES", "CTR", "PKCS5Padding", 192),
        AES_CTR_256("AES", "CTR", "PKCS5Padding", 256),
        AES_CFB128_128("AES", "CFB128", "PKCS5Padding", 128),
        AES_CFB128_192("AES", "CFB128", "PKCS5Padding", 192),
        AES_CFB128_256("AES", "CFB128", "PKCS5Padding", 256),
        AES_OFB128_128("AES", "OFB128", "PKCS5Padding", 128),
        AES_OFB128_192("AES", "OFB128", "PKCS5Padding", 192),
        AES_OFB128_256("AES", "OFB128", "PKCS5Padding", 256),
        AES_GCM_128("AES", "GCM", "PKCS5Padding", 128),
        AES_GCM_192("AES", "GCM", "PKCS5Padding", 192),
        AES_GCM_256("AES", "GCM", "PKCS5Padding", 256),

        // DES Algorithms
        DES_ECB("DES", "ECB", "PKCS5Padding", 0),
        DES_CBC("DES", "CBC", "PKCS5Padding", 0),
        DES_CTR("DES", "CTR", "NoPadding", 0),
        DES_CFB_P("DES", "CFB", "PKCS5Padding", 0),
        DES_CFB_N("DES", "CFB", "NoPadding", 0),
        DES_OFB_P("DES", "OFB", "PKCS5Padding", 0),
        DES_OFB_N("DES", "OFB", "NoPadding", 0),

        // DES3 (Triple DES) Algorithms
        TDES_ECB("DES3", "ECB", "PKCS5Padding", 0),
        TDES_CBC("DES3", "CBC", "PKCS5Padding", 0),
        TDES_CTR("DES3", "CTR", "NoPadding", 0),
        TDES_CFB_P("DES3", "CFB", "PKCS5Padding", 0),
        TDES_CFB_N("DES3", "CFB", "NoPadding", 0),
        TDES_OFB_P("DES3", "OFB", "PKCS5Padding", 0),
        TDES_OFB_N("DES3", "OFB", "NoPadding", 0),

        // Blowfish Algorithms
        BLOWFISH_ECB_32("BLOWFISH", "ECB", "PKCS5Padding", 32),
        BLOWFISH_ECB_64("BLOWFISH", "ECB", "PKCS5Padding", 64),
        BLOWFISH_ECB_128("BLOWFISH", "ECB", "PKCS5Padding", 128),
        BLOWFISH_ECB_192("BLOWFISH", "ECB", "PKCS5Padding", 192),
        BLOWFISH_ECB_256("BLOWFISH", "ECB", "PKCS5Padding", 256),
        BLOWFISH_ECB_448("BLOWFISH", "ECB", "PKCS5Padding", 448),
        BLOWFISH_CBC_32("BLOWFISH", "CBC", "PKCS5Padding", 32),
        BLOWFISH_CBC_64("BLOWFISH", "CBC", "PKCS5Padding", 64),
        BLOWFISH_CBC_128("BLOWFISH", "CBC", "PKCS5Padding", 128),
        BLOWFISH_CBC_192("BLOWFISH", "CBC", "PKCS5Padding", 192),
        BLOWFISH_CBC_256("BLOWFISH", "CBC", "PKCS5Padding", 256),
        BLOWFISH_CBC_448("BLOWFISH", "CBC", "PKCS5Padding", 448),
        BLOWFISH_CTR_P_32("BLOWFISH", "CTR", "PKCS5Padding", 32),
        BLOWFISH_CTR_P_64("BLOWFISH", "CTR", "PKCS5Padding", 64),
        BLOWFISH_CTR_P_128("BLOWFISH", "CTR", "PKCS5Padding", 128),
        BLOWFISH_CTR_P_192("BLOWFISH", "CTR", "PKCS5Padding", 192),
        BLOWFISH_CTR_P_256("BLOWFISH", "CTR", "PKCS5Padding", 256),
        BLOWFISH_CTR_P_448("BLOWFISH", "CTR", "PKCS5Padding", 448),
        BLOWFISH_CTR_N_32("BLOWFISH", "CTR", "NoPadding", 32),
        BLOWFISH_CTR_N_64("BLOWFISH", "CTR", "NoPadding", 64),
        BLOWFISH_CTR_N_128("BLOWFISH", "CTR", "NoPadding", 128),
        BLOWFISH_CTR_N_192("BLOWFISH", "CTR", "NoPadding", 192),
        BLOWFISH_CTR_N_256("BLOWFISH", "CTR", "NoPadding", 256),
        BLOWFISH_CTR_N_448("BLOWFISH", "CTR", "NoPadding", 448),
        BLOWFISH_CFB_P_32("BLOWFISH", "CFB", "PKCS5Padding", 32),
        BLOWFISH_CFB_P_64("BLOWFISH", "CFB", "PKCS5Padding", 64),
        BLOWFISH_CFB_P_128("BLOWFISH", "CFB", "PKCS5Padding", 128),
        BLOWFISH_CFB_P_192("BLOWFISH", "CFB", "PKCS5Padding", 192),
        BLOWFISH_CFB_P_256("BLOWFISH", "CFB", "PKCS5Padding", 256),
        BLOWFISH_CFB_P_448("BLOWFISH", "CFB", "PKCS5Padding", 448),
        BLOWFISH_CFB_N_32("BLOWFISH", "CFB", "NoPadding", 32),
        BLOWFISH_CFB_N_64("BLOWFISH", "CFB", "NoPadding", 64),
        BLOWFISH_CFB_N_128("BLOWFISH", "CFB", "NoPadding", 128),
        BLOWFISH_CFB_N_192("BLOWFISH", "CFB", "NoPadding", 192),
        BLOWFISH_CFB_N_256("BLOWFISH", "CFB", "NoPadding", 256),
        BLOWFISH_CFB_N_448("BLOWFISH", "CFB", "NoPadding", 448),
        BLOWFISH_OFB_P_32("BLOWFISH", "OFB", "PKCS5Padding", 32),
        BLOWFISH_OFB_P_64("BLOWFISH", "OFB", "PKCS5Padding", 64),
        BLOWFISH_OFB_P_128("BLOWFISH", "OFB", "PKCS5Padding", 128),
        BLOWFISH_OFB_P_192("BLOWFISH", "OFB", "PKCS5Padding", 192),
        BLOWFISH_OFB_P_256("BLOWFISH", "OFB", "PKCS5Padding", 256),
        BLOWFISH_OFB_P_448("BLOWFISH", "OFB", "PKCS5Padding", 448),
        BLOWFISH_OFB_N_32("BLOWFISH", "OFB", "NoPadding", 32),
        BLOWFISH_OFB_N_64("BLOWFISH", "OFB", "NoPadding", 64),
        BLOWFISH_OFB_N_128("BLOWFISH", "OFB", "NoPadding", 128),
        BLOWFISH_OFB_N_192("BLOWFISH", "OFB", "NoPadding", 192),
        BLOWFISH_OFB_N_256("BLOWFISH", "OFB", "NoPadding", 256),
        BLOWFISH_OFB_N_448("BLOWFISH", "OFB", "NoPadding", 448),

        // IDEA Algorithms
        IDEA_ECB("IDEA", "ECB", "PKCS5Padding", 0),
        IDEA_CBC("IDEA", "CBC", "PKCS5Padding", 0),
        IDEA_CTR("IDEA", "CTR", "NoPadding", 0),
        IDEA_CFB_P("IDEA", "CFB", "PKCS5Padding", 0),
        IDEA_CFB_N("IDEA", "CFB", "NoPadding", 0),
        IDEA_OFB_P("IDEA", "OFB", "PKCS5Padding", 0),
        IDEA_OFB_N("IDEA", "OFB", "NoPadding", 0),

        // RC4 Algorithms
        RC4_40("RC4", "", "", 40),
        RC4_64("RC4", "", "", 64),
        RC4_128("RC4", "", "", 128),
        RC4_192("RC4", "", "", 192),
        RC4_256("RC4", "", "", 256),
        RC4_1024("RC4", "", "", 1024),

        // RC5 Algorithms
        RC5_ECB_128("RC5", "ECB", "PKCS5Padding", 128),
        RC5_EBC_192("RC5", "ECB", "PKCS5Padding", 192),
        RC5_ECB_256("RC5", "ECB", "PKCS5Padding", 256),
        RC5_CBC_128("RC5", "CBC", "PKCS5Padding", 128),
        RC5_CBC_192("RC5", "CBC", "PKCS5Padding", 192),
        RC5_CBC_256("RC5", "CBC", "PKCS5Padding", 256),
        RC5_CTR_128("RC5", "CTR", "NoPadding", 128),
        RC5_CTR_192("RC5", "CTR", "NoPadding", 192),
        RC5_CTR_256("RC5", "CTR", "NoPadding", 256),
        RC5_CFB_N_128("RC5", "CFB", "NoPadding", 128),
        RC5_CFB_N_192("RC5", "CFB", "NoPadding", 192),
        RC5_CFB_N_256("RC5", "CFB", "NoPadding", 256),
        RC5_OFB_N_128("RC5", "OFB", "NoPadding", 128),
        RC5_OFB_N_192("RC5", "OFB", "NoPadding", 192),
        RC5_OFB_N_256("RC5", "OFB", "NoPadding", 256),

        // RC6 Algorithms
        RC6_ECB_128("RC6", "ECB", "PKCS5Padding", 128),
        RC6_EBC_192("RC6", "ECB", "PKCS5Padding", 192),
        RC6_ECB_256("RC6", "ECB", "PKCS5Padding", 256),
        RC6_CBC_128("RC6", "CBC", "PKCS5Padding", 128),
        RC6_CBC_192("RC6", "CBC", "PKCS5Padding", 192),
        RC6_CBC_256("RC6", "CBC", "PKCS5Padding", 256),
        RC6_CTR_128("RC6", "CTR", "NoPadding", 128),
        RC6_CTR_192("RC6", "CTR", "NoPadding", 192),
        RC6_CTR_256("RC6", "CTR", "NoPadding", 256),
        RC6_CFB_N_128("RC6", "CFB", "NoPadding", 128),
        RC6_CFB_N_192("RC6", "CFB", "NoPadding", 192),
        RC6_CFB_N_256("RC6", "CFB", "NoPadding", 256),
        RC6_OFB_N_128("RC6", "OFB", "NoPadding", 128),
        RC6_OFB_N_192("RC6", "OFB", "NoPadding", 192),
        RC6_OFB_N_256("RC6", "OFB", "NoPadding", 256),

        // RSA Algorithms
        RSA_PKCS1_1024("RSA", "PKCS1Padding", "", 1024),
        RSA_PKCS1_2048("RSA", "PKCS1Padding", "", 2048),
        RSA_PKCS1_4096("RSA", "PKCS1Padding", "", 4096),
        RSA_NOPAD_1024("RSA", "NoPadding", "", 1024),
        RSA_NOPAD_2048("RSA", "NoPadding", "", 2048),
        RSA_NOPAD_4096("RSA", "NoPadding", "", 4096),

        // SAM Algorithms
        SAM_1024("SAM", "", "", 1024),
        SAM_2048("SAM", "", "", 2048),
        SAM_3072("SAM", "", "", 3072),

        // DH Algorithms
        DH_1024("DH", "", "", 1024),
        DH_2048("DH", "", "", 2048),
        DH_4096("DH", "", "", 4096),

        // ElGamal Algorithms
        ELGAMAL_1024("ELGAMAL", "", "", 1024),
        ELGAMAL_2048("ELGAMAL", "", "", 2048),
        ELGAMAL_4096("ELGAMAL", "", "", 4096),

        // Paillier Algorithms (Hybrid)
        PAILLIER_1024("PAILLIER", "", "", 1024),
        PAILLIER_2048("PAILLIER", "", "", 2048),
        PAILLIER_4096("PAILLIER", "", "", 4096);

        private final String algorithm;
        private final String mode;
        private final String padding;
        private final int keySize;

        AlgorithmType(String algorithm, String mode, String padding, int keySize) {
            this.algorithm = algorithm;
            this.mode = mode;
            this.padding = padding;
            this.keySize = keySize;
        }

        public CryptographicAlgorithm createAlgorithm() throws Exception {
            switch (algorithm) {
                case "AES":
                    return new AES(mode, padding, keySize);
                case "DES":
                    return new DES(mode, padding);
                case "DES3":
                    return new DES3(mode, padding);
                case "BLOWFISH":
                    return new BLOWFISH(mode, padding, keySize);
                case "IDEA":
                    return new IDEA(mode, padding);
                case "RC4":
                    return new RC4(keySize);
                case "RC5":
                    return new RC5(mode, padding, keySize);
                case "RC6":
                    return new RC6(mode, padding, keySize);
                case "RSA":
                    return new RSA(mode, keySize);
                case "SAM":
                    return new SAM(keySize);
                case "DH":
                    return new DH(keySize);
                case "ELGAMAL":
                    return new ELGAMAL(keySize);
                case "PAILLIER":
                    return new PAILLIER(keySize);
                default:
                    throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String variable = "AES_ECB_128"; // Change this to test any algorithm
        AlgorithmType algoType = AlgorithmType.valueOf(variable); // Convert string to enum
        CryptographicAlgorithm algorithm = algoType.createAlgorithm();

        String filePath = "db/test_datasets/plaintext_MB1.txt"; // Change this to your file path
        String plainText = readTextFromFile(filePath);

        System.out.println("Testing " + algoType.name() + ":");
        evaluationTest(algorithm, plainText);
    }

    /**
     * Reads text content from a file.
     * @param filePath The path to the file to read.
     * @return The content of the file as a string.
     * @throws Exception if the file cannot be read.
     */
    public static String readTextFromFile(String filePath) throws Exception {
        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
            return new String(fileBytes);
        } catch (Exception e) {
            throw new Exception("Failed to read file '" + filePath + "': " + e.getMessage());
        }
    }


    /**
     *      Evaluates a cryptographic algorithm's performance and correctness.
     *      @param algorithm The algorithm to test, implementing CryptographicAlgorithm.
     *      @param plainText The plaintext to encrypt and evaluate.
     */
    public static void evaluationTest(CryptographicAlgorithm algorithm, String plainText) {
        try {
            ///     Initialize System Information for - OSHI
            SystemInfo systemInfo = new SystemInfo();
            HardwareAbstractionLayer hardware = systemInfo.getHardware();
            CentralProcessor processor = hardware.getProcessor();
            OperatingSystem os = systemInfo.getOperatingSystem();
            int pid = os.getProcessId();
            OSProcess process = os.getProcess(pid);

            ///     Initialize Path to HWiNFO's CSV log for gathering CPU power.
            String csvPath = "C:\\power_log.csv";// Adjust this to your log file path

            ///     Retrieve power information
            List<PowerSource> powerSources = hardware.getPowerSources();
            for (PowerSource ps : powerSources) {
                double powerUsage = Math.abs(ps.getPowerUsageRate());
                System.out.println("Power Source: " + ps.getName());
                System.out.println("Battery Remaining Capacity: " + ps.getRemainingCapacityPercent() * 100 + "%");
                System.out.println("Battery Power Usage Rate: " + powerUsage + " mW");
                System.out.println("Battery Voltage: " + ps.getVoltage() + " V");
                System.out.println("Battery Amperage: " + ps.getAmperage() + " mA");
                System.out.println("----------------------------------------------------");
            }

            ///     Warm-up phase to stabilize JVM
            for (int i = 0; i < 10; i++) {
                algorithm.encrypt(plainText);
            }

            ///     Number of iterations for measurable load
            int iterations = 1000;
            long totalExecutionTime = 0;
            double totalCpuLoad = 0;
            long totalMemoryUsed = 0;
            double totalCpuPowerWatts = 0.0;
            int validPowerReadings = 0;

            ///     File to save results
            FileWriter writer = new FileWriter("crypto_power_usage.csv");
            writer.write("Iteration,ExecutionTime(ns),CpuLoad(%),MemoryUsed(bytes),CpuPower(W)\n");

            ///     Measure over multiple iterations
            for (int i = 0; i < iterations; i++) {
                long[] ticksBefore = processor.getSystemCpuLoadTicks();
                long memoryBefore = process.getResidentSetSize();
                long startTime = System.nanoTime();

                String cipherText = algorithm.encrypt(plainText);

                long endTime = System.nanoTime();
                process.updateAttributes();

                ///     Get CPU power from HWiNFO's CSV
                double cpuPowerWatts = getLatestCpuPowerFromCsv(csvPath);
                if (cpuPowerWatts != -1) {
                    totalCpuPowerWatts += cpuPowerWatts;
                    validPowerReadings++;
                }

                totalExecutionTime += (endTime - startTime);
                totalCpuLoad += processor.getSystemCpuLoadBetweenTicks(ticksBefore);
                totalMemoryUsed += (process.getResidentSetSize() - memoryBefore);

                // Save to CSV
                writer.write(String.format("%d,%d,%.2f,%d,%.2f\n",
                        i, (endTime - startTime), processor.getSystemCpuLoadBetweenTicks(ticksBefore) * 100,
                        (process.getResidentSetSize() - memoryBefore), cpuPowerWatts));

                ///     Verify correctness (only once, after first iteration)
                if (i == 0) {
                    String decryptedText = algorithm.decrypt(cipherText);
                    boolean isCorrect = decryptedText.equals(plainText);
                    System.out.println("Correctness: " + (isCorrect ? "Pass" : "Fail"));
                }

            }

            writer.close();

            ///     Calculate averages
            long avgExecutionTime = totalExecutionTime / iterations;
            double avgCpuLoad = totalCpuLoad / iterations;
            long avgMemoryUsed = totalMemoryUsed / iterations;

            double avgCpuPowerWatts = (validPowerReadings > 0) ? totalCpuPowerWatts / validPowerReadings : 0;

            double executionTimeSeconds = avgExecutionTime / 1_000_000_000.0;

            double energyJoulesNEW = avgCpuPowerWatts * executionTimeSeconds;


            ///     Output results
            System.out.println("Algorithm: " + algorithm.getAlgorithmName());
            System.out.println("Avg Execution Time: " + avgExecutionTime + " ns");
            System.out.println("Avg CPU Load (OSHI):" + String.format("%.2f%%", avgCpuLoad * 100));
            System.out.println("Avg Memory Used (OSHI): " + avgMemoryUsed + " bytes");

            System.out.println("Avg CPU Power (HWiNFO): " + String.format("%.2f W", avgCpuPowerWatts));
            System.out.println("Estimated Energy: " + String.format("%.4f J", energyJoulesNEW));
            System.out.println("----------------------------------------------------");

        } catch (Exception e) {
            System.err.println("Evaluation failed for " + algorithm.getAlgorithmName() + ": " + e.getMessage());
        }
    }

    /**
     * Reads the latest CPU Package Power from HWiNFO's CSV log.
     * @param csvPath Path to HWiNFO's power_log.csv file.
     * @return CPU power in watts, or -1 if not found.
     */
    public static double getLatestCpuPowerFromCsv(String csvPath) {
        try (BufferedReader br = new BufferedReader(new FileReader(csvPath))) {
            String header = br.readLine();
            if (header == null) {
                System.err.println("CSV file is empty or not found");
                return -1;
            }

            String[] headers = header.split(",");
            int powerColumnIndex = -1;

            for (int i = 0; i < headers.length; i++) {
                String headerTrimmed = headers[i].trim();
                ///      Use exact or safe match — not CPU model strings, for faster use
                if (headerTrimmed.equalsIgnoreCase("CPU Package Power")
                        || headerTrimmed.equalsIgnoreCase("CPU (Total) Package Power")
                        || headerTrimmed.toLowerCase().contains("package power")) {
                    powerColumnIndex = i;
                    break;
                }
            }

            if (powerColumnIndex == -1) {
                System.err.println("CPU Package Power column not found. Headers: " + Arrays.toString(headers));
                return -1;
            }

            String line, lastLine = null;
            while ((line = br.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    lastLine = line;
                }
            }

            if (lastLine == null) {
                System.err.println("No data rows found in CSV");
                return -1;
            }

            String[] values = lastLine.split(",");
            if (powerColumnIndex >= values.length) {
                System.err.println("Power column index out of bounds in last row");
                return -1;
            }

            String powerStr = values[powerColumnIndex].trim().replaceAll("[^0-9.]", "");
            return Double.parseDouble(powerStr);

        } catch (IOException e) {
            System.err.println("Error reading CSV: " + e.getMessage());
        } catch (NumberFormatException e) {
            System.err.println("Power value parsing failed: " + e.getMessage());
        }
        return -1;
    }
}