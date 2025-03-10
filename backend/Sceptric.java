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
import java.util.List;

public class Sceptric {

    public static void main(String[] args) throws Exception {

        // Manual test example
        CryptographicAlgorithm algorithm1 = new RSA("OAEPWithSHA-256AndMGF1Padding", 1024);
        CryptographicAlgorithm algorithm2 = new AES("ECB", "PKCS5Padding", 128);
        String plainText = "Hello, World!";
        SystemInfo si = new SystemInfo();
        String cpuName = si.getHardware().getProcessor().getProcessorIdentifier().getName().trim();
        System.out.println("CPU: " + cpuName);
        evaluationTest(algorithm1, plainText);
        System.out.println("---------------------------------------------------------------------------------------------");
        evaluationTest(algorithm2, plainText);
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
            double totalPowerUsed = 0;

            ///     Measure over multiple iterations
            for (int i = 0; i < iterations; i++) {
                long[] ticksBefore = processor.getSystemCpuLoadTicks();
                long memoryBefore = process.getResidentSetSize();
                long startTime = System.nanoTime();

                String cipherText = algorithm.encrypt(plainText);

                long endTime = System.nanoTime();
                process.updateAttributes();

                totalExecutionTime += (endTime - startTime);
                totalCpuLoad += processor.getSystemCpuLoadBetweenTicks(ticksBefore);
                totalMemoryUsed += (process.getResidentSetSize() - memoryBefore);

                ///     Estimate power usage
                for (PowerSource ps : powerSources) {
                    totalPowerUsed += Math.abs(ps.getPowerUsageRate());
                }

                ///     Verify correctness (only once, after first iteration)
                if (i == 0) {
                    String decryptedText = algorithm.decrypt(cipherText);
                    boolean isCorrect = decryptedText.equals(plainText);
                    System.out.println("Correctness: " + (isCorrect ? "Pass" : "Fail"));
                    System.out.println("Original: " + plainText);
                    System.out.println("Encrypted: " + cipherText);
                    System.out.println("Decrypted: " + decryptedText);
                }
            }

            ///     Calculate averages
            long avgExecutionTime = totalExecutionTime / iterations;
            double avgCpuLoad = totalCpuLoad / iterations;
            long avgMemoryUsed = totalMemoryUsed / iterations;
            double avgPowerUsage = totalPowerUsed / iterations;
            double executionTimeSeconds = avgExecutionTime / 1_000_000_000.0;
            double energyJoules = avgPowerUsage * executionTimeSeconds;


            ///     Output results
            System.out.println("Algorithm: " + algorithm.getAlgorithmName());
            System.out.println("Avg Execution Time: " + avgExecutionTime + " ns");
            System.out.println("Avg CPU Load: " + String.format("%.2f%%", avgCpuLoad * 100));
            System.out.println("Avg Memory Used: " + avgMemoryUsed + " bytes");
            System.out.println("Avg Power Usage: " + avgPowerUsage + " mW");
            System.out.println("Estimated Energy (Joules): " + String.format("%.4f J", energyJoules));
            System.out.println("----------------------------------------------------");

        } catch (Exception e) {
            System.err.println("Evaluation failed for " + algorithm.getAlgorithmName() + ": " + e.getMessage());
        }
    }
}