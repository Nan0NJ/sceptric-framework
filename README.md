# Sceptric Framework

**Sceptric** (Systematic Cryptographic Encryption Performance Testing, Rigorous Integrated Comparison) is a Java-based framework for benchmarking cryptographic algorithms.

It evaluates the performance of **symmetric** and **asymmetric** ciphers across key metrics:
- Execution time
- CPU usage
- Memory usage
- Energy consumption *(optional via HWiNFO)*

## 🔧 How to Run

1. **Clone and build**:
   ```bash
   git clone https://github.com/YourUsername/sceptric-framework.git
   cd sceptric-framework
   mvn clean package
   ```

2. **(Optional) Set up HWiNFO for energy measurement**:
   - Download and install [HWiNFO64](https://www.hwinfo.com/download/)
   - Run it in **Sensors-only** mode
   - Enable **Shared Memory Support** in settings
   - Ensure `CPU Package Power` is visible in the sensor layout
   - Configure logging to output to `C:\power_log.csv`
   - Make sure the path matches what is referenced in `backend/Sceptric.java`

3. **Run**:
   ```bash
   java -jar target/sceptric-framework-1.0.jar
   ```
   *(Or run `SceptricApplication.java` from an IDE)*

## 📂 Key Paths

- Benchmark logic: [`backend/Sceptric.java`](backend/Sceptric.java)
- Algorithm tested:
  - Symmetric: [`backend/algorithms/symmetric/`](backend/algorithms/symmetric/)
  - Asymmetric: [`backend/algorithms/asymmetric/`](backend/algorithms/asymmetric/)
- Input data: [`db/test_datasets/`](db/test_datasets/)
- Results DB: [`db/results_database/performance.db`](db/results_database/)
- Analysis logic: [`python_scripts/analysis/`](python_scripts/analysis/)
   - Resulting output: [`charts/`](charts/)

## 📊 Output

Results are stored in:
- **CSV log** (`crypto_power_usage.csv`)
- **SQLite DB** (`performance.db`) with iteration data and summary stats

## 🧪 Algorithms Included

- **Symmetric**: AES, DES, Blowfish, IDEA, RC4, RC5, RC6
- **Asymmetric**: RSA, Diffie-Hellman, ElGamal, Paillier
- **Hybrid**: SAM Protocol (DSA + AES)

## 📜 License

MIT License. See [LICENSE](LICENSE).

---
**Made for practical testing and research in cryptographic performance.**
