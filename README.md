# sceptric-framework
Systematic Cryptographic Encryption Performance Testing, Rigorous Integrated Comparison Framework


## 🧪 Energy-Aware Cryptographic Algorithm Evaluator

This tool benchmarks symmetric/asymmetric crypto algorithms and correlates them with real-time CPU power usage using data from HWiNFO.

### 🔧 Requirements

- Java 17+
- Maven
- [HWiNFO](https://www.hwinfo.com/download/) (for power logging)

### 🚀 How to Use

1. Start HWiNFO and enable CSV logging.
2. Ensure `"CPU Package Power"` is logged at 1-second intervals.
3. Run:

```bash
mvn clean package
java -jar target/sceptric-framework.jar
