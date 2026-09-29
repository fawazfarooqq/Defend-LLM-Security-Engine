# 5-Minute Demo Script

### 1. Explain the problem
“An LLM may receive instructions from untrusted user text or retrieved documents. The security boundary must therefore exist outside the model.”

### 2. Show the vulnerable path
Turn guardrails off and use the poisoned HR document. The deterministic simulator demonstrates the unsafe path without requiring a real provider or credential.

### 3. Show the defended path
Turn guardrails on. Direct injection is stopped at Layer 1. Indirect canary leakage is stopped at Layer 4.

### 4. Show observability
Open the incident endpoint or UI and explain severity, vector, timestamp, and reason.

### 5. Run the benchmark
Run all 10 deterministic vectors. Explain that the results measure this simulator and configured rules—not the security of a real LLM provider.
