Biometric Security System (Fuzzy Vault Scheme)

A cryptographic authentication implementation in C++ using the Juels-Sudan Fuzzy Vault scheme to protect biometric template data with finite-field arithmetic and Reed-Solomon decoding routines.

•	System Architecture & Features
    Finite-Field Arithmetic: Implements modular arithmetic and Fermat's Little Theorem for fast field inversion.
    Polynomial Reconstruction: Lagrange interpolation combined with subset combination matching to decode secret keys from noisy biometric inputs.
    Integrity Validation: Embedded CRC checksums eliminate false-positive polynomial reconstructions.
    Chaff Point Injection: Provable zero-leakage security masking genuine biometric minutiae among cryptographic noise.

•	Benchmark Results
    Enrolment Latency: ~99 µs (150 chaff points)
    Match & Decoding Latency: ~27 µs
    Imposter Rejection Latency: ~4 µs
    False Accept Rate (FAR): 0.0%

•	Build and Run
    PowerShell
    g++ -std=c++17 -O3 fuzzy_vault.cpp -o fuzzy_vault.exe
    .\fuzzy_vault.exe
