# Biometric Security System (Fuzzy Vault Scheme)

[![Live Demo](https://img.shields.io/badge/Demo-GitHub%20Pages-38bdf8?style=flat-square&logo=github)](https://chirantan17.github.io/biometric-fuzzy-vault/)
[![Language](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=c%2B%2B)](https://isocpp.org/)

An end-to-end cryptographic authentication engine implementing the **Juels-Sudan Fuzzy Vault** scheme in C++ to secure biometric template data using finite-field arithmetic and Reed-Solomon polynomial reconstruction.

👉 **[Launch Interactive Web Sandbox](https://chirantan17.github.io/biometric-fuzzy-vault/)**

---

## System Architecture

```mermaid
flowchart TD
    subgraph Enrollment ["1. Vault Enrollment (Locking)"]
        A[Biometric Minutiae Features] --> B[Generate Secret Poly p(x)]
        B --> C[Evaluate Genuine Points (x, p(x))]
        D[Chaff Point Generator] --> E[Noise Points (x_fake, y_fake)]
        C & E --> F[Vault Set V = Genuine + Chaff]
        F --> G[Randomized Shuffling]
    end

    subgraph Authentication ["2. Authentication (Unlocking)"]
        H[Query Biometric Sample] --> I[Filter Candidate Set V_match]
        I --> J{Overlap >= k+1?}
        J -- No --> K[Reject: Imposter / Insufficient Overlap]
        J -- Yes --> L[Combinatorial Lagrange Reconstruction]
        L --> M{CRC Integrity Check Passed?}
        M -- Yes --> N[Unlock: Secret Key Recovered]
        M -- No --> O[Next Subset Combination]
        O --> L
    end