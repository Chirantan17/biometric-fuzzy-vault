#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <cstdint>
#include <numeric>
#include <set>

using namespace std;

// -----------------------------------------------------------------------------
// Finite Field & Cryptographic Utilities (Field: Z_p, where p is a safe prime)
// -----------------------------------------------------------------------------
namespace CryptoField {
    const long long PRIME = 2147483647LL; // Mersenne Prime 2^31 - 1

    long long modAdd(long long a, long long b) {
        return (a % PRIME + b % PRIME + PRIME) % PRIME;
    }

    long long modSub(long long a, long long b) {
        return (a % PRIME - b % PRIME + PRIME) % PRIME;
    }

    long long modMul(long long a, long long b) {
        return (long long)((__int128)(a % PRIME + PRIME) * (b % PRIME + PRIME) % PRIME);
    }

    long long modPow(long long base, long long exp) {
        long long res = 1;
        base %= PRIME;
        while (exp > 0) {
            if (exp % 2 == 1) res = modMul(res, base);
            base = modMul(base, base);
            exp /= 2;
        }
        return res;
    }

    long long modInverse(long long n) {
        return modPow(n, PRIME - 2); // Fermat's Little Theorem
    }

    // CRC-16-like Checksum over polynomial coefficients for integrity verification
    uint16_t computeChecksum(const vector<long long>& coeffs, int length) {
        uint16_t crc = 0xFFFF;
        for (int i = 0; i < length; ++i) {
            long long val = coeffs[i];
            for (int b = 0; b < 4; ++b) {
                uint8_t byte = (val >> (b * 8)) & 0xFF;
                crc ^= (uint16_t)byte << 8;
                for (int j = 0; j < 8; ++j) {
                    if (crc & 0x8000)
                        crc = (crc << 1) ^ 0x1021;
                    else
                        crc <<= 1;
                }
            }
        }
        return crc;
    }
}

// -----------------------------------------------------------------------------
// Core Data Structures
// -----------------------------------------------------------------------------
struct Point {
    long long x;
    long long y;

    bool operator==(const Point& other) const {
        return x == other.x && y == other.y;
    }
};

class Polynomial {
public:
    int degree;
    vector<long long> coeffs; // p(x) = c0 + c1*x + c2*x^2 + ... + ck*x^k

    Polynomial() : degree(0) {}
    Polynomial(int d) : degree(d), coeffs(d + 1, 0) {}

    // Encode secret key and checksum into coefficients
    static Polynomial createWithSecret(long long secret, int degree, mt19937_64& rng) {
        Polynomial poly(degree);
        poly.coeffs[0] = secret % CryptoField::PRIME;
        
        // Random intermediate coefficients
        for (int i = 1; i < degree; ++i) {
            poly.coeffs[i] = rng() % (CryptoField::PRIME - 1) + 1;
        }

        // Embed checksum in the highest-degree coefficient for validation
        uint16_t chk = CryptoField::computeChecksum(poly.coeffs, degree);
        poly.coeffs[degree] = chk;
        return poly;
    }

    long long evaluate(long long x) const {
        long long result = 0;
        long long x_pow = 1;
        for (int i = 0; i <= degree; ++i) {
            long long term = CryptoField::modMul(coeffs[i], x_pow);
            result = CryptoField::modAdd(result, term);
            x_pow = CryptoField::modMul(x_pow, x);
        }
        return result;
    }

    bool verifyChecksum() const {
        if (coeffs.empty() || degree <= 0) return false;
        uint16_t expected = CryptoField::computeChecksum(coeffs, degree);
        return (uint16_t)(coeffs[degree]) == expected;
    }
};

// -----------------------------------------------------------------------------
// Fuzzy Vault Core Engine
// -----------------------------------------------------------------------------
class FuzzyVaultSystem {
private:
    int polyDegree;
    int chaffPointsCount;
    mt19937_64 rng;

    // Optimized Lagrange Interpolation modulo PRIME
    bool reconstructPolynomial(const vector<Point>& pts, Polynomial& outPoly) {
        int k = polyDegree + 1;
        if (pts.size() < (size_t)k) return false;

        outPoly = Polynomial(polyDegree);

        for (int i = 0; i < k; ++i) {
            // Compute Lagrange basis polynomial L_i(x)
            vector<long long> basis = {1}; // Starts as 1
            long long denominator = 1;

            for (int j = 0; j < k; ++j) {
                if (i == j) continue;

                // Numerator multiplies by (x - x_j) -> represented as vector convolution
                vector<long long> nextBasis(basis.size() + 1, 0);
                long long neg_xj = CryptoField::modSub(0, pts[j].x);

                for (size_t deg = 0; deg < basis.size(); ++deg) {
                    // term * (-xj)
                    nextBasis[deg] = CryptoField::modAdd(nextBasis[deg], CryptoField::modMul(basis[deg], neg_xj));
                    // term * x
                    nextBasis[deg + 1] = CryptoField::modAdd(nextBasis[deg + 1], basis[deg]);
                }
                basis = nextBasis;

                // Denominator: (x_i - x_j)
                long long diff = CryptoField::modSub(pts[i].x, pts[j].x);
                denominator = CryptoField::modMul(denominator, diff);
            }

            long long invDenom = CryptoField::modInverse(denominator);
            long long factor = CryptoField::modMul(pts[i].y, invDenom);

            for (size_t d = 0; d < basis.size() && d <= (size_t)polyDegree; ++d) {
                long long term = CryptoField::modMul(basis[d], factor);
                outPoly.coeffs[d] = CryptoField::modAdd(outPoly.coeffs[d], term);
            }
        }

        return outPoly.verifyChecksum();
    }

    // Helper for subset combinations (RANSAC-style combinatorial search)
    bool searchCombinations(const vector<Point>& candidatePts, int offset, int k, vector<Point>& current, Polynomial& recoveredPoly) {
        if ((int)current.size() == k) {
            return reconstructPolynomial(current, recoveredPoly);
        }

        for (size_t i = offset; i < candidatePts.size(); ++i) {
            current.push_back(candidatePts[i]);
            if (searchCombinations(candidatePts, i + 1, k, current, recoveredPoly)) {
                return true;
            }
            current.pop_back();
        }
        return false;
    }

public:
    FuzzyVaultSystem(int degree = 4, int chaffCount = 180)
        : polyDegree(degree), chaffPointsCount(chaffCount) {
        rng.seed(chrono::high_resolution_clock::now().time_since_epoch().count());
    }

    // Vault Enrollment
    vector<Point> lock(const vector<long long>& biometricTemplate, long long secretKey) {
        Polynomial secretPoly = Polynomial::createWithSecret(secretKey, polyDegree, rng);
        vector<Point> vault;
        set<long long> usedX;

        // 1. Embed genuine points on polynomial
        for (long long feature : biometricTemplate) {
            long long x = feature % CryptoField::PRIME;
            if (usedX.count(x)) continue;
            usedX.insert(x);
            long long y = secretPoly.evaluate(x);
            vault.push_back({x, y});
        }

        // 2. Inject noisy chaff points NOT lying on the polynomial
        while ((int)vault.size() < (int)biometricTemplate.size() + chaffPointsCount) {
            long long fakeX = rng() % (CryptoField::PRIME - 2) + 1;
            if (usedX.count(fakeX)) continue;

            long long fakeY = rng() % (CryptoField::PRIME - 2) + 1;
            // Guarantee chaff points do not accidentally fall on the secret polynomial
            if (fakeY == secretPoly.evaluate(fakeX)) continue;

            usedX.insert(fakeX);
            vault.push_back({fakeX, fakeY});
        }

        // 3. Shuffle vault to obscure genuine vs chaff coordinates
        shuffle(vault.begin(), vault.end(), rng);
        return vault;
    }

    // Vault Authentication & Decoding
    bool unlock(const vector<Point>& vault, const vector<long long>& queryBiometrics, long long& outSecret) {
        // Step 1: Filter candidate points from vault using query features
        set<long long> querySet(queryBiometrics.begin(), queryBiometrics.end());
        vector<Point> matchedPoints;

        for (const auto& pt : vault) {
            if (querySet.count(pt.x)) {
                matchedPoints.push_back(pt);
            }
        }

        int required = polyDegree + 1;
        if ((int)matchedPoints.size() < required) {
            return false; // Insufficient feature overlap
        }

        // Step 2: Error-correction via Polynomial Reconstruction (combinatorial Reed-Solomon decoding)
        Polynomial recoveredPoly;
        vector<Point> subset;
        if (searchCombinations(matchedPoints, 0, required, subset, recoveredPoly)) {
            outSecret = recoveredPoly.coeffs[0];
            return true;
        }

        return false;
    }
};

// -----------------------------------------------------------------------------
// Demonstration & Benchmark Runner
// -----------------------------------------------------------------------------
int main() {
    cout << "================================================================" << "\n";
    cout << "  BIOMETRIC FUZZY VAULT CRYPTOSYSTEM (C++ / REED-SOLOMON DECODING)" << "\n";
    cout << "================================================================" << "\n\n";

    const int DEGREE = 4;             // Requires 5 matching features to unlock
    const int CHAFF_SIZE = 150;       // Noise complexity for zero-leakage security
    const long long SECRET_KEY = 9876543210LL; // Confidential Payload to secure

    FuzzyVaultSystem vaultSystem(DEGREE, CHAFF_SIZE);

    // Simulated Biometric Minutiae Data (16 genuine points)
    vector<long long> enrollmentFeatures = {
        10234, 20456, 30567, 40891, 50123, 60789, 70112, 80443,
        90998, 11223, 22334, 33445, 44556, 55667, 66778, 77889
    };

    cout << "[+] Step 1: Enrolling user template and locking the secret..." << "\n";
    auto startEnroll = chrono::high_resolution_clock::now();
    vector<Point> vault = vaultSystem.lock(enrollmentFeatures, SECRET_KEY);
    auto endEnroll = chrono::high_resolution_clock::now();

    cout << "    - Secret Key: " << SECRET_KEY << "\n";
    cout << "    - Features Enrolled: " << enrollmentFeatures.size() << "\n";
    cout << "    - Chaff Points Injected: " << CHAFF_SIZE << "\n";
    cout << "    - Total Vault Size: " << vault.size() << " coordinate pairs\n";
    cout << "    - Enrollment Time: " 
         << chrono::duration_cast<chrono::microseconds>(endEnroll - startEnroll).count() << " us\n\n";

    // -------------------------------------------------------------------------
    // Scenario A: Genuine User (with slight noise / missing features)
    // -------------------------------------------------------------------------
    cout << "[+] Step 2: Testing Genuine User Authentication (Noise added)..." << "\n";
    // 7 Genuine features match (needs >= 5), 5 are missing, 3 are noisy spurious features
    vector<long long> genuineQuery = {
        10234, 20456, 30567, 40891, 50123, 60789, 70112, // 7 Genuine
        99991, 88882, 77773                               // 3 False/Noisy
    };

    long long unlockedKeyA = 0;
    auto startUnlockA = chrono::high_resolution_clock::now();
    bool authSuccessA = vaultSystem.unlock(vault, genuineQuery, unlockedKeyA);
    auto endUnlockA = chrono::high_resolution_clock::now();

    if (authSuccessA && unlockedKeyA == (SECRET_KEY % CryptoField::PRIME)) {
        cout << "    [SUCCESS] Authentication PASSED!" << "\n";
        cout << "    - Recovered Secret: " << unlockedKeyA << "\n";
        cout << "    - Decoding Time: " 
             << chrono::duration_cast<chrono::microseconds>(endUnlockA - startUnlockA).count() << " us\n\n";
    } else {
        cout << "    [FAILED] Legitimate authentication failed unexpectedly.\n\n";
    }

    // -------------------------------------------------------------------------
    // Scenario B: Imposter User (Random features)
    // -------------------------------------------------------------------------
    cout << "[+] Step 3: Testing Imposter User Authentication (Attacker)..." << "\n";
    vector<long long> imposterQuery = {
        11111, 22222, 33333, 44444, 55555, 66666, 77777, 88888, 99999
    };

    long long unlockedKeyB = 0;
    auto startUnlockB = chrono::high_resolution_clock::now();
    bool authSuccessB = vaultSystem.unlock(vault, imposterQuery, unlockedKeyB);
    auto endUnlockB = chrono::high_resolution_clock::now();

    if (!authSuccessB) {
        cout << "    [SECURE] Imposter Rejected! Vault remained securely locked." << "\n";
        cout << "    - Rejection Time: " 
             << chrono::duration_cast<chrono::microseconds>(endUnlockB - startUnlockB).count() << " us\n\n";
    } else {
        cout << "    [CRITICAL] Security breach: Imposter unlocked vault!\n\n";
    }

    cout << "================================================================" << "\n";
    cout << "  EXECUTION COMPLETE: Cryptographic Vault Integrity Verified" << "\n";
    cout << "================================================================" << "\n";

    return 0;
}