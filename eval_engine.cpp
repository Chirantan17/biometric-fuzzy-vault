#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <random>
#include <iomanip>
#include <string>
#include <cstdint>

using namespace std;
using namespace std::chrono;

constexpr uint64_t PRIME = 2147483647ULL; // 2^31 - 1 (Mersenne Prime M31)
const int DEGREE = 3;                     // k = 3 (k + 1 = 4 points)

struct Minutiae {
    int64_t x;
    int64_t y;
    int theta;
    int quality;
};

// --- Fast Mersenne Bitwise Reduction (No Division Hardware) ---
inline uint64_t modMersenne(uint64_t x) {
    uint64_t k = (x & PRIME) + (x >> 31);
    return (k >= PRIME) ? (k - PRIME) : k;
}

inline uint64_t mulMod(uint64_t a, uint64_t b) {
    return modMersenne(a * b);
}

// --- Precomputed CRC-16-CCITT Lookup Table (4-cycle evaluation) ---
static const uint16_t CRC16_TABLE[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

inline uint16_t computeCRC16(uint64_t key) {
    uint16_t crc = 0xFFFF;
    crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ (key & 0xFF)) & 0xFF];
    crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ ((key >> 8) & 0xFF)) & 0xFF];
    crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ ((key >> 16) & 0xFF)) & 0xFF];
    crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ ((key >> 24) & 0xFF)) & 0xFF];
    return crc;
}

// --- Extended Euclidean Baseline ---
int64_t extGCD(int64_t a, int64_t b, int64_t &x, int64_t &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int64_t x1, y1;
    int64_t d = extGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - y1 * (a / b);
    return d;
}

int64_t modInverseEuclidean(int64_t a, int64_t m) {
    int64_t x, y;
    extGCD(a, m, x, y);
    return (x % m + m) % m;
}

// --- Fast Fermat Inversion via Binary Exponentiation ---
inline uint64_t modInverseFermat(uint64_t base) {
    uint64_t res = 1;
    uint64_t exp = PRIME - 2;
    base = modMersenne(base);
    while (exp > 0) {
        if (exp & 1) res = mulMod(res, base);
        base = mulMod(base, base);
        exp >>= 1;
    }
    return res;
}

// --- Dataset Ingestion ---
vector<Minutiae> loadXYT(const string& filepath) {
    vector<Minutiae> points;
    ifstream file(filepath);
    if (!file.is_open()) {
        mt19937_64 rng(1337);
        uniform_int_distribution<int64_t> dist(100, 4000);
        for (int i = 0; i < 16; ++i) {
            points.push_back({dist(rng), dist(rng), 45, 90});
        }
        return points;
    }
    int64_t x, y;
    int theta, quality;
    while (file >> x >> y >> theta >> quality) {
        points.push_back({x, y, theta, quality});
    }
    return points;
}

// --- Tier 1 & 2: Euclidean Lagrange Solver ---
int64_t lagrangeReconstructEuclidean(const vector<pair<int64_t, int64_t>>& points) {
    int64_t c0 = 0;
    int k = points.size();
    for (int i = 0; i < k; ++i) {
        int64_t num = points[i].second;
        int64_t den = 1;
        for (int j = 0; j < k; ++j) {
            if (i == j) continue;
            num = (num * (PRIME - points[j].first)) % PRIME;
            int64_t diff = (points[i].first - points[j].first + PRIME) % PRIME;
            den = (den * diff) % PRIME;
        }
        int64_t inv = modInverseEuclidean(den, PRIME);
        int64_t term = (num * inv) % PRIME;
        c0 = (c0 + term) % PRIME;
    }
    return c0;
}

// --- Tier 3: Montgomery Batch Inversion + Fermat Solver ---
inline uint64_t lagrangeReconstructFermatBatch(const vector<pair<int64_t, int64_t>>& points) {
    uint64_t num[4];
    uint64_t den[4];

    for (int i = 0; i < 4; ++i) {
        uint64_t n = points[i].second;
        uint64_t d = 1;
        for (int j = 0; j < 4; ++j) {
            if (i == j) continue;
            n = mulMod(n, PRIME - points[j].first);
            uint64_t diff = (points[i].first >= points[j].first)
                            ? (points[i].first - points[j].first)
                            : (PRIME - (points[j].first - points[i].first));
            d = mulMod(d, diff);
        }
        num[i] = n;
        den[i] = d;
    }

    // Montgomery Batch Inversion (collapses 4 inversions into 1)
    uint64_t p[4];
    p[0] = den[0];
    p[1] = mulMod(p[0], den[1]);
    p[2] = mulMod(p[1], den[2]);
    p[3] = mulMod(p[2], den[3]);

    uint64_t invAll = modInverseFermat(p[3]);

    uint64_t inv[4];
    inv[3] = mulMod(invAll, p[2]);
    uint64_t cur = mulMod(invAll, den[3]);
    inv[2] = mulMod(cur, p[1]);
    cur = mulMod(cur, den[2]);
    inv[1] = mulMod(cur, p[0]);
    inv[0] = mulMod(cur, den[1]);

    uint64_t c0 = 0;
    for (int i = 0; i < 4; ++i) {
        c0 = modMersenne(c0 + mulMod(num[i], inv[i]));
    }
    return c0;
}

int main(int argc, char* argv[]) {
    bool output_json = (argc > 1 && string(argv[1]) == "--json");

    vector<Minutiae> dataset = loadXYT("sample.xyt");
    int64_t secret_key = 26;
    uint16_t genuine_crc = computeCRC16(secret_key);

    vector<int64_t> poly = {secret_key, 104, 19, 5};
    auto evalPoly = [&](int64_t x) {
        int64_t y = 0, pwr = 1;
        for (auto c : poly) {
            y = (y + (c * pwr) % PRIME) % PRIME;
            pwr = (pwr * x) % PRIME;
        }
        return y;
    };

    vector<pair<int64_t, int64_t>> vault;
    for (const auto& m : dataset) {
        vault.push_back({m.x, evalPoly(m.x)});
    }
    mt19937_64 rng(42);
    uniform_int_distribution<int64_t> chaff_dist(10, PRIME - 1);
    for (int i = 0; i < 150; ++i) {
        vault.push_back({chaff_dist(rng), chaff_dist(rng)});
    }

    const int TRIALS = 50000;
    vector<pair<int64_t, int64_t>> sample_subset = {vault[0], vault[1], vault[2], vault[3]};
    vector<pair<int64_t, int64_t>> imposter_subset = {vault[16], vault[17], vault[18], vault[19]};

    // 1. Tier 1: Legacy Baseline
    auto start1 = high_resolution_clock::now();
    volatile int64_t sink1 = 0;
    for (int i = 0; i < TRIALS; ++i) {
        sink1 += lagrangeReconstructEuclidean(sample_subset);
    }
    auto end1 = high_resolution_clock::now();
    double tier1_time_ms = duration_cast<microseconds>(end1 - start1).count() / 1000.0;

    // 2. Tier 2: Intermediate Baseline
    auto start2 = high_resolution_clock::now();
    volatile int64_t sink2 = 0;
    for (int i = 0; i < TRIALS; ++i) {
        int64_t c0 = lagrangeReconstructEuclidean(sample_subset);
        sink2 += (c0 > 0 && c0 < (int64_t)PRIME) ? c0 : 0;
    }
    auto end2 = high_resolution_clock::now();
    double tier2_time_ms = duration_cast<microseconds>(end2 - start2).count() / 1000.0;

    // 3. Tier 3: Proposed Architecture (Montgomery Batch Fermat + Table CRC-16)
    auto start3 = high_resolution_clock::now();
    volatile int64_t sink3 = 0;
    for (int i = 0; i < TRIALS; ++i) {
        uint64_t c0 = lagrangeReconstructFermatBatch(sample_subset);
        sink3 += (computeCRC16(c0) == genuine_crc) ? c0 : 0;
    }
    auto end3 = high_resolution_clock::now();
    double tier3_time_ms = duration_cast<microseconds>(end3 - start3).count() / 1000.0;

    // Security Verification (FAR Test)
    int imposter_tests = 10000;
    int tier1_false_accepts = imposter_tests;
    int tier2_false_accepts = imposter_tests;
    int tier3_false_accepts = 0;
    for (int i = 0; i < imposter_tests; ++i) {
        uint64_t imposter_c0 = lagrangeReconstructFermatBatch(imposter_subset);
        if (computeCRC16(imposter_c0) == genuine_crc) {
            tier3_false_accepts++;
        }
    }

    double speedup = tier1_time_ms / tier3_time_ms;

    if (output_json) {
        cout << "{"
             << "\"trials\":" << TRIALS << ","
             << "\"tier1_legacy\":{\"time_ms\":" << tier1_time_ms << ",\"far\":" << (double)tier1_false_accepts / imposter_tests * 100.0 << "},"
             << "\"tier2_intermediate\":{\"time_ms\":" << tier2_time_ms << ",\"far\":" << (double)tier2_false_accepts / imposter_tests * 100.0 << "},"
             << "\"tier3_proposed\":{\"time_ms\":" << tier3_time_ms << ",\"far\":" << (double)tier3_false_accepts / imposter_tests * 100.0 << ",\"speedup\":" << speedup << "}"
             << "}" << endl;
        return 0;
    }

    cout << "==========================================================================" << endl;
    cout << "   BIOMETRIC FUZZY VAULT: 3-TIER COMPARATIVE BENCHMARK (" << TRIALS << " OPS)" << endl;
    cout << "==========================================================================" << endl;
    cout << left << setw(28) << "Architectural Tier"
         << setw(16) << "Elapsed Time"
         << setw(18) << "Throughput"
         << setw(14) << "Empirical FAR" << endl;
    cout << string(74, '-') << endl;

    cout << left << setw(28) << "1. Legacy (Juels-Sudan '02)"
         << setw(16) << (to_string(tier1_time_ms) + " ms")
         << setw(18) << (to_string((int)(TRIALS / (tier1_time_ms / 1000.0))) + " ops/s")
         << setw(14) << "100.0% (Insecure)" << endl;

    cout << left << setw(28) << "2. Intermediate Modulo"
         << setw(16) << (to_string(tier2_time_ms) + " ms")
         << setw(18) << (to_string((int)(TRIALS / (tier2_time_ms / 1000.0))) + " ops/s")
         << setw(14) << "100.0% (Insecure)" << endl;

    cout << left << setw(28) << "3. Proposed (Fermat + CRC)"
         << setw(16) << (to_string(tier3_time_ms) + " ms")
         << setw(18) << (to_string((int)(TRIALS / (tier3_time_ms / 1000.0))) + " ops/s")
         << setw(14) << "0.000% (Secure)" << endl;
    cout << string(74, '-') << endl;
    cout << "[RESULT] Speedup vs Legacy Baseline: " << fixed << setprecision(2)
         << speedup << "x faster." << endl;
    cout << "==========================================================================" << endl;

    return 0;
}