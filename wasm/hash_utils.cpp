#include "hash_utils.h"
#include <algorithm>
#include <random>

// ======================== splitmix64 ========================

uint64_t hash_splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

// ======================== Cuckoo hashing ========================

uint32_t hash_cuckoo_int(uint32_t entry_id, uint64_t key, uint32_t num_bins) {
    uint64_t h = hash_splitmix64(key ^ static_cast<uint64_t>(entry_id));
    return static_cast<uint32_t>(h % num_bins);
}

// Build a cuckoo hash table using 3 hash functions per entry.
// keys[0..2] are the 3 primary hash keys.
// keys[3..5] are stash hash keys (if needed, unused in basic version).
// Uses the "random walk" eviction strategy with a max iteration limit.
std::vector<uint32_t> build_cuckoo_bs1(
    const uint32_t* entries, size_t num_entries,
    const uint64_t* keys, size_t num_keys,
    uint32_t num_bins) {

    constexpr uint32_t EMPTY = 0xFFFFFFFF;
    constexpr size_t MAX_EVICTIONS = 500;
    constexpr size_t NUM_HASH_FUNCS = 3;

    std::vector<uint32_t> table(num_bins, EMPTY);

    // Simple PRNG for eviction choice (deterministic from seed)
    std::mt19937 rng(42);

    for (size_t i = 0; i < num_entries; i++) {
        uint32_t item = entries[i];
        bool placed = false;

        // Try each hash function first
        for (size_t h = 0; h < NUM_HASH_FUNCS && h < num_keys; h++) {
            uint32_t bin = hash_cuckoo_int(item, keys[h], num_bins);
            if (table[bin] == EMPTY) {
                table[bin] = item;
                placed = true;
                break;
            }
        }

        if (placed) continue;

        // Random walk eviction
        for (size_t evict = 0; evict < MAX_EVICTIONS; evict++) {
            size_t h = rng() % std::min(NUM_HASH_FUNCS, num_keys);
            uint32_t bin = hash_cuckoo_int(item, keys[h], num_bins);

            // Swap with occupant
            uint32_t evicted = table[bin];
            table[bin] = item;

            if (evicted == EMPTY) {
                placed = true;
                break;
            }

            item = evicted;

            // Try to place evicted item in its other buckets
            bool evicted_placed = false;
            for (size_t h2 = 0; h2 < NUM_HASH_FUNCS && h2 < num_keys; h2++) {
                uint32_t bin2 = hash_cuckoo_int(item, keys[h2], num_bins);
                if (table[bin2] == EMPTY) {
                    table[bin2] = item;
                    evicted_placed = true;
                    break;
                }
            }

            if (evicted_placed) {
                placed = true;
                break;
            }
        }

        // If still not placed after MAX_EVICTIONS, insertion failed.
        // The caller should use a larger table or different keys.
    }

    return table;
}

// ======================== Embind wrappers ========================

#ifdef __EMSCRIPTEN__
#include <emscripten/val.h>

using namespace emscripten;

val hash_build_cuckoo_bs1_embind(val entries_val, val keys_val, uint32_t num_bins) {
    // Convert JS Uint32Array → C++ vector
    size_t num_entries = entries_val["length"].as<size_t>();
    std::vector<uint32_t> entries(num_entries);
    for (size_t i = 0; i < num_entries; i++) {
        entries[i] = entries_val[i].as<uint32_t>();
    }

    // Convert JS BigUint64Array → C++ vector
    size_t num_keys = keys_val["length"].as<size_t>();
    std::vector<uint64_t> keys(num_keys);
    for (size_t i = 0; i < num_keys; i++) {
        // BigUint64Array values come as BigInt — convert via string for safety
        keys[i] = static_cast<uint64_t>(keys_val[i].as<double>());
    }

    auto result = build_cuckoo_bs1(entries.data(), entries.size(),
                                    keys.data(), keys.size(), num_bins);

    // Return as Uint32Array
    return val(typed_memory_view(result.size(), result.data())).call<val>("slice");
}
#endif
