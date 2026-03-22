// OnionPIR WASM Client — Emscripten embind bindings.
// Wraps PirClient directly (bypasses the FFI layer to avoid server.cpp dependencies).

#include <emscripten/bind.h>
#include <emscripten/val.h>
#include "client.h"
#include "pir.h"
#include "hash_utils.h"

#include <sstream>
#include <vector>
#include <cstdint>

using namespace emscripten;

// ======================== Helpers ========================

// Convert a stringstream to a JS Uint8Array (copies data out of WASM heap)
static val stream_to_uint8array(std::stringstream &ss) {
    ss.seekg(0, std::ios::end);
    size_t size = ss.tellg();
    ss.seekg(0);
    std::vector<uint8_t> buf(size);
    ss.read(reinterpret_cast<char *>(buf.data()), size);
    return val(typed_memory_view(buf.size(), buf.data())).call<val>("slice");
}

// Convert a JS Uint8Array (passed as val) to a stringstream
static std::stringstream uint8array_to_stream(const val &arr) {
    std::vector<uint8_t> buf = convertJSArrayToNumberVector<uint8_t>(arr);
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    ss.seekg(0);
    return ss;
}

// ======================== OnionPirWasmClient ========================

class OnionPirWasmClient {
public:
    OnionPirWasmClient(uint32_t num_entries)
        : params_(static_cast<size_t>(num_entries)), client_(params_) {}

    // Get the unique client ID (used for server key registration)
    double id() const {
        // Return as double since JS numbers can represent up to 2^53 safely,
        // and client IDs are small.
        return static_cast<double>(client_.get_client_id());
    }

    // Generate Galois keys (serialized bytes for the server)
    val generateGaloisKeys() {
        std::stringstream ss;
        client_.create_galois_keys(ss);
        return stream_to_uint8array(ss);
    }

    // Generate GSW keys (serialized bytes for the server)
    val generateGswKeys() {
        auto gsw = client_.generate_gsw_from_key();
        std::stringstream ss;
        PirClient::write_gsw_to_stream(gsw, ss);
        return stream_to_uint8array(ss);
    }

    // Generate a PIR query for entry at index
    val generateQuery(uint32_t entry_index) {
        auto ct = client_.fast_generate_query(static_cast<size_t>(entry_index));
        std::stringstream ss;
        PirClient::write_query_to_stream(ct, ss);
        return stream_to_uint8array(ss);
    }

    // Decrypt server response → plaintext entry bytes
    val decryptResponse(uint32_t entry_index, val response_arr) {
        auto resp_stream = uint8array_to_stream(response_arr);
        auto ct = client_.load_resp_from_stream(resp_stream);
        auto pt = client_.decrypt_reply(ct);
        auto entry = client_.get_entry_from_plaintext(
            static_cast<size_t>(entry_index), pt);
        return val(typed_memory_view(entry.size(), entry.data())).call<val>("slice");
    }

private:
    PirParams params_;
    PirClient client_;
};

// ======================== Params info ========================

val paramsInfo(uint32_t num_entries) {
    PirParams params(static_cast<size_t>(num_entries));
    val obj = val::object();
    obj.set("numEntries", static_cast<uint32_t>(params.get_num_entries()));
    obj.set("entrySize", static_cast<uint32_t>(params.get_entry_size()));
    obj.set("numPlaintexts", static_cast<uint32_t>(params.get_num_pt()));
    obj.set("fstDimSz", static_cast<uint32_t>(params.get_fst_dim_sz()));
    obj.set("otherDimSz", static_cast<uint32_t>(params.get_other_dim_sz()));
    obj.set("coeffValCnt", static_cast<uint32_t>(params.get_coeff_val_cnt()));
    return obj;
}

// ======================== Hash utility wrappers ========================

// splitmix64: accepts and returns double since JS BigInt <-> C++ uint64_t
// is awkward in embind. Callers should use Number if within safe range,
// or use the string-based variant for full 64-bit precision.
double splitmix64_wrapper(double x) {
    uint64_t input = static_cast<uint64_t>(x);
    uint64_t result = hash_splitmix64(input);
    return static_cast<double>(result);
}

double cuckoo_hash_int_wrapper(uint32_t entry_id, double key, uint32_t num_bins) {
    uint64_t key_u64 = static_cast<uint64_t>(key);
    return static_cast<double>(hash_cuckoo_int(entry_id, key_u64, num_bins));
}

// ======================== Embind registrations ========================

EMSCRIPTEN_BINDINGS(onionpir_client) {
    class_<OnionPirWasmClient>("OnionPirClient")
        .constructor<uint32_t>()
        .function("id", &OnionPirWasmClient::id)
        .function("generateGaloisKeys", &OnionPirWasmClient::generateGaloisKeys)
        .function("generateGswKeys", &OnionPirWasmClient::generateGswKeys)
        .function("generateQuery", &OnionPirWasmClient::generateQuery)
        .function("decryptResponse", &OnionPirWasmClient::decryptResponse);

    function("paramsInfo", &paramsInfo);
    function("splitmix64", &splitmix64_wrapper);
    function("cuckooHashInt", &cuckoo_hash_int_wrapper);
    function("buildCuckooBs1", &hash_build_cuckoo_bs1_embind);
}
