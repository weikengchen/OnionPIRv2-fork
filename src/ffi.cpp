// OnionPIRv2 FFI — implements the C++ side of the cxx bridge.
//
// Each function wraps the internal PirServer / PirClient classes,
// converting SEAL's stringstream serialization to/from flat byte vectors.

#include "ffi.h"
#include "server.h"
#include "client.h"
#include "pir.h"
#include "database_constants.h"

#include <sstream>
#include <cstring>
#include <stdexcept>

// ======================== Opaque wrapper definitions ========================

class OnionPirServer {
public:
  PirParams params;
  PirServer inner;

  OnionPirServer() : params(), inner(params) {}
};

class OnionPirClient {
public:
  PirParams params;
  PirClient inner;

  OnionPirClient() : params(), inner(params) {}
};

// ======================== Helpers ========================

// bytes → stringstream
static std::stringstream bytes_to_stream(const std::vector<uint8_t> &data) {
  std::stringstream ss;
  ss.write(reinterpret_cast<const char *>(data.data()), data.size());
  ss.seekg(0);
  return ss;
}

// stringstream → bytes
static std::vector<uint8_t> stream_to_bytes(std::stringstream &ss) {
  ss.seekg(0, std::ios::end);
  size_t size = ss.tellg();
  ss.seekg(0, std::ios::beg);
  std::vector<uint8_t> out(size);
  ss.read(reinterpret_cast<char *>(out.data()), size);
  return out;
}

// ======================== Params ========================

PirParamsInfo get_pir_params_info() {
  PirParams params;
  PirParamsInfo info;
  info.num_entries    = params.get_num_entries();
  info.entry_size     = params.get_entry_size();
  info.num_plaintexts = params.get_num_pt();
  info.fst_dim_sz     = params.get_fst_dim_sz();
  info.other_dim_sz   = params.get_other_dim_sz();
  info.poly_degree    = DatabaseConstants::PolyDegree;
  info.db_size_mb     = params.get_DBSize_MB();
  info.physical_size_mb = params.get_physical_storage_MB();
  return info;
}

// ======================== Server ========================

std::unique_ptr<OnionPirServer> new_server() {
  return std::make_unique<OnionPirServer>();
}

bool server_load_db(OnionPirServer &server, const std::string &path) {
  return server.inner.load_db_from_file(path);
}

void server_save_db(const OnionPirServer &server, const std::string &path) {
  server.inner.save_db_to_file(path);
}

void server_push_chunk(OnionPirServer &server,
                       const std::vector<uint8_t> &chunk_data,
                       size_t chunk_idx) {
  const size_t entry_size = server.params.get_entry_size();
  const size_t fst_dim_sz = server.params.get_fst_dim_sz();
  const size_t num_per_pt = server.params.get_num_entries_per_plaintext();
  const size_t expected = fst_dim_sz * num_per_pt * entry_size;

  if (chunk_data.size() != expected) {
    throw std::invalid_argument(
        "server_push_chunk: expected " + std::to_string(expected) +
        " bytes, got " + std::to_string(chunk_data.size()));
  }

  // Reconstruct the Entry vector that push_database_chunk expects
  std::vector<Entry> entries(fst_dim_sz * num_per_pt, Entry(entry_size, 0));
  for (size_t i = 0; i < entries.size(); ++i) {
    std::memcpy(entries[i].data(), chunk_data.data() + i * entry_size, entry_size);
  }

  server.inner.push_database_chunk(entries, chunk_idx);
}

void server_preprocess(OnionPirServer &server) {
  // Access the private methods via the friend class trick:
  // We need preprocess_ntt + realign_db, which are called by gen_data.
  // Since they're private, we expose a public wrapper.
  // For now, we call them through a minimal public path.
  //
  // NOTE: This requires adding a public preprocess() method to PirServer.
  // See the comment in server.h.
  server.inner.preprocess_db();
}

void server_set_galois_key(OnionPirServer &server,
                           uint64_t client_id,
                           const std::vector<uint8_t> &key_bytes) {
  auto ss = bytes_to_stream(key_bytes);
  server.inner.set_client_galois_key(static_cast<size_t>(client_id), ss);
}

void server_set_gsw_key(OnionPirServer &server,
                        uint64_t client_id,
                        const std::vector<uint8_t> &key_bytes) {
  auto ss = bytes_to_stream(key_bytes);
  server.inner.set_client_gsw_key(static_cast<size_t>(client_id), ss);
}

std::vector<uint8_t> server_answer_query(OnionPirServer &server,
                                         uint64_t client_id,
                                         const std::vector<uint8_t> &query_bytes) {
  auto query_stream = bytes_to_stream(query_bytes);
  seal::Ciphertext response = server.inner.make_query(
      static_cast<size_t>(client_id), query_stream);

  std::stringstream resp_stream;
  server.inner.save_resp_to_stream(response, resp_stream);
  return stream_to_bytes(resp_stream);
}

// ======================== Client ========================

std::unique_ptr<OnionPirClient> new_client() {
  return std::make_unique<OnionPirClient>();
}

uint64_t client_get_id(const OnionPirClient &client) {
  return static_cast<uint64_t>(client.inner.get_client_id());
}

std::vector<uint8_t> client_generate_galois_keys(OnionPirClient &client) {
  std::stringstream ss;
  client.inner.create_galois_keys(ss);
  return stream_to_bytes(ss);
}

std::vector<uint8_t> client_generate_gsw_keys(OnionPirClient &client) {
  auto gsw = client.inner.generate_gsw_from_key();
  std::stringstream ss;
  PirClient::write_gsw_to_stream(gsw, ss);
  return stream_to_bytes(ss);
}

std::vector<uint8_t> client_generate_query(OnionPirClient &client,
                                           uint64_t entry_index) {
  seal::Ciphertext query = client.inner.fast_generate_query(
      static_cast<size_t>(entry_index));
  std::stringstream ss;
  PirClient::write_query_to_stream(query, ss);
  return stream_to_bytes(ss);
}

std::vector<uint8_t> client_decrypt_response(OnionPirClient &client,
                                             uint64_t entry_index,
                                             const std::vector<uint8_t> &response_bytes) {
  auto resp_stream = bytes_to_stream(response_bytes);
  seal::Ciphertext response = client.inner.load_resp_from_stream(resp_stream);
  seal::Plaintext plaintext = client.inner.decrypt_reply(response);
  Entry entry = client.inner.get_entry_from_plaintext(
      static_cast<size_t>(entry_index), plaintext);
  return entry;  // Entry is already std::vector<uint8_t>
}
