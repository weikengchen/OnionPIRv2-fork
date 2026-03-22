#pragma once
// OnionPIRv2 C-compatible FFI layer for Rust integration.
// Wraps the C++ ffi.h API with extern "C" functions using raw pointers.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ======================== Params info ========================

typedef struct {
  uint64_t num_entries;
  uint64_t entry_size;
  uint64_t num_plaintexts;
  uint64_t fst_dim_sz;
  uint64_t other_dim_sz;
  uint64_t poly_degree;
  double   db_size_mb;
  double   physical_size_mb;
} CPirParamsInfo;

// ======================== Opaque handles ========================

typedef void* OnionPirServerHandle;
typedef void* OnionPirClientHandle;
typedef void* OnionPirQueueHandle;

// ======================== Return buffer ========================
// Caller-owned byte buffer returned by functions that produce variable-length output.
// The caller must free it with onion_free_buf().

typedef struct {
  uint8_t *data;
  size_t   len;
} OnionBuf;

void onion_free_buf(OnionBuf buf);

// ======================== Params ========================

// Pass num_entries = 0 to use the compiled-in default.
CPirParamsInfo onion_get_params_info(uint64_t num_entries);

// ======================== Server ========================

// Pass num_entries = 0 to use the compiled-in default.
OnionPirServerHandle onion_server_new(uint64_t num_entries);
void onion_server_free(OnionPirServerHandle h);

// Returns 1 on success, 0 on failure.
int onion_server_load_db(OnionPirServerHandle h, const char *path);
void onion_server_save_db(OnionPirServerHandle h, const char *path);

void onion_server_push_chunk(OnionPirServerHandle h,
                             const uint8_t *data, size_t data_len,
                             size_t chunk_idx);
void onion_server_preprocess(OnionPirServerHandle h);

void onion_server_set_galois_key(OnionPirServerHandle h,
                                 uint64_t client_id,
                                 const uint8_t *key, size_t key_len);
void onion_server_set_gsw_key(OnionPirServerHandle h,
                              uint64_t client_id,
                              const uint8_t *key, size_t key_len);
void onion_server_remove_client(OnionPirServerHandle h, uint64_t client_id);

OnionBuf onion_server_answer_query(OnionPirServerHandle h,
                                   uint64_t client_id,
                                   const uint8_t *query, size_t query_len);

// ======================== Query queue ========================

// Status codes matching QueryStatus enum
#define ONION_QUERY_QUEUED     0
#define ONION_QUERY_PROCESSING 1
#define ONION_QUERY_DONE       2
#define ONION_QUERY_ERROR      3
#define ONION_QUERY_NOT_FOUND  4

OnionPirQueueHandle onion_queue_new(OnionPirServerHandle server);
void onion_queue_stop(OnionPirQueueHandle h);
void onion_queue_free(OnionPirQueueHandle h);

uint64_t onion_queue_submit(OnionPirQueueHandle h,
                            uint64_t client_id,
                            const uint8_t *query, size_t query_len);
uint8_t  onion_queue_status(OnionPirQueueHandle h, uint64_t ticket);
uint64_t onion_queue_position(OnionPirQueueHandle h, uint64_t ticket);

// Returns the result. Caller must free with onion_free_buf().
// Returns {NULL, 0} if ticket is not Done.
OnionBuf onion_queue_result(OnionPirQueueHandle h, uint64_t ticket);

// ======================== Client ========================

// Pass num_entries = 0 to use the compiled-in default. Must match the server.
OnionPirClientHandle onion_client_new(uint64_t num_entries);
void onion_client_free(OnionPirClientHandle h);

uint64_t onion_client_get_id(OnionPirClientHandle h);
OnionBuf onion_client_generate_galois_keys(OnionPirClientHandle h);
OnionBuf onion_client_generate_gsw_keys(OnionPirClientHandle h);
OnionBuf onion_client_generate_query(OnionPirClientHandle h, uint64_t entry_index);
OnionBuf onion_client_decrypt_response(OnionPirClientHandle h,
                                       uint64_t entry_index,
                                       const uint8_t *resp, size_t resp_len);

#ifdef __cplusplus
}
#endif
