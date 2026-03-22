//! Rust bindings for OnionPIRv2 — a high-performance Private Information Retrieval library.
//!
//! # Quick start
//!
//! ```no_run
//! use onionpir::{Server, Client, QueryQueue};
//!
//! let num_entries: u64 = 1 << 16;
//!
//! // Inspect database parameters for a given entry count
//! let params = onionpir::params_info(num_entries);
//! println!("DB: {} entries × {} bytes", params.num_entries, params.entry_size);
//!
//! // Server setup
//! let mut server = Server::new(num_entries);
//! if !server.load_db("/path/to/preprocessed_db.bin") {
//!     // ... push chunks, preprocess, save ...
//! }
//!
//! // Client setup (num_entries must match the server)
//! let mut client = Client::new(num_entries);
//! let client_id = client.id();
//! let galois = client.generate_galois_keys();
//! let gsw = client.generate_gsw_keys();
//! server.set_galois_key(client_id, &galois);
//! server.set_gsw_key(client_id, &gsw);
//!
//! // Query (synchronous)
//! let query = client.generate_query(42);
//! let response = server.answer_query(client_id, &query);
//! let entry = client.decrypt_response(42, &response);
//!
//! // Or use the async queue
//! let mut queue = server.query_queue();
//! let ticket = queue.submit(client_id, &query);
//! // ... poll queue.status(ticket) ...
//! let entry = queue.result(ticket).unwrap();
//! ```

use std::ffi::CString;

// ======================== Raw FFI bindings ========================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct COnionBuf {
    data: *mut u8,
    len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CPirParamsInfo {
    num_entries: u64,
    entry_size: u64,
    num_plaintexts: u64,
    fst_dim_sz: u64,
    other_dim_sz: u64,
    poly_degree: u64,
    coeff_val_cnt: u64,
    db_size_mb: f64,
    physical_size_mb: f64,
}

type ServerHandle = *mut std::ffi::c_void;
type ClientHandle = *mut std::ffi::c_void;
type QueueHandle = *mut std::ffi::c_void;

extern "C" {
    fn onion_free_buf(buf: COnionBuf);
    fn onion_get_params_info(num_entries: u64) -> CPirParamsInfo;

    // Server
    fn onion_server_new(num_entries: u64) -> ServerHandle;
    fn onion_server_free(h: ServerHandle);
    fn onion_server_load_db(h: ServerHandle, path: *const i8) -> i32;
    fn onion_server_save_db(h: ServerHandle, path: *const i8);
    fn onion_server_push_chunk(h: ServerHandle, data: *const u8, data_len: usize, chunk_idx: usize);
    fn onion_server_preprocess(h: ServerHandle);
    fn onion_server_set_shared_database(
        h: ServerHandle,
        shared_ntt_store: *const u64,
        shared_store_num_entries: usize,
        index_table: *const u32,
        index_table_len: usize,
    );
    fn onion_server_ntt_expand_entry(
        h: ServerHandle,
        raw_entry: *const u8,
        raw_len: usize,
        dst: *mut u64,
    );
    fn onion_server_set_galois_key(h: ServerHandle, client_id: u64, key: *const u8, key_len: usize);
    fn onion_server_set_gsw_key(h: ServerHandle, client_id: u64, key: *const u8, key_len: usize);
    fn onion_server_remove_client(h: ServerHandle, client_id: u64);
    fn onion_server_answer_query(
        h: ServerHandle,
        client_id: u64,
        query: *const u8,
        query_len: usize,
    ) -> COnionBuf;

    // Queue
    fn onion_queue_new(server: ServerHandle) -> QueueHandle;
    fn onion_queue_stop(h: QueueHandle);
    fn onion_queue_free(h: QueueHandle);
    fn onion_queue_submit(
        h: QueueHandle,
        client_id: u64,
        query: *const u8,
        query_len: usize,
    ) -> u64;
    fn onion_queue_status(h: QueueHandle, ticket: u64) -> u8;
    fn onion_queue_position(h: QueueHandle, ticket: u64) -> u64;
    fn onion_queue_result(h: QueueHandle, ticket: u64) -> COnionBuf;

    // Client
    fn onion_client_new(num_entries: u64) -> ClientHandle;
    fn onion_client_free(h: ClientHandle);
    fn onion_client_get_id(h: ClientHandle) -> u64;
    fn onion_client_generate_galois_keys(h: ClientHandle) -> COnionBuf;
    fn onion_client_generate_gsw_keys(h: ClientHandle) -> COnionBuf;
    fn onion_client_generate_query(h: ClientHandle, entry_index: u64) -> COnionBuf;
    fn onion_client_decrypt_response(
        h: ClientHandle,
        entry_index: u64,
        resp: *const u8,
        resp_len: usize,
    ) -> COnionBuf;
}

// ======================== Helpers ========================

fn buf_to_vec(buf: COnionBuf) -> Vec<u8> {
    if buf.data.is_null() || buf.len == 0 {
        unsafe { onion_free_buf(buf) };
        return Vec::new();
    }
    let v = unsafe { std::slice::from_raw_parts(buf.data, buf.len) }.to_vec();
    unsafe { onion_free_buf(buf) };
    v
}

// ======================== Public types ========================

/// Database configuration parameters (computed from the entry count at runtime).
#[derive(Debug, Clone, Copy)]
pub struct ParamsInfo {
    /// Total entries in the DB (after padding — may be larger than requested).
    pub num_entries: u64,
    /// Bytes per entry.
    pub entry_size: u64,
    /// Total plaintext count (fst_dim_sz × other_dim_sz).
    pub num_plaintexts: u64,
    /// First dimension size.
    pub fst_dim_sz: u64,
    /// Number of chunks to push.
    pub other_dim_sz: u64,
    /// SEAL polynomial degree (compile-time constant: 2048 or 4096).
    pub poly_degree: u64,
    /// Number of uint64 values per NTT-expanded plaintext (poly_degree × rns_mod_cnt).
    /// This is the number of coefficients per entry in the shared NTT store.
    pub coeff_val_cnt: u64,
    /// Logical DB size in MB.
    pub db_size_mb: f64,
    /// NTT-expanded physical storage in MB.
    pub physical_size_mb: f64,
}

/// Status of a queued query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QueryStatus {
    Queued = 0,
    Processing = 1,
    Done = 2,
    Error = 3,
    NotFound = 4,
}

impl From<u8> for QueryStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => QueryStatus::Queued,
            1 => QueryStatus::Processing,
            2 => QueryStatus::Done,
            3 => QueryStatus::Error,
            4 => QueryStatus::NotFound,
            _ => QueryStatus::NotFound,
        }
    }
}

/// Return PIR database parameters for a given number of entries.
///
/// The returned `num_entries` may be larger than requested due to padding.
/// Entry size, poly degree, and coefficient moduli are compile-time constants.
pub fn params_info(num_entries: u64) -> ParamsInfo {
    let c = unsafe { onion_get_params_info(num_entries) };
    ParamsInfo {
        num_entries: c.num_entries,
        entry_size: c.entry_size,
        num_plaintexts: c.num_plaintexts,
        fst_dim_sz: c.fst_dim_sz,
        other_dim_sz: c.other_dim_sz,
        poly_degree: c.poly_degree,
        coeff_val_cnt: c.coeff_val_cnt,
        db_size_mb: c.db_size_mb,
        physical_size_mb: c.physical_size_mb,
    }
}

// ======================== Server ========================

/// PIR server that holds the database and answers queries.
///
/// The server is **not** `Send` or `Sync` — it uses OpenMP internally
/// and is not safe to share across threads. Use [`QueryQueue`] for
/// concurrent query serving.
pub struct Server {
    handle: ServerHandle,
}

impl Server {
    /// Create a new PIR server for the given number of database entries.
    ///
    /// You must load or populate a database before answering queries.
    pub fn new(num_entries: u64) -> Self {
        let handle = unsafe { onion_server_new(num_entries) };
        assert!(!handle.is_null(), "failed to create OnionPirServer");
        Self { handle }
    }

    /// Load a preprocessed database from disk (mmap, zero-copy).
    /// Returns `true` on success, `false` if the file doesn't exist or config mismatches.
    pub fn load_db(&mut self, path: &str) -> bool {
        let cpath = CString::new(path).expect("path contains null byte");
        unsafe { onion_server_load_db(self.handle, cpath.as_ptr()) != 0 }
    }

    /// Save the preprocessed database to disk for future fast loading.
    pub fn save_db(&self, path: &str) {
        let cpath = CString::new(path).expect("path contains null byte");
        unsafe { onion_server_save_db(self.handle, cpath.as_ptr()) }
    }

    /// Push one chunk of raw entry data.
    ///
    /// `chunk_idx` ranges from `0` to `params.other_dim_sz - 1`.
    /// Each chunk must be exactly `fst_dim_sz × entries_per_plaintext × entry_size` bytes.
    /// If the size is wrong, the C++ layer will panic with the expected size.
    pub fn push_chunk(&mut self, data: &[u8], chunk_idx: usize) {
        unsafe {
            onion_server_push_chunk(self.handle, data.as_ptr(), data.len(), chunk_idx);
        }
    }

    /// Run NTT preprocessing + memory realignment after all chunks are pushed.
    /// This is expensive (seconds to minutes depending on DB size). Call once, then `save_db`.
    pub fn preprocess(&mut self) {
        unsafe { onion_server_preprocess(self.handle) }
    }

    /// Attach a shared NTT-expanded database with per-instance indirection.
    /// Replaces `push_chunk` + `preprocess` for this instance.
    ///
    /// # Arguments
    /// * `shared_ntt_store` - Pointer to level-major shared NTT data.
    ///   Layout: `store[level * shared_num_entries + entry_id]`.
    ///   Must remain valid for the lifetime of this server.
    /// * `shared_num_entries` - Number of entries in the shared store.
    /// * `index_table` - Per-instance mapping: `index_table[logical_pos] = entry_id`.
    ///   Length must equal `params.num_plaintexts` (`fst_dim_sz * other_dim_sz`).
    ///   The slice must remain valid for the lifetime of this server.
    ///
    /// # Safety
    /// The caller must ensure `shared_ntt_store` points to at least
    /// `coeff_val_cnt * shared_num_entries` uint64 values and remains valid.
    pub unsafe fn set_shared_database(
        &mut self,
        shared_ntt_store: *const u64,
        shared_num_entries: usize,
        index_table: &[u32],
    ) {
        onion_server_set_shared_database(
            self.handle,
            shared_ntt_store,
            shared_num_entries,
            index_table.as_ptr(),
            index_table.len(),
        );
    }

    /// NTT-expand a single raw entry into level-major coefficient form.
    /// Used for offline preparation of the shared NTT store.
    ///
    /// `coeff_val_cnt` is available from [`params_info`].
    /// Returns `coeff_val_cnt` uint64 values. The caller scatters
    /// `result[level]` to `shared_store[level * num_entries + entry_id]`.
    pub fn ntt_expand_entry(&self, raw_entry: &[u8], coeff_val_cnt: usize) -> Vec<u64> {
        let mut dst = vec![0u64; coeff_val_cnt];
        unsafe {
            onion_server_ntt_expand_entry(
                self.handle,
                raw_entry.as_ptr(),
                raw_entry.len(),
                dst.as_mut_ptr(),
            );
        }
        dst
    }

    /// Register a client's Galois keys. Required before answering queries from this client.
    pub fn set_galois_key(&mut self, client_id: u64, key: &[u8]) {
        unsafe {
            onion_server_set_galois_key(self.handle, client_id, key.as_ptr(), key.len());
        }
    }

    /// Register a client's GSW keys. Required before answering queries from this client.
    pub fn set_gsw_key(&mut self, client_id: u64, key: &[u8]) {
        unsafe {
            onion_server_set_gsw_key(self.handle, client_id, key.as_ptr(), key.len());
        }
    }

    /// Remove a client's cached keys.
    pub fn remove_client(&mut self, client_id: u64) {
        unsafe { onion_server_remove_client(self.handle, client_id) }
    }

    /// Answer a PIR query synchronously. Returns the encrypted response bytes.
    ///
    /// **Warning:** This saturates all CPU cores via OpenMP. Do not call concurrently
    /// on the same server. Use [`QueryQueue`] for multi-client serving.
    pub fn answer_query(&mut self, client_id: u64, query: &[u8]) -> Vec<u8> {
        let buf =
            unsafe { onion_server_answer_query(self.handle, client_id, query.as_ptr(), query.len()) };
        buf_to_vec(buf)
    }

    /// Create an async query queue backed by a worker thread.
    ///
    /// The queue serializes queries so only one runs at a time (saturating all cores).
    /// The returned `QueryQueue` borrows this server — the server must outlive the queue.
    pub fn query_queue(&mut self) -> QueryQueue<'_> {
        let qh = unsafe { onion_queue_new(self.handle) };
        assert!(!qh.is_null(), "failed to create query queue");
        QueryQueue {
            handle: qh,
            _server: std::marker::PhantomData,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe { onion_server_free(self.handle) }
    }
}

// ======================== QueryQueue ========================

/// Async query queue that serializes PIR queries through a single worker thread.
///
/// Submit queries and get a ticket ID back immediately, then poll for status.
pub struct QueryQueue<'a> {
    handle: QueueHandle,
    _server: std::marker::PhantomData<&'a mut Server>,
}

impl<'a> QueryQueue<'a> {
    /// Submit a query. Returns a ticket ID immediately (non-blocking).
    pub fn submit(&mut self, client_id: u64, query: &[u8]) -> u64 {
        unsafe { onion_queue_submit(self.handle, client_id, query.as_ptr(), query.len()) }
    }

    /// Check the status of a ticket.
    pub fn status(&self, ticket: u64) -> QueryStatus {
        QueryStatus::from(unsafe { onion_queue_status(self.handle, ticket) })
    }

    /// How many queries are ahead of this ticket in the queue.
    /// Returns 0 when the query is processing, done, or errored.
    pub fn position(&self, ticket: u64) -> u64 {
        unsafe { onion_queue_position(self.handle, ticket) }
    }

    /// Collect the result for a completed ticket. Removes it from the queue.
    /// Returns `None` if the ticket is not done or not found.
    pub fn result(&mut self, ticket: u64) -> Option<Vec<u8>> {
        let buf = unsafe { onion_queue_result(self.handle, ticket) };
        if buf.data.is_null() {
            return None;
        }
        Some(buf_to_vec(buf))
    }

    /// Stop the worker thread. Called automatically on drop.
    pub fn stop(&mut self) {
        unsafe { onion_queue_stop(self.handle) }
    }
}

impl<'a> Drop for QueryQueue<'a> {
    fn drop(&mut self) {
        unsafe {
            onion_queue_stop(self.handle);
            onion_queue_free(self.handle);
        }
    }
}

// ======================== Client ========================

/// PIR client that generates keys, queries, and decrypts responses.
pub struct Client {
    handle: ClientHandle,
}

impl Client {
    /// Create a new PIR client. `num_entries` must match the server's value.
    pub fn new(num_entries: u64) -> Self {
        let handle = unsafe { onion_client_new(num_entries) };
        assert!(!handle.is_null(), "failed to create OnionPirClient");
        Self { handle }
    }

    /// Get this client's unique ID (used for server key registration).
    pub fn id(&self) -> u64 {
        unsafe { onion_client_get_id(self.handle) }
    }

    /// Generate Galois keys to send to the server. Several MB.
    pub fn generate_galois_keys(&mut self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_generate_galois_keys(self.handle) })
    }

    /// Generate GSW keys to send to the server. Several MB.
    pub fn generate_gsw_keys(&mut self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_generate_gsw_keys(self.handle) })
    }

    /// Generate a PIR query for the given entry index.
    /// Valid indices: `0 ..= params_info(n).num_entries - 1`.
    pub fn generate_query(&mut self, entry_index: u64) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_generate_query(self.handle, entry_index) })
    }

    /// Decrypt the server's response and extract the entry bytes.
    pub fn decrypt_response(&mut self, entry_index: u64, response: &[u8]) -> Vec<u8> {
        let buf = unsafe {
            onion_client_decrypt_response(self.handle, entry_index, response.as_ptr(), response.len())
        };
        buf_to_vec(buf)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { onion_client_free(self.handle) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_info_default() {
        let info = params_info(1 << 16);
        assert!(info.num_entries >= (1 << 16));
        assert!(info.entry_size > 0);
        assert!(info.fst_dim_sz > 0);
        assert!(info.other_dim_sz > 0);
        assert!(info.poly_degree == 2048 || info.poly_degree == 4096);
    }

    #[test]
    fn test_params_info_custom() {
        let info = params_info(1000);
        assert!(info.num_entries >= 1000);
        assert!(info.entry_size > 0);

        let info2 = params_info(1 << 20);
        assert!(info2.num_entries >= (1 << 20));
        // More entries → larger DB
        assert!(info2.db_size_mb > info.db_size_mb);
    }
}
