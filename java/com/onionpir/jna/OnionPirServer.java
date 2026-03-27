package com.onionpir.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Safe wrapper around an OnionPIR server handle.
 * <p>
 * Thread safety: a single server instance must not be shared across threads.
 * Use {@link OnionPirQueue} for concurrent query handling.
 */
public class OnionPirServer implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;

    private Pointer handle;

    /**
     * Create a new server for a database with {@code numEntries} rows.
     * Pass 0 to use the compiled-in default.
     */
    public OnionPirServer(long numEntries) {
        handle = LIB.onion_server_new(numEntries);
        if (handle == null) {
            throw new RuntimeException("Failed to create OnionPirServer");
        }
    }

    /**
     * Load a preprocessed database from disk.
     *
     * @return true on success, false on failure
     */
    public boolean loadDb(String path) {
        return LIB.onion_server_load_db(handle, path) == 1;
    }

    /** Save the preprocessed database to disk. */
    public void saveDb(String path) {
        LIB.onion_server_save_db(handle, path);
    }

    /** Push a raw data chunk into the database at the given chunk index. */
    public void pushChunk(byte[] data, long chunkIdx) {
        LIB.onion_server_push_chunk(handle, data,
                new NativeLong(data.length), new NativeLong(chunkIdx));
    }

    /** Preprocess the database for PIR queries (NTT expansion). */
    public void preprocess() {
        LIB.onion_server_preprocess(handle);
    }

    /**
     * Attach a shared NTT-expanded database with per-instance indirection.
     *
     * @param sharedNttStore          level-major layout, caller-owned
     * @param sharedStoreNumEntries   number of entries in the shared store
     * @param indexTable              per-instance index mapping, caller-owned
     * @param indexTableLen           length of the index table
     */
    public void setSharedDatabase(Pointer sharedNttStore, long sharedStoreNumEntries,
                                  Pointer indexTable, long indexTableLen) {
        LIB.onion_server_set_shared_database(handle, sharedNttStore,
                new NativeLong(sharedStoreNumEntries), indexTable,
                new NativeLong(indexTableLen));
    }

    /**
     * NTT-expand a single raw entry into the destination buffer.
     *
     * @param rawEntry raw entry bytes
     * @param dst      caller-allocated buffer for coeff_val_cnt uint64 values
     */
    public void nttExpandEntry(byte[] rawEntry, Pointer dst) {
        LIB.onion_server_ntt_expand_entry(handle, rawEntry,
                new NativeLong(rawEntry.length), dst);
    }

    /** Register a client's Galois key for server-side FHE evaluation. */
    public void setGaloisKey(long clientId, byte[] key) {
        LIB.onion_server_set_galois_key(handle, clientId,
                key, new NativeLong(key.length));
    }

    /** Register a client's GSW key for server-side FHE evaluation. */
    public void setGswKey(long clientId, byte[] key) {
        LIB.onion_server_set_gsw_key(handle, clientId,
                key, new NativeLong(key.length));
    }

    /** Remove all keys for a client. */
    public void removeClient(long clientId) {
        LIB.onion_server_remove_client(handle, clientId);
    }

    /**
     * Answer an FHE query synchronously.
     *
     * @param clientId client that generated the query
     * @param query    encrypted query bytes from {@link OnionPirClient#generateQuery}
     * @return encrypted response bytes for the client to decrypt
     */
    public byte[] answerQuery(long clientId, byte[] query) {
        return OnionPir.bufToBytes(LIB.onion_server_answer_query(
                handle, clientId, query, new NativeLong(query.length)));
    }

    /**
     * Attach a shared key store to this server.
     * The store must outlive the server (non-owning reference).
     */
    public void setKeyStore(OnionKeyStore store) {
        LIB.onion_server_set_key_store(handle, store.getHandle());
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_server_free(handle);
            handle = null;
        }
    }

    /** Package-private handle access for interop with other wrappers. */
    Pointer getHandle() {
        return handle;
    }
}
