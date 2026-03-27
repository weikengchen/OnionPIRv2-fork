package com.onionpir.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Safe wrapper around a shared key store handle.
 * <p>
 * A key store deserializes client keys once and shares the expanded
 * representation across multiple {@link OnionPirServer} instances,
 * avoiding redundant deserialization + NTT expansion.
 * <p>
 * The key store must outlive all servers it is attached to.
 */
public class OnionKeyStore implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;

    private Pointer handle;

    /**
     * Create a new key store for a database with {@code numEntries} rows.
     * Pass 0 to use the compiled-in default.
     */
    public OnionKeyStore(long numEntries) {
        handle = LIB.onion_key_store_new(numEntries);
        if (handle == null) {
            throw new RuntimeException("Failed to create OnionKeyStore");
        }
    }

    /** Deserialize and store a client's Galois key. */
    public void setGaloisKey(long clientId, byte[] key) {
        LIB.onion_key_store_set_galois_key(handle, clientId,
                key, new NativeLong(key.length));
    }

    /** Deserialize and store a client's GSW key. */
    public void setGswKey(long clientId, byte[] key) {
        LIB.onion_key_store_set_gsw_key(handle, clientId,
                key, new NativeLong(key.length));
    }

    /**
     * Export the expanded GSW key as raw bytes for caching.
     * The returned buffer contains uint64 values serialized as bytes.
     */
    public byte[] exportGsw(long clientId) {
        return OnionPir.bufToBytes(LIB.onion_key_store_export_gsw(handle, clientId));
    }

    /**
     * Import a pre-expanded GSW key (skips deserialization + NTT).
     *
     * @param clientId  client ID
     * @param data      pointer to uint64 array of expanded key data
     * @param numValues number of uint64 values
     */
    public void importGsw(long clientId, Pointer data, long numValues) {
        LIB.onion_key_store_import_gsw(handle, clientId,
                data, new NativeLong(numValues));
    }

    /** Check whether both key types are loaded for a client. */
    public boolean hasClient(long clientId) {
        return LIB.onion_key_store_has_client(handle, clientId) == 1;
    }

    /** Remove all keys for a client. */
    public void removeClient(long clientId) {
        LIB.onion_key_store_remove_client(handle, clientId);
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_key_store_free(handle);
            handle = null;
        }
    }

    /** Package-private handle access for interop with other wrappers. */
    Pointer getHandle() {
        return handle;
    }
}
